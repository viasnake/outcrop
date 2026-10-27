package Outcrop;
use Mojo::Base 'Mojolicious';
use utf8;

use Fcntl qw(:flock SEEK_END);
use Minion;
use Mojo::File qw(path);
use Mojo::JSON qw(from_json);
use Mojo::Util qw(decode);

use Outcrop::Config;
use Outcrop::Scan;
use Outcrop::Store;

has settings => sub { Outcrop::Config->new };
has store    => sub { Outcrop::Store->new(config => shift->settings) };
has queue    => sub { Minion->new(SQLite => shift->settings->queue) };

sub startup {
    my ($self) = @_;

    $self->_configure_sessions;
    $self->store->annotations->initialize;
    $self->_register_display_helpers;
    $self->hook(before_dispatch => sub { $self->_protect_request(@_) });

    # Route handlers describe UI operations; presentation work stays
    # outside startup so session and request protections remain easy to inspect.
    my $routes = $self->routes;
    $routes->get('/')->to(cb => sub { $self->_show_index(@_) });
    $routes->get('/inventory')->to(
        cb => sub {
            my ($controller) = @_;
            $controller->res->headers->cache_control('no-store');
            $controller->render(template => 'inventory', inventory => $self->inventory);
        }
    );
    $routes->get('/history')->to(cb => sub { $self->_show_history(@_) });
    $routes->post('/scans')->to(cb => sub { $self->_start_scan(@_) });
    $routes->get('/scans/:id')->to(cb => sub { $self->_show_scan(@_) });
    $routes->post('/scans/:id/tags')->to(cb => sub { $self->_update_tags(@_) });
    $routes->post('/scans/:id/note')->to(cb => sub { $self->_update_note(@_) });
    $routes->get('/scans/:id/download/:kind')->to(cb => sub { $self->_download_artifact(@_) });
}

sub random_id {
    open my $random, '<:raw', '/dev/urandom' or die "random: $!";
    read($random, my $bytes, 16) == 16 or die 'Random source unavailable';
    return unpack('H*', $bytes);
}

sub pending_scans {
    my ($self) = @_;

    my $jobs = $self->queue->backend->sqlite->db->query(
        q{
        SELECT args FROM minion_jobs
        WHERE task = 'scan' AND state IN ('inactive', 'active')
        ORDER BY id DESC
    }
    )->hashes->to_array;

    # A submission is visible before Worker copies it into permanent history.
    # Treat queue arguments as untrusted input in both processes.
    my $scanner = Outcrop::Scan->new(
        config => $self->settings,
        store  => $self->store,
    );
    my @scans;
    for my $job (@$jobs) {

        # SQLite returns JSON text with Unicode already decoded.
        my $arguments = eval { from_json($job->{args}) };
        next unless ref $arguments eq 'ARRAY' && @$arguments == 1;

        my $scan = eval { $scanner->queued($arguments->[0]) };
        if ($scan) {
            $scan->{tags} = $self->store->annotations->get_tags($scan->{id}) // $scan->{tags};
            $scan->{note} = $self->store->annotations->get_note($scan->{id}) // $scan->{note};
            push @scans, $scan;
        }
    }
    return \@scans;
}

sub inventory {
    my ($self) = @_;

    my $file      = path($self->settings->state, 'inventory.json');
    my $inventory = eval { $self->store->read_json($file) };
    $inventory //= {
        disks  => [],
        errors => ['Worker のディスク情報を取得できません。Worker の起動を確認してください。'],
    };
    $inventory->{stale} = time - ($inventory->{updated_at} // 0) > 30;
    return $inventory;
}

sub _configure_sessions {
    my ($self) = @_;

    my $secret = path($self->settings->state, 'web.secret')->slurp;
    die 'Missing session secret; initialize Worker first' unless length($secret) >= 32;

    $self->secrets([$secret]);
    $self->sessions->cookie_name('outcrop_session');
    $self->sessions->samesite('Strict');
    $self->max_request_size(65536);
}

sub _register_display_helpers {
    my ($self) = @_;

    $self->helper(
        display => sub {
            my ($controller, $value) = @_;
            return '不明' unless defined $value && !ref($value) && length($value);
            return $value;
        }
    );

    my %labels = (
        queued          => '待機中',
        running         => '実行中',
        completed       => '完了',
        partial         => '一部完了',
        failed          => '失敗',
        interrupted     => '中断',
        not_needed      => '未マウント',
        mounted         => 'マウント中',
        unmounted       => 'アンマウント済み',
        needs_cleanup   => '手動アンマウントが必要',
        validating      => '対象の再確認',
        mounting        => '読み取り専用マウント',
        inspecting      => 'ルートファイルシステムとスキャン範囲の確認',
        sbom            => 'SBOM 生成',
        unmounting      => 'アンマウント',
        vulnerabilities => '脆弱性照合',
        finished        => '処理終了',
    );
    $self->helper(
        label => sub {
            my ($controller, $value) = @_;
            return $labels{$value // ''} // $value // '不明';
        }
    );
    $self->helper(
        exclusion_reasons => sub {
            my ($controller, $reasons) = @_;
            return $self->_exclusion_reasons($reasons);
        }
    );
}

sub _exclusion_reasons {
    my ($self, $reasons) = @_;

    # Several partitions can report the same disk-wide exclusion. Present each
    # reason once while preserving the original diagnostic data in inventory.
    my @labels = (
        [qr/\A(?:Mounted filesystem|Scanner storage:|Active swap|Referenced)/, '使用中'],
        [qr/\ANo hardware serial/,                                             '識別情報を取得できません'],
        [qr/\AUnsupported/,                                                    '未対応の構成'],
        [qr/\A(?:Ambiguous filesystem|Partition table present)/,               '構成を判別できません'],
        [qr/\AOnly ext4/,                                                      '対象外のファイルシステム'],
        [qr/\ACannot resolve scanner storage:/,                                '使用状態を確認できません'],
    );
    my %seen;
    my @translated;
    for my $reason (@$reasons) {
        my $label = $reason;
        for my $translation (@labels) {
            next unless $reason =~ $translation->[0];
            $label = $translation->[1];
            last;
        }
        push @translated, $label unless $seen{$label}++;
    }
    return \@translated;
}

sub _protect_request {
    my ($self, $controller) = @_;

    my $headers = $controller->res->headers;
    $headers->header(
        'Content-Security-Policy' => join(
            '; ',
            "default-src 'none'",
            "style-src 'self'",

            # The browser compiler inserts a style element for utility classes.
            "style-src-elem 'self' 'unsafe-inline'",
            "script-src 'self' https://cdn.jsdelivr.net/npm/\@tailwindcss/browser\@4.3.3/dist/index.global.js",
            "worker-src 'self'",
            "connect-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
        )
    );
    $headers->header('X-Content-Type-Options' => 'nosniff');
    $headers->header('Referrer-Policy'        => 'no-referrer');
    $headers->cache_control('no-store');

    # Loopback binding alone does not protect against DNS rebinding.
    my $host = lc($controller->req->url->to_abs->host // '');
    return if $host eq '127.0.0.1' || $host eq 'localhost';
    $controller->render(text => 'Invalid Host', status => 403);
}

sub _show_index {
    my ($self, $controller) = @_;

    $controller->stash(scan_id => random_id(), inventory => $self->inventory);
    $controller->render(template => 'index');
}

sub _show_history {
    my ($self, $controller) = @_;

    my $tag      = substr($controller->param('tag') // '', 0, 120);
    my $page     = $self->_page_number($controller->param('page'));
    my $history  = $self->store->history($tag, $page);
    my $has_more = @$history > 50;
    pop @$history if $has_more;

    # Permanent history takes precedence if Worker has already imported a job.
    if ($page == 1) {
        my %listed = map { $_->{id} => 1 } @$history;
        my @pending;
        for my $scan (@{$self->pending_scans}) {
            next if $listed{$scan->{id}};
            next if $self->store->get($scan->{id});
            next if length($tag) && !grep { $_ eq $tag } @{$scan->{tags}};
            push @pending, $scan;
        }
        unshift @$history, @pending;
    }

    $controller->stash(
        history => $history,
        tag     => $tag,
        page    => $page,
        more    => $has_more,
    );
    $controller->render(template => 'history');
}

sub _start_scan {
    my ($self, $controller) = @_;

    return $controller->render(text => 'Invalid CSRF token', status => 403)
        if $controller->validation->csrf_protect->has_error('csrf_token');
    my @tags      = @{$controller->every_param('tags')};
    my $draft_tag = $controller->param('new_tag') // '';
    push @tags, $draft_tag if $draft_tag =~ /\S/;
    my $request = {
        id    => $controller->param('scan_id'),
        tags  => eval { Outcrop::Tags->validate(\@tags) },
        note  => $controller->param('note') // '',
        token => $controller->param('target'),
    };
    return $controller->render(text => 'タグを確認してください。', status => 400)
        unless defined $request->{tags};
    my $scanner = Outcrop::Scan->new(store => $self->store);
    return $controller->render(text => '入力値を確認してください。', status => 400)
        unless eval { $scanner->validate_request($request) };

    # Hold the submission lock across lookup and enqueue. Browser-side button
    # disabling cannot prevent two requests from reaching different Web workers.
    my $lock_file = path($self->settings->state, 'queue', 'submit.lock');
    open my $lock, '+<', $lock_file or die "Submission lock: $!";
    flock($lock, LOCK_EX) or die "Submission lock: $!";

    my $id = $request->{id};
    return $self->_submission_response($controller, $id, 200) if $self->_submission_exists($id);
    my $target = $self->_selectable_target($request->{token});
    return $controller->render(
        text   => '対象情報が古いか選択できません。一覧を更新してください。',
        status => 409,
    ) unless $target;
    return $controller->render(text => 'クローンディスクであることの確認が必要です。', status => 400)
        unless ($target->{kind} // '') eq 'host' || ($controller->param('clone') // '') eq 'yes';

    return $controller->render(text => 'この対象はすでに待機中または実行中です。', status => 409)
        if grep { $_->{token} eq $request->{token} } @{$self->pending_scans};
    $self->queue->enqueue(scan => [$request], {attempts => 1});
    return $self->_submission_response($controller, $id, 202);
}

sub _submission_response {
    my ($self, $controller, $id, $status) = @_;
    if (($controller->req->headers->accept // '') =~ /application\/json/) {
        return $controller->render(
            status => $status,
            json   => {
                id      => $id,
                url     => "/scans/$id",
                next_id => random_id(),
            }
        );
    }
    $controller->res->code($status == 200 ? 302 : 303);
    return $controller->redirect_to("/scans/$id");
}

sub _submission_exists {
    my ($self, $id) = @_;

    return 1 if $self->store->get($id);
    return $self->queue->backend->sqlite->db->query(
        q{
        SELECT id FROM minion_jobs
        WHERE task = 'scan' AND json_extract(args, '$[0].id') = ?
        LIMIT 1
    }, $id
    )->hash;
}

sub _selectable_target {
    my ($self, $token) = @_;

    my $inventory = $self->inventory;
    return 0 if $inventory->{stale};
    return 0 if @{$inventory->{blocked} // []};

    my @matches;
    my $host = $inventory->{host};
    push @matches, $host if $host && $host->{selectable} && $host->{token} eq $token;
    for my $disk (@{$inventory->{disks}}) {
        for my $target (@{$disk->{targets}}) {
            next unless $target->{selectable} && $target->{token} eq $token;
            push @matches, $target;
        }
    }
    return @matches == 1 ? $matches[0] : undef;
}

sub _find_scan {
    my ($self, $id) = @_;

    return unless $self->store->valid_id($id);
    my $saved = $self->store->get($id);
    return $saved if $saved;

    for my $pending (@{$self->pending_scans}) {
        return $pending if $pending->{id} eq $id;
    }
    return;
}

sub _show_scan {
    my ($self, $controller) = @_;

    my $scan = $self->_find_scan($controller->param('id'));
    return $controller->reply->not_found unless $scan;

    my $artifacts = $self->_artifacts($scan->{id});
    my %versions;
    for my $kind (qw(syft grype)) {
        next unless $artifacts->{$kind};

        # Published artifacts are replaced by atomic rename. File identity
        # changes the browser cache key without reading large JSON bodies.
        my @stat = stat $artifacts->{$kind};
        $versions{$kind} = join('-', @stat[1, 7, 9, 10]);
    }
    $controller->stash(
        scan      => $scan,
        artifacts => $artifacts,
        versions  => \%versions,
        log       => $self->_read_log_tail($artifacts->{log}),
    );
    $controller->render(template => 'scan');
}

sub _artifacts {
    my ($self, $id) = @_;
    return {map { $_ => scalar($self->store->artifact($id, $_)) } qw(syft cdx grype metadata log)};
}

sub _update_tags {
    my ($self, $controller) = @_;
    return $controller->render(text => 'Invalid CSRF token', status => 403)
        if $controller->validation->csrf_protect->has_error('csrf_token');
    my $scan = $self->_find_scan($controller->param('id'));
    return $controller->reply->not_found unless $scan;
    my $operation = $controller->param('operation') // '';
    return $controller->render(text => 'Invalid tag operation', status => 400)
        unless $operation eq 'add' || $operation eq 'remove';
    my $values = eval { Outcrop::Tags->validate([$controller->param('tag')]); };
    return $controller->render(text => 'タグは20個まで、各120文字以内で入力してください。', status => 400)
        unless defined $values;
    my $tags = eval {
        $self->store->annotations->change_tags($scan->{id}, $scan->{tags}, $operation, $values);
    };
    unless (defined $tags) {
        my $error = $@;
        die $error unless $error =~ /\A(?:Invalid tag|Tag too long|Remove exactly)/;
        return $controller->render(text => 'タグは20個まで、各120文字以内で入力してください。', status => 400);
    }
    return $controller->render(json => {tags => $tags})
        if ($controller->req->headers->accept // '') eq 'application/json';
    $controller->res->code(303);
    $controller->redirect_to('/scans/' . $scan->{id});
}

sub _update_note {
    my ($self, $controller) = @_;
    return $controller->render(text => 'Invalid CSRF token', status => 403)
        if $controller->validation->csrf_protect->has_error('csrf_token');
    my $scan = $self->_find_scan($controller->param('id'));
    return $controller->reply->not_found unless $scan;
    my $note = eval { Outcrop::Annotations->validate_note($controller->param('note')); };
    return $controller->render(text => 'メモは2000文字以内で入力してください。', status => 400)
        unless defined $note;
    $self->store->annotations->save_note($scan->{id}, $note);
    return $controller->render(json => {note => $note})
        if ($controller->req->headers->accept // '') eq 'application/json';
    $controller->res->code(303);
    $controller->redirect_to('/scans/' . $scan->{id});
}

sub _page_number {
    my ($self, $value) = @_;

    return 1 unless ($value // '') =~ /\A[1-9]\d{0,5}\z/;
    return $value;
}

sub _read_log_tail {
    my ($self, $file) = @_;

    return '' unless $file;
    open my $handle, '<:raw', $file or die "Log: $!";
    if (-s $handle > 262144) {
        seek($handle, -262144, SEEK_END) or die "Seek log: $!";
    }

    local $/;
    return decode('UTF-8', scalar(<$handle>) // '') // 'ログはダウンロードして確認してください。';
}

sub _download_artifact {
    my ($self, $controller) = @_;

    # Store resolves a Scan ID plus an allowlisted kind; no request value is
    # ever interpreted as a filesystem path or a download filename.
    my $kind = $controller->param('kind');
    my $file = $self->store->artifact($controller->param('id'), $kind);
    return $controller->reply->not_found unless $file;

    my $headers = $controller->res->headers;
    $headers->content_disposition('attachment; filename="' . $file->basename . '"');
    $headers->content_type($kind eq 'log' ? 'text/plain; charset=UTF-8' : 'application/json');
    return $controller->render(json => $self->_find_scan($controller->param('id')))
        if $kind eq 'metadata';
    $controller->reply->file("$file");
}

1;
