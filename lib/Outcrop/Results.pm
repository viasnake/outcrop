package Outcrop::Results;
use Mojo::Base -base;
use utf8;
use feature 'fc';
use DBI;
use Digest::SHA;
use Fcntl      qw(:flock);
use Mojo::File qw(path);
use Mojo::JSON qw(encode_json decode_json);
use Outcrop::ResultStream;

has 'config';

sub revision {
    my ($class, $file) = @_;
    my @stat = stat $file;
    die 'Result unavailable' unless @stat;
    return join '-', @stat[1, 7, 9, 10];
}

sub location {
    my ($self, $id, $kind) = @_;
    die 'Invalid result identity' unless $id =~ /\A[0-9a-f]{32}\z/ && $kind =~ /\A(?:syft|grype)\z/;

    # Derivative data belongs to Web's writable area, never the original scan.
    return path($self->config->state, 'annotations', 'results', "$id-$kind.sqlite");
}

sub connect {
    my ($self, $file, $readonly) = @_;
    return DBI->connect(
        "dbi:SQLite:dbname=$file",
        '', '',
        {
            RaiseError        => 1,
            PrintError        => 0,
            AutoCommit        => 1,
            sqlite_unicode    => 1,
            sqlite_open_flags => $readonly ? 1 : 6,
        }
    );
}

sub published_location {
    my ($self, $id, $kind) = @_;
    $self->location($id, $kind);    # Validate both path components.
    return path($self->config->state, 'scans', $id, "results-$kind.sqlite");
}

sub available {
    my ($self, $id, $kind, $revision) = @_;
    for my $file ($self->location($id, $kind), $self->published_location($id, $kind)) {
        return $file if $self->ready($file, $revision);
    }
    return;
}

sub version {
    my ($self, $file, $revision) = @_;

    # A rebuild of unchanged JSON must invalidate cached API responses too.
    return '2.' . $revision . '.' . $self->revision($file);
}

sub ready {
    my ($self, $file, $revision) = @_;
    return 0 unless -f $file;
    return eval {
        my $db = $self->connect($file, 1);
        my ($saved) =
            $db->selectrow_array('SELECT revision FROM metadata WHERE schema_version = 2');
        defined($saved) && $saved eq $revision;
    } || 0;
}

sub text {
    my ($value) = @_;
    return defined($value) && !ref($value) && length($value) ? "$value" : '不明';
}

sub row {
    my ($self, $kind, $value) = @_;
    die 'Invalid result row' unless ref($value) eq 'HASH';
    if ($kind eq 'syft') {
        return [
            map { text($_) } (
                $value->{name},
                $value->{version},
                $value->{type},
                $value->{foundBy},
                join(', ',
                    map { $_->{path} || $_->{accessPath} || '不明' } @{$value->{locations} // []})
            )
        ];
    }
    my $vulnerability = $value->{vulnerability} // {};
    my $artifact      = $value->{artifact}      // {};
    return [
        map { text($_) } (
            $vulnerability->{id}, $artifact->{name},
            $artifact->{version}, $vulnerability->{severity},
            join(', ', @{$vulnerability->{fix}{versions} // []})
        )
    ];
}

sub sort_key {
    my ($value) = @_;
    $value = fc($value);

    # Numeric segments sort by digit count, then value, without numeric overflow.
    $value =~
        s/([0-9]+)/my $n = $1; $n =~ s!^0+(?=\d)!!; sprintf("\x01%010d%s\x01", length($n), $n)/ge;
    return $value;
}

sub build_lock {
    my ($self, $file) = @_;
    $file->dirname->make_path({mode => 0750});
    open my $lock, '>>', $file->dirname->child('build.lock') or die "Result lock: $!";
    return unless flock($lock, LOCK_EX | LOCK_NB);
    return $lock;
}

sub save_build_status {
    my ($self, $file, $status) = @_;
    my $temporary = path("$file.build.json.tmp");
    $temporary->spurt(encode_json($status));
    chmod 0640, $temporary or die "Build status permissions: $!";
    rename $temporary, "$file.build.json" or die "Publish build status: $!";
}

sub build_status {
    my ($self, $file) = @_;
    my $status = eval { decode_json(path("$file.build.json")->slurp) };
    return {state => 'idle'} unless ref($status) eq 'HASH';
    if ($status->{state} eq 'running') {

        # A stopped Web process must not leave the button waiting forever.
        my $lock = $self->build_lock($file);
        return {%$status, state => 'failed'} if $lock;
    }
    return $status;
}

sub build {
    my ($self, $source, $file, $kind, $revision, %options) = @_;

    # Web rebuilds serialize in their shared directory. Scanner outputs use
    # the private scan directory and remain bounded by the worker job limit.
    my $lock = $options{lock} || $self->build_lock($file);
    return 0 unless $lock;
    return 1 if !$options{force} && $self->ready($file, $revision);
    my $temporary = path("$file.part");
    unlink $temporary           if -f $temporary;
    unlink "$temporary-journal" if -f "$temporary-journal";
    my $db;
    my $ok = eval {
        $db = $self->connect($temporary, 0);
        $db->do('PRAGMA cache_size=-8192');
        $db->do('PRAGMA temp_store=FILE');
        $db->do(
            'CREATE TABLE metadata (schema_version INTEGER NOT NULL, revision TEXT NOT NULL, total INTEGER NOT NULL, source_sha256 TEXT NOT NULL, rows_sha256 TEXT NOT NULL)'
        );
        $db->do(
            'CREATE TABLE rows (id INTEGER PRIMARY KEY, '
                . join(
                ', ', map { "c$_ TEXT NOT NULL, f$_ TEXT NOT NULL, s$_ TEXT NOT NULL" } 0 .. 4
                )
                . ')'
        );
        $db->begin_work;
        my $insert        = $db->prepare('INSERT INTO rows VALUES (' . join(',', ('?') x 16) . ')');
        my $total         = 0;
        my $source_digest = Digest::SHA->new(256);
        my $rows_digest   = Digest::SHA->new(256);
        my %severity =
            (Critical => 0, High => 1, Medium => 2, Low => 3, Negligible => 4, Unknown => 5);
        my $envelope = Outcrop::ResultStream->read(
            $source, $kind,
            sub {
                my $row = $self->row($kind, $_[0]);
                my @columns;
                for my $column (0 .. 4) {
                    my $value = $row->[$column];
                    my $sort  = $kind eq 'grype'
                        && $column == 3 ? ($severity{$value} // 6) : sort_key($value);
                    push @columns, $value, fc($value), "$sort";
                }
                $rows_digest->add(encode_json([$total, @columns]) . "\n");
                $insert->execute($total++, @columns);
            },
            $source_digest,
        );
        my $array = $kind eq 'syft' ? 'artifacts' : 'matches';
        die 'Invalid result array' unless ref($envelope->{$array}) eq 'ARRAY';
        for my $column (0 .. 4) {
            $db->do("CREATE INDEX sort_$column ON rows(s$column, id)");
        }
        die 'Result changed during indexing' unless __PACKAGE__->revision($source) eq $revision;
        my $rows_hash = $rows_digest->hexdigest;
        $db->do('INSERT INTO metadata VALUES (2, ?, ?, ?, ?)',
            undef, $revision, $total, $source_digest->hexdigest, $rows_hash);
        $db->commit;
        $db->disconnect;

        # Read back committed data through a new connection before publication.
        $db = $self->connect($temporary, 1);
        $self->verify($db, $total, $rows_hash);
        $db->disconnect;
        undef $db;
        chmod 0640, $temporary or die "Result permissions: $!";
        rename $temporary, $file or die "Publish result index: $!";
        1;
    };
    unless ($ok) {
        my $error = $@;
        if ($db) {
            eval { $db->rollback unless $db->{AutoCommit} };
            $db->disconnect;
        }
        unlink $temporary;
        die $error;
    }
    return 1;
}

sub verify {
    my ($self, $db, $expected_total, $expected_hash) = @_;
    my $checks = $db->selectcol_arrayref('PRAGMA integrity_check');
    die 'Result database integrity check failed' unless @$checks == 1 && $checks->[0] eq 'ok';
    my $rows = $db->prepare('SELECT * FROM rows ORDER BY id');
    $rows->execute;
    my $digest = Digest::SHA->new(256);
    my $count  = 0;
    while (my $row = $rows->fetchrow_arrayref) {
        $digest->add(encode_json([0 + $row->[0], map { "$_" } @$row[1 .. $#$row]]) . "\n");
        $count++;
    }
    die 'Result row count mismatch'   unless $count == $expected_total;
    die 'Result row content mismatch' unless $digest->hexdigest eq $expected_hash;
    return 1;
}

sub page {
    my ($self, $file, $revision, $request) = @_;
    my $db       = $self->connect($file, 1);
    my $metadata = $db->selectrow_hashref('SELECT * FROM metadata');
    die 'Result version changed' unless $metadata->{revision} eq $revision;
    my $query = fc($request->{query} // '');
    $query =~ s/\A\s+|\s+\z//g;
    my $where = length($query) ? ' WHERE ' . join(' OR ', map { "instr(f$_, ?) > 0" } 0 .. 4) : '';
    my @bind  = length($query) ? (($query) x 5)                                               : ();
    my $total = 0 + $metadata->{total};
    my $count =
        length($query)
        ? $db->selectrow_array("SELECT count(*) FROM rows$where", undef, @bind)
        : $total;
    my $start = 0 + ($request->{start} // 0);
    $start = $count ? $count - 1 : 0 if $start >= $count;
    my $column = $request->{column};
    my $order =
        defined($column)
        ? 's' . $column . ($request->{descending} ? ' DESC' : ' ASC') . ', id'
        : 'id';
    my $rows = $db->selectall_arrayref(
        "SELECT c0,c1,c2,c3,c4 FROM rows$where ORDER BY $order LIMIT 60 OFFSET ?",
        undef, @bind, $start);
    die 'Result generation changed'
        if defined($request->{version})
        && $request->{version} ne $self->version($file, $revision);
    return {
        revision => $request->{version} // $revision,
        total    => $total,
        count    => 0 + $count,
        start    => $start,
        rows     => $rows
    };
}

1;
