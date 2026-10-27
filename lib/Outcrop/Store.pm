package Outcrop::Store;
use Mojo::Base -base;

use DBI;
use Outcrop::Annotations;
use DBD::SQLite::Constants qw(SQLITE_OPEN_CREATE SQLITE_OPEN_READONLY SQLITE_OPEN_READWRITE);
use Mojo::File             qw(path);
use Mojo::JSON             qw(decode_json encode_json from_json to_json);
use POSIX                  qw(strftime);

has 'config';
has writable    => 0;
has annotations => sub { Outcrop::Annotations->new(config => shift->config) };

sub valid_id {
    my ($self, $id) = @_;
    return defined $id && $id =~ /\A[0-9a-f]{32}\z/;
}

sub now {
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
}

sub db {
    my ($self) = @_;

    # A SQLite connection belongs to the process that opened it. Never reuse
    # an inherited connection if this store is accessed after a fork.
    return $self->{db} if $self->{db} && $self->{connection_pid} == $$;

    my $file = path($self->config->state, 'outcrop.sqlite');
    my $open_flags =
        $self->writable
        ? SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
        : SQLITE_OPEN_READONLY;
    my $database = DBI->connect(
        "dbi:SQLite:dbname=$file",
        '', '',
        {
            RaiseError        => 1,
            PrintError        => 0,
            AutoCommit        => 1,
            sqlite_unicode    => 1,
            sqlite_open_flags => $open_flags,
        }
    );
    $database->do('PRAGMA busy_timeout=5000');
    $database->do('ATTACH DATABASE ? AS annotations', undef, $self->config->annotations);

    $self->{connection_pid} = $$;
    $self->{db}             = $database;
    return $database;
}

sub initialize {
    my ($self) = @_;

    die 'Read-only store' unless $self->writable;
    $self->annotations->initialize;
    $self->db->do(
        q{
        CREATE TABLE IF NOT EXISTS scans (
            id             TEXT PRIMARY KEY,
            created_at     TEXT NOT NULL,
            status         TEXT NOT NULL,
            phase          TEXT NOT NULL,
            cleanup_status TEXT NOT NULL,
            metadata       TEXT NOT NULL
        )
    }
    );

    # Older installations used one required asset name. Preserve it in tags
    # while removing the obsolete column; source SBOMs are never rewritten.
    my $columns = $self->db->selectall_arrayref('PRAGMA table_info(scans)', {Slice => {}});
    if (grep { $_->{name} eq 'asset' } @$columns) {
        $self->db->begin_work;
        eval {
            my $rows = $self->db->selectall_arrayref('SELECT id, asset, metadata FROM scans');
            for my $row (@$rows) {

                # The previous schema stored UTF-8 bytes in a Unicode SQLite
                # text field. Decode that representation once during migration.
                my $scan = decode_json($row->[2]);
                $scan->{tags} //= [$row->[1]];
                delete $scan->{asset};
                $self->db->do('UPDATE scans SET metadata = ? WHERE id = ?',
                    undef, to_json($scan), $row->[0]);
            }
            $self->db->do('ALTER TABLE scans DROP COLUMN asset');
            $self->db->do('DROP TABLE IF EXISTS assets');
            $self->db->commit;
            1;
        } or do {
            my $error = $@;
            $self->db->rollback;
            die $error;
        };
    }
}

sub directory {
    my ($self, $id) = @_;

    die 'Invalid scan ID' unless $self->valid_id($id);
    return path($self->config->state, 'scans', $id);
}

sub read_json {
    my ($self, $file) = @_;
    return decode_json(path($file)->slurp);
}

sub atomic_json {
    my ($self, $file, $value) = @_;

    # Readers see either the previous complete document or its replacement,
    # including when Worker publishes state while Web is rendering a page.
    my $temporary = "$file.tmp";
    path($temporary)->spurt(encode_json($value));
    chmod 0640, $temporary or die "chmod $temporary: $!";
    rename $temporary, $file or die "rename $file: $!";
}

sub save {
    my ($self, $scan) = @_;

    die 'Read-only store' unless $self->writable;
    my $directory = $self->directory($scan->{id});
    $directory->make_path({mode => 0750});
    $self->atomic_json($directory->child('metadata.json'), $scan);

    # Scan history belongs to Outcrop rather than Minion's job retention.
    # Keep the full state document alongside the few columns used for listing.
    $self->db->do(
        q{
        INSERT INTO scans (id, created_at, status, phase, cleanup_status, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            status         = excluded.status,
            phase          = excluded.phase,
            cleanup_status = excluded.cleanup_status,
            metadata       = excluded.metadata
    }, undef,
        @$scan{qw(id created_at status phase cleanup_status)},
        to_json($scan),
    );
    return $scan;
}

sub get {
    my ($self, $id) = @_;

    return unless $self->valid_id($id);
    my ($json) = $self->db->selectrow_array('SELECT metadata FROM scans WHERE id = ?', undef, $id);
    return defined $json ? $self->_annotate(from_json($json)) : undef;
}

sub history {
    my ($self, $tag, $page) = @_;

    my $where = '';
    my @parameters;
    if (length($tag // '')) {
        $where = q{ WHERE EXISTS (
            SELECT 1 FROM json_each(COALESCE(
                (SELECT tags FROM annotations.scan_tags WHERE scan_id = scans.id),
                json_extract(metadata, '$.tags'), '[]'
            )) WHERE value = ?
        )};
        push @parameters, $tag;
    }
    my $offset = (($page // 1) - 1) * 50;

    # Fetch one extra row so the view can offer a next page without a separate
    # count query. Tags stay bound parameters, never SQL fragments.
    my $rows = $self->db->selectall_arrayref(
        "SELECT metadata FROM scans$where ORDER BY created_at DESC, id DESC LIMIT 51 OFFSET ?",
        {}, @parameters, $offset,);
    return [map { $self->_annotate(from_json($_->[0])) } @$rows];
}

sub _annotate {
    my ($self, $scan) = @_;
    $scan->{tags} = $self->annotations->get_tags($scan->{id}) // $scan->{tags} // [];
    $scan->{note} = $self->annotations->get_note($scan->{id}) // $scan->{note} // '';
    return $scan;
}

sub unfinished {
    my ($self) = @_;

    my $rows = $self->db->selectall_arrayref(
        q{
        SELECT metadata FROM scans
        WHERE status IN ('queued', 'running')
           OR cleanup_status IN ('mounted', 'needs_cleanup')
    }
    );
    return [map { $self->_annotate(from_json($_->[0])) } @$rows];
}

sub artifact {
    my ($self, $id, $kind) = @_;

    # The same allowlist is used for page rendering and downloads. Neither
    # caller can use a user-supplied filename to escape a scan directory.
    my %filenames = (
        syft     => 'sbom.syft.json',
        cdx      => 'sbom.cdx.json',
        grype    => 'vulnerabilities.grype.json',
        metadata => 'metadata.json',
        log      => 'scan.log',
    );
    return unless $filenames{$kind // ''} && $self->valid_id($id);

    my $file = $self->directory($id)->child($filenames{$kind});
    return unless -f $file && !-l $file;
    return $file;
}

sub log {
    my ($self, $id, $message) = @_;

    my $file = $self->directory($id)->child('scan.log');
    open my $handle, '>>:encoding(UTF-8)', $file or die "log: $!";
    print {$handle} now() . " $message\n";
    close $handle or die "log close: $!";
    chmod 0640, $file;
}

1;
