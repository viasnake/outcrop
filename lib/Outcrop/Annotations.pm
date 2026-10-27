package Outcrop::Annotations;
use Mojo::Base -base;

use DBI;
use Mojo::File qw(path);
use Mojo::JSON qw(from_json to_json);
use Outcrop::Tags;

has 'config';

sub initialize {
    my ($self) = @_;
    path($self->config->annotations)->dirname->make_path({mode => 0750});
    $self->db->do(
        'CREATE TABLE IF NOT EXISTS scan_tags (scan_id TEXT PRIMARY KEY, tags TEXT NOT NULL)');
    $self->db->do(
        'CREATE TABLE IF NOT EXISTS scan_notes (scan_id TEXT PRIMARY KEY, note TEXT NOT NULL)');
}

sub db {
    my ($self) = @_;
    return $self->{db} if $self->{db} && $self->{connection_pid} == $$;
    my $file     = $self->config->annotations;
    my $database = DBI->connect(
        "dbi:SQLite:dbname=$file",
        '', '',
        {
            RaiseError     => 1,
            PrintError     => 0,
            AutoCommit     => 1,
            sqlite_unicode => 1,
        }
    );
    $database->do('PRAGMA busy_timeout=5000');
    $self->{connection_pid} = $$;
    return $self->{db} = $database;
}

sub get_tags {
    my ($self, $id) = @_;
    my ($tags) =
        $self->db->selectrow_array('SELECT tags FROM scan_tags WHERE scan_id = ?', undef, $id);
    return defined($tags) ? from_json($tags) : undef;
}

sub change_tags {
    my ($self, $id, $original, $operation, $values) = @_;
    die 'Invalid scan ID'       unless ($id // '') =~ /\A[0-9a-f]{32}\z/;
    die 'Invalid tag operation' unless $operation eq 'add' || $operation eq 'remove';
    $values = Outcrop::Tags->validate($values);
    die 'Remove exactly one tag' if $operation eq 'remove' && @$values != 1;

    # Serialize read-modify-write so two tabs adding different tags do not
    # discard each other's edits. Original tags apply until the first edit.
    $self->db->do('BEGIN IMMEDIATE');
    my $tags;
    my $succeeded = eval {
        my $current = $self->get_tags($id) // $original;
        my %seen;
        my @combined = grep { !$seen{$_}++ } (@$current, @$values);
        $tags =
            $operation eq 'add'
            ? Outcrop::Tags->validate(\@combined)
            : [grep { $_ ne $values->[0] } @$current];
        $self->db->do(
            'INSERT INTO scan_tags (scan_id, tags) VALUES (?, ?) ON CONFLICT(scan_id) DO UPDATE SET tags = excluded.tags',
            undef, $id, to_json($tags),
        );
        $self->db->do('COMMIT');
        1;
    };
    unless ($succeeded) {
        my $error = $@;
        $self->db->do('ROLLBACK');
        die $error;
    }
    return $tags;
}

sub validate_note {
    my ($class, $note) = @_;
    die 'Invalid note' if ref($note) || length($note // '') > 2000 || ($note // '') =~ /\x00/;
    return $note // '';
}

sub get_note {
    my ($self, $id) = @_;
    my ($note) =
        $self->db->selectrow_array('SELECT note FROM scan_notes WHERE scan_id = ?', undef, $id);
    return $note;
}

sub save_note {
    my ($self, $id, $note) = @_;
    die 'Invalid scan ID' unless ($id // '') =~ /\A[0-9a-f]{32}\z/;
    $note = $self->validate_note($note);

    # Notes share the Web-writable annotation database. Editing a note never
    # changes the original scan record or a published result file.
    $self->db->do(
        'INSERT INTO scan_notes (scan_id, note) VALUES (?, ?) ON CONFLICT(scan_id) DO UPDATE SET note = excluded.note',
        undef, $id, $note,
    );
    return $note;
}

1;
