use strict;
use warnings;
use utf8;
use Test::More;
use File::Temp qw(tempdir);
use Mojo::JSON qw(encode_json);
use DBI;
use IO::Select;
use lib 'lib';
use Outcrop::Config;
use Outcrop::Store;
use Outcrop::Tags;
use Outcrop::Annotations;
use Outcrop::Scan;

is_deeply(
    Outcrop::Tags->validate([' production', '日本語', 'web', 'production', '', ' ']),
    ['production', '日本語', 'web'],
    'Whitespace, blanks, and duplicate tags are normalized'
);
is_deeply(Outcrop::Tags->validate([]), [], 'Tags are optional');
for my $invalid ([{}], [undef], ["bad\nvalue"], ['x' x 121], [('tag') x 21]) {
    ok(!eval { Outcrop::Tags->validate($invalid); 1 }, 'Malformed or excessive tags are rejected');
}
my $input = [' padded '];
Outcrop::Tags->validate($input);
is_deeply($input, [' padded '], 'Validation does not mutate its input');

my $root   = tempdir(CLEANUP => 1);
my $config = Outcrop::Config->new(state => $root);

# Reproduce the old schema so migration is tested against real SQLite data.
my $database = DBI->connect("dbi:SQLite:dbname=$root/outcrop.sqlite",
    '', '', {RaiseError => 1, sqlite_unicode => 1});
$database->do('CREATE TABLE assets (name TEXT PRIMARY KEY)');
$database->do(
    'CREATE TABLE scans (id TEXT PRIMARY KEY, asset TEXT NOT NULL, created_at TEXT NOT NULL, status TEXT NOT NULL, phase TEXT NOT NULL, cleanup_status TEXT NOT NULL, metadata TEXT NOT NULL)'
);
my $id  = 'a' x 32;
my $old = {
    id             => $id,
    asset          => 'legacy 日本語',
    created_at     => '2026-01-01',
    status         => 'completed',
    phase          => 'finished',
    cleanup_status => 'not_needed'
};
$database->do(
    'INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)',           undef,
    @$old{qw(id asset created_at status phase cleanup_status)}, encode_json($old)
);
$database->disconnect;
my $store = Outcrop::Store->new(config => $config, writable => 1);
$store->initialize;
$store->initialize;
is_deeply($store->get($id)->{tags},
    ['legacy 日本語'], 'Legacy asset names become tags; migration is repeatable');
ok(!exists($store->get($id)->{asset}), 'The obsolete asset field is removed');
is(scalar(@{$store->history('legacy 日本語')}), 1, 'Migrated tags are searchable');

$store->annotations->change_tags($id, ['legacy 日本語'], 'add', ['production']);
my $other_tab = Outcrop::Annotations->new(config => $config);
$other_tab->change_tags($id, ['legacy 日本語'], 'add', ['日本語']);
is_deeply(
    $store->get($id)->{tags},
    ['legacy 日本語', 'production', '日本語'],
    'Additions from stale tabs preserve each other'
);
$other_tab->change_tags($id, ['legacy 日本語'], 'remove', ['legacy 日本語']);
is(scalar(@{$store->history('legacy 日本語')}),
    0, 'Edited annotations replace original tags in filtering');
is(scalar(@{$store->history('日本語')}),          1, 'Unicode tag filtering works');
is(scalar(@{$store->history(q{' OR 1=1 --})}), 0, 'Tag values cannot change the history query');
my $scan = $store->get($id);
$scan->{tags} = ['stale'];
$store->save($scan);
is_deeply(
    $store->get($id)->{tags},
    ['production', '日本語'],
    'Worker state updates cannot overwrite edited annotations'
);

my $full_id = 'c' x 32;
my @full    = map { "tag-$_" } 1 .. 20;
$store->annotations->change_tags($full_id, [], 'add', \@full);
is_deeply($store->annotations->change_tags($full_id, [], 'add', ['tag-1']),
    \@full, 'Adding an existing tag is harmless at the tag limit');
ok(!eval { $store->annotations->change_tags($full_id, [], 'add', ['extra']); 1 },
    'The combined tag count is bounded');
is_deeply($store->annotations->get_tags($full_id),
    \@full, 'An invalid addition rolls back without losing tags');
is_deeply(
    $store->annotations->change_tags($id, [], 'remove', ['not-present']),
    ['production', '日本語'],
    'Removing a missing tag does not affect others'
);

$store->annotations->save_note($id, "編集したメモ\n2行目");
is($store->get($id)->{note}, "編集したメモ\n2行目", 'Edited Unicode notes are overlaid on scan metadata');
$scan->{note} = 'stale worker value';
$store->save($scan);
is($store->get($id)->{note}, "編集したメモ\n2行目", 'Worker state updates preserve edited notes');
$store->annotations->save_note($id, '');
is($store->get($id)->{note}, '', 'An explicitly cleared note stays empty');
for my $note (['invalid'], 'x' x 2001, "bad\x00note") {
    ok(!eval { $store->annotations->save_note($id, $note); 1 }, 'Invalid notes are rejected');
}

# A read-only scan connection must still allow annotations through their
# separate database, without making the original scan record writable.
my $reader = Outcrop::Store->new(config => $config);
ok(
    !eval {
        $reader->db->do('UPDATE scans SET status = ?', undef, 'corrupted');
        1;
    },
    'Web cannot update the scan database through its read-only connection'
);
is($store->get($id)->{status}, 'completed', 'Rejected writes preserve scan status');
$reader->annotations->save_note($id, 'Web annotation');
is(
    $reader->get($id)->{note},
    'Web annotation',
    'Web can edit annotations without scan write access'
);

# Hold an uncommitted edit in one process while another adds a tag. Moving
# the read outside BEGIN IMMEDIATE would lose the first writer's tag here.
my $concurrent_id = 'd' x 32;
$store->annotations->db->do('BEGIN IMMEDIATE');
$store->annotations->db->do('INSERT INTO scan_tags VALUES (?, ?)',
    undef, $concurrent_id, '["first-writer"]');
pipe my $child_result, my $child_output or die "pipe: $!";
my $child = fork;
die "fork: $!" unless defined $child;
if (!$child) {
    close $child_result;
    open STDOUT, '>&', $child_output or die "redirect child output: $!";

    # Exec gives SQLite a clean process without inherited connection state.
    my $program = <<'PERL';
use strict;
use warnings;
use Outcrop::Config;
use Outcrop::Annotations;
$| = 1;
print "ready\n";
my $config = Outcrop::Config->new(state => $ARGV[0]);
my $succeeded = eval {
    Outcrop::Annotations->new(config => $config)->change_tags($ARGV[1], [], 'add', ['second-writer']);
    1;
};
print $succeeded ? "saved\n" : "failed: $@\n";
exit($succeeded ? 0 : 1);
PERL
    exec $^X, '-Ilib', '-e', $program, $root, $concurrent_id;
    die "exec: $!";
}
close $child_output;
is(scalar(<$child_result>), "ready\n", 'Concurrent editor started');
ok(
    !IO::Select->new($child_result)->can_read(0.2),
    'The second editor waits for the first transaction'
);
$store->annotations->db->do('COMMIT');
my $finished = IO::Select->new($child_result)->can_read(6);
ok($finished, 'The waiting edit completes after commit');
kill 'TERM', $child unless $finished;
is($finished ? scalar(<$child_result>) : '', "saved\n", 'The second writer saves successfully');
waitpid $child, 0;
is($?, 0, 'Concurrent editor exits successfully');
is_deeply(
    $store->annotations->get_tags($concurrent_id),
    ['first-writer', 'second-writer'],
    'Overlapping transactions preserve both writers rather than losing an edit'
);

my $scanner = Outcrop::Scan->new(store => $store);
my $request = $scanner->validate_request(
    {id => 'b' x 32, token => 'f' x 64, note => '', command => '/evil', tags => []});
is_deeply($request->{tags}, [], 'Scan requests accept no tags');
ok(!exists($request->{command}), 'Only accepted fields cross into Worker');
ok(!eval { $scanner->validate_request({%$request, tags => 'untrusted'}); 1 },
    'Worker validates tag shapes independently');

done_testing;
