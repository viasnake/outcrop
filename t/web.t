use strict;
use warnings;
use utf8;
use Test::More;
use Test::Mojo;
use File::Temp qw(tempdir);
use Mojo::File qw(path);
use Mojo::JSON qw(encode_json);
use lib 'lib';
use Outcrop;
use Outcrop::Store;
use Outcrop::Config;
use Minion;

# Keep the real SQLite store and Minion queue, replacing only disk input and
# generated scan files with small, public fixture documents.
my $root   = tempdir(CLEANUP => 1);
my $config = Outcrop::Config->new(state => $root, runtime => "$root/run");
my $store  = Outcrop::Store->new(config => $config, writable => 1);
$store->initialize;
path($root, 'queue')->make_path;
path($root, 'queue/submit.lock')->spurt('');
path($root, 'web.secret')->spurt('test-secret-' x 8);
my $token = 'f' x 64;
$store->atomic_json(
    "$root/inventory.json",
    {
        updated_at => time,
        errors     => [],
        disks      => [
            {
                name    => '/dev/example',
                size    => 1000000000,
                serial  => 'fixture',
                targets => [
                    {
                        name       => '/dev/example1',
                        size       => 900000000,
                        fstype     => 'ext4',
                        selectable => 1,
                        reasons    => [],
                        token      => $token
                    }
                ]
            }
        ]
    }
);
my $id      = 'a' x 32;
my $payload = '<script>alert("external")</script>';
my $scan    = {
    id             => $id,
    tags           => [$payload],
    note           => $payload,
    created_at     => '2026-01-01T00:00:00Z',
    status         => 'completed',
    phase          => 'finished',
    cleanup_status => 'unmounted',
    warnings       => [$payload]
};
$store->save($scan);
my $dir = $store->directory($id);
$store->atomic_json(
    $dir->child('sbom.syft.json'),
    {
        artifacts => [
            {
                name      => $payload,
                version   => '1.0',
                type      => 'deb',
                foundBy   => 'fixture',
                locations => [{path => '/var/lib/dpkg/status'}]
            }
        ]
    }
);
$store->atomic_json(
    $dir->child('vulnerabilities.grype.json'),
    {
        matches => [
            {
                artifact      => {name => $payload},
                vulnerability => {
                    id       => 'CVE-EXAMPLE-001',
                    severity => 'High',
                    fix      => {versions => ['1.1'], state => 'fixed'}
                }
            }
        ]
    }
);
$store->log($id, $payload);
my $queue = Minion->new(SQLite => $config->queue);
my $app   = Outcrop->new(
    settings => $config,
    store    => Outcrop::Store->new(config => $config),
    queue    => $queue
);
$app->log->level('error');
my $t = Test::Mojo->new($app);

# Exercise the HTTP boundary with the same read-only scan store used by Web.
# Assertions concern data, authorization, and side effects, not page layout.
$t->get_ok('/history')->status_is(200)->content_unlike(qr/<script>alert/);
$t->get_ok("/scans/$id")->status_is(200)->content_unlike(qr/<script>alert/);
$t->get_ok("/scans/$id/download/syft")
    ->status_is(200)
    ->content_is($dir->child('sbom.syft.json')->slurp);
$t->get_ok("/scans/$id/download/grype")
    ->status_is(200)
    ->content_is($dir->child('vulnerabilities.grype.json')->slurp);
$t->get_ok("/scans/$id/download/secret")->status_is(404);
$t->get_ok('/scans/invalid/download/metadata')->status_is(404);
$t->get_ok("/scans/$id/download/..%2F..%2Fweb.secret")->status_is(404);

sub job_count {
    return $queue->backend->sqlite->db->query('SELECT count(*) AS count FROM minion_jobs')
        ->hash->{count};
}

$t->get_ok('/scans/' . $id => {Host => 'attacker.example'})->status_is(403);
$t->post_ok('/scans' => form => {scan_id => 'b' x 32, target => $token, clone => 'yes'})
    ->status_is(403);
is(job_count(), 0, 'Rejected requests cannot enqueue privileged scan work');

$t->get_ok('/')->status_is(200);
my $csrf   = $t->tx->res->dom->at('input[name="csrf_token"]')->attr('value');
my $new_id = $t->tx->res->dom->at('input[name="scan_id"]')->attr('value');
my %form   = (
    csrf_token => $csrf,
    scan_id    => $new_id,
    target     => $token,
    clone      => 'yes',
    tags       => ['clone-test', '日本語', 'team,blue'],
    new_tag    => 'pending-tag',
    note       => '',
);
$t->post_ok('/scans' => form => \%form)->status_is(303);
is_deeply(
    $app->pending_scans->[0]{tags},
    ['clone-test', '日本語', 'team,blue', 'pending-tag'],
    'Submission preserves separate Unicode tags, literal commas, and the unfinished input'
);
$t->post_ok('/scans' => form => \%form)->status_is(302);
is(job_count(), 1, 'Resubmitting a form cannot schedule the same disk scan twice');

# Rejected edits must leave all existing annotations and original artifacts intact.
$t->post_ok("/scans/$id/tags" => form => {operation => 'add', tag => 'denied'})->status_is(403);
$t->post_ok("/scans/$id/note" => form => {note      => 'denied'})->status_is(403);
is_deeply($store->get($id)->{tags}, [$payload], 'Missing CSRF cannot change tags');
is($store->get($id)->{note}, $payload, 'Missing CSRF cannot change a note');

$t->post_ok(
    "/scans/$id/tags" => {Accept => 'application/json'} => form => {
        csrf_token => $csrf,
        operation  => 'add',
        tag        => 'production'
    }
)->status_is(200)->json_is('/tags', [$payload, 'production']);
$t->post_ok(
    "/scans/$id/tags" => form => {
        csrf_token => $csrf,
        operation  => 'add',
        tag        => 'x' x 121
    }
)->status_is(400);
is_deeply(
    $store->get($id)->{tags},
    [$payload, 'production'],
    'An invalid edit cannot overwrite existing tags'
);
$t->post_ok("/scans/$id/tags" => form => {csrf_token => $csrf, tags => ''})->status_is(400);
is_deeply(
    $store->get($id)->{tags},
    [$payload, 'production'],
    'An obsolete overwrite request cannot clear tags'
);
$t->get_ok('/history?tag=production')
    ->status_is(200)
    ->content_like(qr/\Q$id\E/)
    ->content_unlike(qr/\Q$new_id\E/);
$t->get_ok('/history?tag=prod')->status_is(200)->content_unlike(qr/\Q$id\E/);
$t->post_ok(
    "/scans/$id/tags" => form => {
        csrf_token => $csrf,
        operation  => 'remove',
        tag        => 'production'
    }
)->status_is(303);
is_deeply($store->get($id)->{tags}, [$payload], 'Removing one tag preserves every other tag');

my $note = "日本語のメモ\n$payload";
$t->post_ok(
    "/scans/$id/note" => {Accept => 'application/json'} => form => {
        csrf_token => $csrf,
        note       => $note
    }
)->status_is(200)->json_is('/note', $note);
$t->get_ok("/scans/$id")->status_is(200)->content_unlike(qr/<script>alert/);
$t->get_ok("/scans/$id/download/metadata")
    ->status_is(200)
    ->json_is('/note', $note)
    ->json_is('/tags', [$payload]);
$t->post_ok("/scans/$id/note" => form => {csrf_token => $csrf, note => 'x' x 2001})->status_is(400);
is($store->get($id)->{note}, $note, 'An invalid note edit preserves the previously saved value');
$t->post_ok('/scans/' . ('f' x 32) . '/note' => form => {csrf_token => $csrf, note => ''})
    ->status_is(404);
$t->post_ok("/scans/$id/note" => form => {csrf_token => $csrf, note => ''})->status_is(303);
is($store->get($id)->{note}, '', 'Clearing a note persists rather than restoring its old value');
is_deeply($store->read_json($dir->child('metadata.json')),
    $scan, 'Annotation edits never rewrite the original scan record');
is(job_count(), 1, 'Annotation edits never enqueue or replay disk work');

# Target authorization comes from current inventory, never a claimed kind or
# an old browser form. Verify rejection by the unchanged queue as well as HTTP.
my $inventory  = $store->read_json("$root/inventory.json");
my $host_token = 'e' x 64;
$inventory->{host} = {kind => 'host', selectable => 1, token => $host_token};
$store->atomic_json("$root/inventory.json", $inventory);
my %host_form = (csrf_token => $csrf, scan_id => Outcrop::random_id(), target => $host_token);
$t->post_ok('/scans' => form => \%host_form)->status_is(303);
is(job_count(), 2, 'Live-host scanning does not require a false clone claim');
$host_form{scan_id} = Outcrop::random_id();
$host_form{target}  = $token;
$host_form{kind}    = 'host';
$t->post_ok('/scans' => form => \%host_form)->status_is(400);
$host_form{target} = $host_token;
$inventory->{updated_at} = time - 60;
$store->atomic_json("$root/inventory.json", $inventory);
$t->post_ok('/scans' => form => \%host_form)->status_is(409);
$inventory->{updated_at} = time;
$inventory->{blocked}    = ['/run/outcrop/mounts/fixture'];
$store->atomic_json("$root/inventory.json", $inventory);
$t->post_ok('/scans' => form => \%host_form)->status_is(409);
is(job_count(), 2, 'Forged targets, stale inventory, and residual mounts cannot create scan jobs');

# Polling renders current disk controls even while earlier scans are active.
$inventory->{updated_at} = time;
$inventory->{blocked}    = [];
my $new_token = 'd' x 64;
my $new_disk  = {
    name    => '/dev/hotplug',
    targets => [
        {
            name       => '/dev/hotplug1',
            token      => $new_token,
            fstype     => 'ext4',
            selectable => 1,
            reasons    => [],
            size       => 1000,
        }
    ],
};
push @{$inventory->{disks}}, $new_disk;
$store->atomic_json("$root/inventory.json", $inventory);
$queue->add_task(scan => sub { });
my $running_worker = $queue->worker->register;
my $running_job    = $running_worker->dequeue(0, {tasks => ['scan']});
ok($running_job, 'Existing scan is active during hotplug submission');
$t->get_ok('/inventory')
    ->status_is(200)
    ->header_is('Cache-Control', 'no-store')
    ->element_exists('input[value="' . $new_token . '"]')
    ->element_exists_not('textarea[name="note"]');
my $async_id   = Outcrop::random_id();
my %async_form = (csrf_token => $csrf, scan_id => $async_id, target => $new_token, clone => 'yes');
$t->post_ok('/scans' => {Accept => 'application/json'} => form => \%async_form)
    ->status_is(202)
    ->json_is('/id',  $async_id)
    ->json_is('/url', "/scans/$async_id");
like($t->tx->res->json->{next_id}, qr/\A[0-9a-f]{32}\z/,
    'Response supplies the next submission ID');
$t->post_ok('/scans' => {Accept => 'application/json'} => form => \%async_form)
    ->status_is(200)
    ->json_is('/id', $async_id);
is(job_count(), 3, 'Retrying an asynchronous submission is idempotent');
$async_form{scan_id} = Outcrop::random_id();
$t->post_ok('/scans' => {Accept => 'application/json'} => form => \%async_form)->status_is(409);
is(job_count(), 3, 'A second submission ID cannot duplicate a pending target');
$inventory->{updated_at} = time - 60;
$store->atomic_json("$root/inventory.json", $inventory);
$t->get_ok('/inventory')
    ->status_is(200)
    ->element_exists('input[value="' . $new_token . '"][disabled]');
$running_job->finish;
$running_worker->unregister;

done_testing;
