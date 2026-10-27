use strict;
use warnings;
use utf8;
use Test::More;
use File::Temp qw(tempdir);
use Mojo::File qw(path);
use Minion;
use Time::HiRes qw(sleep);
use lib 'lib';
use Outcrop::Config;
use Outcrop::Store;
use Outcrop::Scan;
use Outcrop::Worker;

# Recovery uses a real Minion queue and a recorded mount table, without any
# privileged directory setup or block-device access.
{

    package RecoveryDisk;
    use Mojo::Base -base;
    has mounts => sub { [] };
    sub mount_table { shift->mounts }
    sub inventory   { return {updated_at => time, disks => [], errors => []} }

    package WorkerScan;
    use Mojo::Base 'Outcrop::Scan';

    sub run {
        my ($self, $request) = @_;
        $self->validate_request($request);
        die 'Failure before recording start' if $request->{note} eq 'fail-before-start';
        my $scan = $self->store->get($request->{id});
        $scan->{status} = 'interrupted';
        $scan->{phase}  = 'finished';
        return $self->store->save($scan);
    }
}
my $dir = tempdir(CLEANUP => 1);
path($dir, 'queue')->make_path;
my $config = Outcrop::Config->new(state => $dir, runtime => "$dir/run");
path($config->runtime)->make_path;

# A surviving exec child must keep a second worker out after its parent
# closes the lock; releasing only the parent's descriptor is insufficient.
{
    my $first  = Outcrop::Worker->new(config => $config);
    my $second = Outcrop::Worker->new(config => $config);
    $first->acquire_lock;
    eval { $second->acquire_lock };
    like($@, qr/already running/, 'A second worker cannot acquire the disk-operation lock');
    my $ready = "$dir/child.ready";
    my $child = fork;
    die "fork: $!" unless defined $child;

    if (!$child) {
        my $program = <<'PERL';
open my $ready_file, '>', $ARGV[0] or die $!;
close $ready_file;
sleep 30;
PERL
        exec $^X, '-e', $program, $ready;
        die "exec: $!";
    }
    for (1 .. 200) {
        last if -f $ready;
        sleep 0.01;
    }
    ok(-f $ready, 'External child started');
    close delete $first->{lock};
    eval { $second->acquire_lock };
    like($@, qr/already running/,
        'An exec child holds the lock after the worker descriptor closes');
    kill 'TERM', $child;
    waitpid $child, 0;
    ok(eval { $second->acquire_lock; 1 }, 'Lock releases only after the surviving child exits');
}
my $store = Outcrop::Store->new(config => $config, writable => 1);
$store->initialize;
my $minion = Minion->new(SQLite => $config->queue);
$minion->add_task(scan => sub { die 'Must not replay interrupted task' });
my $scanner = WorkerScan->new(config => $config, store => $store);

# Simulate a crash after dequeue, leaving both an active job and a mount.
my $running_request = {id => 'a' x 32, tags => ['old'],     note => '', token => 'b' x 64};
my $queued_request  = {id => 'c' x 32, tags => ['new 日本語'], note => '', token => 'd' x 64};
my $old             = $scanner->queued($running_request);
$old->{status}         = 'running';
$old->{cleanup_status} = 'mounted';
$store->save($old);
my $job_id        = $minion->enqueue(scan => [$running_request], {attempts => 1});
my $minion_worker = $minion->worker->register;
my $active        = $minion_worker->dequeue(0, {tasks => ['scan']});
ok($active, 'Real Minion job was active at simulated shutdown');
my $mount  = $config->mounts . '/' . $old->{id};
my $disk   = RecoveryDisk->new(mounts => [{target => $mount, source => '/dev/example1'}]);
my $worker = Outcrop::Worker->new(
    config  => $config,
    store   => $store,
    disk    => $disk,
    scanner => $scanner,
    minion  => $minion
);
my $blocked = $worker->recover;
is(scalar(@$blocked),                         1,               'Residual mount blocks new work');
is($store->get($old->{id})->{status},         'interrupted',   'Crashed scan becomes interrupted');
is($store->get($old->{id})->{cleanup_status}, 'needs_cleanup', 'Residual mount remains unsafe');
is($minion->job($job_id)->info->{state},      'failed', 'Interrupted Minion job is not replayed');

# Reconcile manual cleanup without replaying the interrupted scan.
$disk->mounts([]);
is_deeply($worker->recover, [], 'Verified manual removal releases startup barrier');
is($store->get($old->{id})->{cleanup_status},
    'unmounted', 'Manual cleanup is reflected in stored state');

# A new job still uses Minion's lifecycle, while its history outlives the job.
my $next_id = $minion->enqueue(scan => [$queued_request], {attempts => 3});
$worker->sync_queue;
is($store->get($queued_request->{id})->{status},
    'queued', 'Queue state is copied into permanent history');
is_deeply(
    $store->get($queued_request->{id})->{tags},
    $queued_request->{tags},
    'Worker preserves Unicode tags in permanent history'
);
my $early_request = {id => 'e' x 32, token => 'f' x 64, note => 'fail-before-start'};
my $early_id      = $minion->enqueue(scan => [$early_request], {attempts => 1});
$worker->run;
is($minion->job($early_id)->info->{state}, 'failed', 'Early child failure terminates its job');
is($store->get($early_request->{id})->{status},
    'failed', 'Early failure cannot leave history queued');
is($minion->job($next_id)->info->{state},
    'finished', 'Worker executes through real Minion lifecycle');
is($minion->job($next_id)->info->{attempts}, 1, 'Worker enforces no automatic retry');
$minion->job($next_id)->remove;
ok($store->get($queued_request->{id}), 'Scan history survives Minion job removal');
$minion_worker->unregister;
done_testing;
