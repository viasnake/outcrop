use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Mojo::File qw(path);
use Minion;
use POSIX       qw(WNOHANG);
use Time::HiRes qw(time sleep);
use lib 'lib';
use Outcrop::Config;
use Outcrop::Store;
use Outcrop::Scan;
use Outcrop::Worker;

{

    package ConcurrentDisk;
    use Mojo::Base -base;
    has 'config';

    sub inventory {
        my ($self) = @_;
        my $pause = Mojo::File::path($self->config->state, 'pause-discovery');
        if (-f $pause) {
            Mojo::File::path($self->config->state, 'discovery-paused')->spurt('');
            Time::HiRes::sleep(0.02) while -f $pause;
        }
        my $file = Mojo::File::path($self->config->state, 'attached');
        return {
            updated_at => Time::HiRes::time(),
            errors     => [],
            disks      => -f $file ? [{name => $file->slurp}] : []
        };
    }

    sub mount_table {
        my ($self) = @_;
        return [map { {target => $_->to_string, source => '/dev/fixture'} }
                Mojo::File::path($self->config->mounts)->list->each];
    }

    package ConcurrentScan;
    use Mojo::Base 'Outcrop::Scan';

    sub run {
        my ($self, $request) = @_;
        my $scan  = $self->_start_scan($self->validate_request($request));
        my $root  = Mojo::File::path($self->config->state);
        my $mount = Mojo::File::path($self->config->mounts, $scan->{id});
        $mount->spurt('mounted');
        $scan->{cleanup_status} = 'mounted';
        $self->store->save($scan);
        my $interrupted;
        local $SIG{TERM} = sub { $interrupted = 1 };
        $root->child('started-' . $scan->{id})->spurt("$$:" . $self->cache_slot);

        until ($interrupted || -f $root->child('release-' . $scan->{id})) {
            Time::HiRes::sleep(0.02);
        }
        unlink $mount unless -f $root->child('leave-mount');
        $scan->{status}         = $interrupted ? 'interrupted' : 'completed';
        $scan->{phase}          = 'finished';
        $scan->{cleanup_status} = -f $mount ? 'needs_cleanup' : 'unmounted';
        return $self->store->save($scan);
    }
}

sub wait_for {
    my ($check) = @_;
    my $deadline = time + 8;
    while (time < $deadline) {
        return 1 if $check->();
        sleep 0.03;
    }
    return 0;
}

for my $limit (1, 2) {
    subtest "Admission and queue with $limit slots" => sub {
        my $dir    = tempdir(CLEANUP => 1);
        my $config = Outcrop::Config->new(
            state              => $dir,
            runtime            => "$dir/run",
            worker_jobs        => $limit,
            inventory_interval => 0.1
        );
        path($dir, 'queue')->make_path;
        path($config->mounts)->make_path;
        my $store = Outcrop::Store->new(config => $config, writable => 1);
        $store->initialize;
        my $queue   = Minion->new(SQLite => $config->queue);
        my $scanner = ConcurrentScan->new(config => $config, store => $store);
        my $worker  = Outcrop::Worker->new(
            config  => $config,
            store   => $store,
            minion  => $queue,
            scanner => $scanner,
            disk    => ConcurrentDisk->new(config => $config)
        );
        my @ids     = map { sprintf('%032x', $_) } 1 .. 4;
        my $enqueue = sub {
            my ($id) = @_;
            return $queue->enqueue(scan => [{id => $id, token => 'a' x 64}], {attempts => 5});
        };
        my $first = $enqueue->($ids[0]);
        my $pid   = fork;
        die "fork: $!" unless defined $pid;
        unless ($pid) {
            eval { $worker->run };
            path($dir, 'worker-error')->spurt($@) if $@;
            POSIX::_exit($@ ? 1 : 0);
        }
        ok(wait_for(sub { -f "$dir/started-$ids[0]" }), 'First scan starts');
        path($dir, 'attached')->spurt('/dev/new-disk');
        ok(
            wait_for(
                sub {
                    my $snapshot = eval { $store->read_json("$dir/inventory.json") };
                    return
                           $snapshot
                        && @{$snapshot->{disks}}
                        && $snapshot->{disks}[0]{name} eq '/dev/new-disk';
                }
            ),
            'New disk appears in inventory while first scan is blocked'
        );
        path($dir, 'pause-discovery')->spurt('');
        ok(wait_for(sub { -f "$dir/discovery-paused" }), 'Slow discovery is in progress');
        my $duplicate = $enqueue->($ids[0]);
        my $second    = $enqueue->($ids[1]);
        my $third     = $enqueue->($ids[2]);
        ok(wait_for(sub { $store->get($ids[2]) }), 'New submissions enter history during a scan');
        if ($limit == 2) {
            ok(wait_for(sub { -f "$dir/started-$ids[1]" }), 'Second process runs concurrently');
            is($queue->job($duplicate)->info->{state}, 'failed', 'Duplicate active ID is rejected');
            is($store->get($ids[0])->{status},
                'running', 'Rejected duplicate preserves active history');
            isnt(
                path($dir, "started-$ids[0]")->slurp,
                path($dir, "started-$ids[1]")->slurp,
                'Processes and cache slots are independent'
            );
        }
        else {
            ok(!-f "$dir/started-$ids[1]", 'One-slot setting keeps second scan queued');
        }
        ok(!-f "$dir/started-$ids[2]", 'Third scan cannot exceed configured limit');
        unlink "$dir/pause-discovery";
        path($dir, "release-$ids[0]")->spurt('');
        ok(wait_for(sub { -f "$dir/started-$ids[1]" }),
            'Next scan starts after a slot is released');
        path($dir, "release-$ids[1]")->spurt('');
        ok(wait_for(sub { -f "$dir/started-$ids[2]" }), 'Queued third scan starts');
        is($store->get($ids[0])->{status},        'completed', 'Completed history is preserved');
        is($queue->job($first)->info->{attempts}, 1, 'Retries are disabled before dispatch');
        kill 'TERM', $pid;
        my $ended = wait_for(sub { waitpid($pid, WNOHANG) == $pid });
        ok($ended, 'Supervisor stops and reaps all children');
        unless ($ended) { kill 'KILL', $pid; waitpid($pid, 0) }
        is($store->get($ids[2])->{status},         'interrupted', 'Stop reaches active child');
        is($store->get($ids[2])->{cleanup_status}, 'unmounted',   'Stopped child cleans its mount');
        ok(!-f "$dir/worker-error", 'Normal parallel mounts do not trip residual mount handling');
    };
}

for my $failure ('crash', 'cleanup') {
    subtest "Stop admission after $failure" => sub {
        my $dir    = tempdir(CLEANUP => 1);
        my $config = Outcrop::Config->new(state => $dir, runtime => "$dir/run", worker_jobs => 1);
        path($dir, 'queue')->make_path;
        path($config->mounts)->make_path;
        my $store = Outcrop::Store->new(config => $config, writable => 1);
        $store->initialize;
        my $queue   = Minion->new(SQLite => $config->queue);
        my $scanner = ConcurrentScan->new(config => $config, store => $store);
        my $worker  = Outcrop::Worker->new(
            config  => $config,
            store   => $store,
            minion  => $queue,
            scanner => $scanner,
            disk    => ConcurrentDisk->new(config => $config)
        );
        my @ids  = ('a' x 32, 'b' x 32);
        my @jobs = map { $queue->enqueue(scan => [{id => $_, token => 'c' x 64}]) } @ids;
        my $pid  = fork;
        die "fork: $!" unless defined $pid;

        unless ($pid) {
            eval { $worker->run };
            POSIX::_exit($@ ? 1 : 0);
        }
        ok(wait_for(sub { -f "$dir/started-$ids[0]" }), 'Scan started before failure');
        if ($failure eq 'crash') {
            my ($child) = split /:/, path($dir, "started-$ids[0]")->slurp;
            kill 'KILL', $child;
        }
        else {
            path($dir, 'leave-mount')->spurt('');
            path($dir, "release-$ids[0]")->spurt('');
        }
        my $ended = wait_for(sub { waitpid($pid, WNOHANG) == $pid });
        ok($ended, 'Supervisor exits after unsafe child termination');
        unless ($ended) { kill 'KILL', $pid; waitpid($pid, 0) }
        is($store->get($ids[0])->{cleanup_status}, 'needs_cleanup', 'Remaining mount is recorded');
        is($queue->job($jobs[1])->info->{state},   'inactive',      'Next job stays in the queue');
        ok(!-f "$dir/started-$ids[1]", 'No new scan starts after failure');
        my $inventory = $store->read_json("$dir/inventory.json");
        is_deeply(
            $inventory->{blocked},
            [$config->mounts . '/' . $ids[0]],
            'Residual mount is published to Web'
        );

        if ($failure eq 'crash') {
            is($store->get($ids[0])->{status}, 'interrupted', 'Crashed child is reconciled');
            is($queue->job($jobs[0])->info->{state},
                'failed', 'Crashed job is failed without replay');
        }
    };
}

for my $invalid (0, -1, 65, '2.5', 'abc', '') {
    my $worker = Outcrop::Worker->new(config => Outcrop::Config->new(worker_jobs => $invalid));
    eval { $worker->run };
    like($@, qr/Worker jobs must be/, "Reject invalid concurrency '$invalid' before startup");
}

done_testing;
