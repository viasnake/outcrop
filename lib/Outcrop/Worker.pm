package Outcrop::Worker;
use Mojo::Base -base;
use Mojo::File qw(path);
use Mojo::JSON qw(from_json);
use Fcntl      qw(:flock O_CREAT O_RDWR O_NOFOLLOW F_SETFD);
use Cwd        qw(abs_path);
use Outcrop::Store;
use POSIX       qw(WNOHANG);
use Time::HiRes qw(sleep time);

has [qw(config store disk scanner minion)];

sub trusted_path {
    my ($self, $file) = @_;
    my $resolved = abs_path($file) or die "Missing trusted path: $file";
    while (1) {
        my @stat = stat $resolved;
        die "Root must own $resolved and deny group/other writes"
            unless @stat && $stat[4] == 0 && !($stat[2] & 0022);
        last if $resolved eq '/';
        $resolved = path($resolved)->dirname->to_string;
    }
}

sub initialize {
    my ($self, $app_root) = @_;

    die 'Worker must run as root' unless $> == 0;
    my $group_id = getgrnam('outcrop');
    die 'Create the outcrop group first' unless defined $group_id;

    $self->_verify_runtime_code($app_root);

    # New state files belong to root:outcrop. Web can read scan results, but
    # only the explicitly shared queue directory grants it write permission.
    umask 0027;
    $( = $group_id;
    $) = "$group_id $group_id";
    $self->_prepare_directories($group_id);
    $self->_prepare_queue($group_id);

    $self->acquire_lock;
    $self->_prepare_annotations($group_id);
    $self->store->initialize;
    chmod 0640, $self->config->state . '/outcrop.sqlite';
}

sub _verify_runtime_code {
    my ($self, $app_root) = @_;

    # Everything the privileged process can load must be immutable to Web.
    $self->trusted_path($app_root);
    for my $file (path($app_root)->list_tree->each) {
        next unless "$file" =~ m{/(?:lib|script)/} || "$file" =~ /\.pm\z/;
        $self->trusted_path($file);
    }
    for my $executable ($self->config->syft, $self->config->grype) {
        $self->trusted_path($executable);
    }
}

sub _prepare_directories {
    my ($self, $group_id) = @_;

    my @directories = (
        $self->config->state,
        $self->config->state . '/scans',
        $self->config->state . '/grype-db',
        $self->config->runtime,
        $self->config->mounts,
    );
    for my $directory (@directories) {
        path($directory)->make_path({mode => 0750});
        my @stat = stat $directory;
        die "Unsafe directory: $directory"
            if -l $directory || $stat[4] != 0 || ($stat[2] & 0022);
        chown 0, $group_id, $directory or die "chown $directory: $!";
        chmod 0750, $directory or die "chmod $directory: $!";
    }
}

sub _prepare_queue {
    my ($self, $group_id) = @_;

    my $queue_directory = $self->config->state . '/queue';
    path($queue_directory)->make_path({mode => 03770});
    die 'Queue must be a root-owned directory'
        if -l $queue_directory || (stat $queue_directory)[4] != 0;
    chown 0, $group_id, $queue_directory or die "chown queue: $!";

    # The sticky bit prevents Web from replacing root-owned queue files.
    # Group write on the database itself is still needed for Minion requests.
    chmod 03770, $queue_directory or die "chmod queue: $!";
    my $database = $self->config->queue;
    if (-e $database) {
        my @stat = stat $database;
        die 'Unsafe queue database'
            if -l $database || !-f $database || $stat[4] != 0 || $stat[3] != 1;
    }
    sysopen my $queue_file, $database, O_CREAT | O_RDWR | O_NOFOLLOW, 0660
        or die "Queue database: $!";
    chmod 0660, $database or die "chmod queue database: $!";

    my $submission_lock = "$queue_directory/submit.lock";
    sysopen my $submit, $submission_lock, O_CREAT | O_RDWR | O_NOFOLLOW, 0660
        or die "Submission lock: $!";
    my @stat = stat $submit;
    die 'Unsafe submission lock' unless -f $submit && $stat[4] == 0 && $stat[3] == 1;
    chmod 0660, $submit;
}

sub _prepare_annotations {
    my ($self, $group_id) = @_;
    my $file      = $self->config->annotations;
    my $directory = path($file)->dirname;
    $directory->make_path({mode => 03770});
    die 'Annotations must be a root-owned directory'
        if -l $directory || (stat $directory)[4] != 0;
    chown 0, $group_id, $directory or die "chown annotations: $!";
    chmod 03770, $directory or die "chmod annotations: $!";

    # SQLite journals need directory access, but the sticky bit prevents Web
    # from replacing the root-owned database or redirecting a Worker write.
    sysopen my $database, $file, O_CREAT | O_RDWR | O_NOFOLLOW, 0660
        or die "Annotations database: $!";
    my @stat = stat $database;
    die 'Unsafe annotations database'
        unless -f $database && $stat[4] == 0 && $stat[3] == 1;
    chown 0, $group_id, $file or die "chown annotations database: $!";
    chmod 0660, $file or die "chmod annotations database: $!";
}

sub acquire_lock {
    my ($self) = @_;
    open my $lock, '>>', $self->config->runtime . '/worker.lock' or die "Worker lock: $!";
    flock($lock, LOCK_EX | LOCK_NB) or die 'Another worker or surviving child is already running';

    # An orphaned mount/CLI process must keep the lock after a hard worker
    # crash, including the interval before mount appears in mountinfo.
    fcntl($lock, F_SETFD, 0) or die "Preserve worker lock in children: $!";
    $self->{lock} = $lock;
}

sub pending {
    my ($self) = @_;
    return $self->minion->backend->sqlite->db->query(
        q{
        SELECT id, args, state FROM minion_jobs
        WHERE task = 'scan' AND state IN ('inactive', 'active')
        ORDER BY id
    }
    )->hashes->to_array;
}

sub sync_queue {
    my ($self) = @_;

    # Import only validated submissions that are not already in permanent
    # history. Web-writable queue fields never overwrite Worker-owned state.
    for my $job (@{$self->pending}) {

        # SQLite returns JSON text with Unicode already decoded.
        my $arguments = eval { from_json($job->{args}) };
        next unless ref $arguments eq 'ARRAY' && @$arguments == 1;
        my $request = eval { $self->scanner->validate_request($arguments->[0]) };
        next unless $request;
        next if $self->store->get($request->{id});
        $self->store->save($self->scanner->queued($request));
    }
}

sub recover {
    my ($self) = @_;

    my $mount_root = $self->config->mounts;
    my @remaining = grep { $_->{target} eq $mount_root || index($_->{target}, "$mount_root/") == 0 }
        @{$self->disk->mount_table};

    # Never remount or replay interrupted work. The administrator must inspect
    # remaining mounts and restart Worker after manually removing them.
    for my $scan (@{$self->store->unfinished}) {
        next if $scan->{status} eq 'queued';
        $self->_recover_scan($scan, \@remaining);
    }
    $self->_fail_interrupted_jobs;

    return [map { "$_->{target} ($_->{source})" } @remaining];
}

sub _recover_scan {
    my ($self, $scan, $remaining_mounts) = @_;

    my $mountpoint = $self->config->mounts . '/' . $scan->{id};
    my $still_mounted =
        grep { $_->{target} eq $mountpoint || index($_->{target}, "$mountpoint/") == 0 }
        @$remaining_mounts;

    if ($scan->{status} eq 'running') {
        $scan->{status} = 'interrupted';
        $scan->{error}  = 'Worker stopped unexpectedly; this scan will not be replayed';
    }

    # The processing outcome stays interrupted/partial even when manual
    # cleanup has since removed the mount. Only cleanup status is reconciled.
    if ($still_mounted) {
        $scan->{cleanup_status} = 'needs_cleanup';
    }
    elsif ($scan->{cleanup_status} ne 'not_needed') {
        $scan->{cleanup_status} = 'unmounted';
    }
    $scan->{finished_at} //= Outcrop::Store::now();
    $scan->{phase} = 'finished';
    $self->store->save($scan);
}

sub _fail_interrupted_jobs {
    my ($self) = @_;

    for my $pending (@{$self->pending}) {
        next unless $pending->{state} eq 'active';
        my $job = $self->minion->job($pending->{id});
        $job->fail('Worker restarted; automatic replay disabled') if $job;
    }
}

sub publish_inventory {
    my ($self, $blocked) = @_;
    my $snapshot = eval { $self->disk->inventory };
    $snapshot //= {updated_at => time, disks => [], errors => ["Disk discovery failed: $@"]};
    $snapshot->{blocked} = $blocked;
    $self->store->atomic_json($self->config->state . '/inventory.json', $snapshot);
}

sub run {
    my ($self) = @_;
    my $limit = $self->config->worker_jobs;
    die 'Worker jobs must be an integer from 1 to 64'
        unless defined $limit && $limit =~ /\A[1-9][0-9]*\z/ && $limit <= 64;

    my $blocked_mounts = $self->recover;
    $self->publish_inventory($blocked_mounts);
    die 'Residual mounts require manual cleanup: ' . join(', ', @$blocked_mounts) . "\n"
        if @$blocked_mounts;

    my $stop_requested;
    local $SIG{TERM} = local $SIG{INT} = local $SIG{HUP} = sub { $stop_requested = 1 };
    $self->minion->add_task(
        scan => sub {
            my ($job, @arguments) = @_;
            die 'Invalid job arguments' unless @arguments == 1;
            $self->scanner->run($arguments[0]);
        }
    );

    # Discovery has its own process, so even slow enumeration cannot occupy
    # a scan slot or delay queue dispatch and child supervision.
    my $discovery = $self->_start_discovery;
    my $worker    = $self->minion->worker;
    $worker->status({jobs => 0 + $limit, queues => ['default']});
    my %active;
    my $succeeded = eval {
        $worker->register;
        while (!$stop_requested) {
            if (waitpid($discovery, WNOHANG) == $discovery) {
                undef $discovery;
                die "Disk discovery process exited unexpectedly\n";
            }
            for my $slot (keys %active) {
                my $entry = $active{$slot};
                next unless $entry->{job}->is_finished;
                delete $active{$slot};
                $stop_requested = 1 if $self->_reconcile_job($entry);
            }
            last if $stop_requested;
            my %owned   = map  { ($self->config->mounts . '/' . $_->{id}) => 1 } values %active;
            my @unowned = grep { !$owned{$_->{target}} } @{$self->_managed_mounts};
            die "Unexpected mount requires manual cleanup\n" if @unowned;

            $self->sync_queue;
            $worker->register;
            for my $slot (1 .. $limit) {
                last if $stop_requested;
                next if $active{$slot};
                my $job = $worker->dequeue(0, {queues => ['default'], tasks => ['scan']});
                last unless $job;
                $self->minion->backend->sqlite->db->query(
                    'UPDATE minion_jobs SET attempts = 1 WHERE id = ?', $job->id);
                my $request = eval {
                    die 'Invalid job arguments' unless @{$job->args} == 1;
                    $self->scanner->validate_request($job->args->[0]);
                };
                unless ($request) {
                    $job->fail($@);
                    next;
                }
                if (grep { $_->{id} eq $request->{id} } values %active) {
                    $job->fail('Scan ID is already being processed');
                    next;
                }

                # Each slot owns a persistent Grype cache. Concurrent updates
                # never replace a database another scanner is using.
                $job->on(start => sub { $self->scanner->cache_slot($slot) });
                $active{$slot} = {job => $job, id => $request->{id}};
                $job->start;
            }
            sleep 0.2;
        }
        1;
    };
    my $error = $@;

    # Stop admission first, then interrupt children and wait for Scan's
    # bounded unmount handling. No remaining job is automatically replayed.
    kill 'TERM', $discovery if $discovery;
    $_->{job}->kill('TERM') for grep { $_->{job}->pid } values %active;
    while (%active) {
        for my $slot (keys %active) {
            my $entry = $active{$slot};
            next if $entry->{job}->pid && !$entry->{job}->is_finished;
            delete $active{$slot};
            $entry->{job}->fail('Could not start scan process') unless $entry->{job}->pid;
            $self->_reconcile_job($entry);
        }
        sleep 0.05 if %active;
    }
    waitpid($discovery, 0) if $discovery;
    $worker->unregister    if $worker->id;
    $self->publish_inventory([map { $_->{target} } @{$self->_managed_mounts}]);
    die $error unless $succeeded;
}

sub _start_discovery {
    my ($self) = @_;
    my $pid = fork;
    die "Discovery fork: $!" unless defined $pid;
    return $pid if $pid;

    my $stopping;
    local $SIG{TERM} = local $SIG{INT} = local $SIG{HUP} = sub {
        $stopping = 1;
        die "Discovery stopped\n";
    };
    eval {
        while (!$stopping) {
            $self->publish_inventory([]);
            sleep $self->config->inventory_interval;
        }
    };
    POSIX::_exit($stopping ? 0 : 1);
}

sub _managed_mounts {
    my ($self) = @_;
    my $root = $self->config->mounts;
    return [grep { $_->{target} eq $root || index($_->{target}, "$root/") == 0 }
            @{$self->disk->mount_table}];
}

sub _reconcile_job {
    my ($self, $entry) = @_;
    my $scan = $self->store->get($entry->{id});
    return 0 unless $scan;
    if ($scan->{status} eq 'queued') {

        # A fork failure or an exception before Scan records its start must
        # not leave permanent history displaying a job that will never run.
        $scan->{status}      = 'failed';
        $scan->{phase}       = 'finished';
        $scan->{error}       = 'Scan process exited before recording its start';
        $scan->{finished_at} = Outcrop::Store::now();
        $self->store->save($scan);
    }

    # Only this child's mounts are residual. Other children may still be
    # cataloging normally under their own scan directories.
    my $root      = $self->config->mounts . '/' . $entry->{id};
    my @remaining = grep { $_->{target} eq $root || index($_->{target}, "$root/") == 0 }
        @{$self->_managed_mounts};
    if ($scan->{status} eq 'running' || @remaining) {
        $self->_recover_scan($scan, \@remaining);
    }
    return
           $scan->{status} eq 'interrupted'
        || @remaining
        || $scan->{cleanup_status} eq 'needs_cleanup';
}

1;
