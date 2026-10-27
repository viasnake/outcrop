package Outcrop::Scan;
use Mojo::Base -base;
use Mojo::File qw(path);
use Mojo::JSON qw(decode_json);
use Digest::SHA;
use Outcrop::Command;
use Outcrop::Store;
use Outcrop::Tags;

has [qw(config store disk)];
has command => sub { Outcrop::Command->new };

sub validate_request {
    my ($self, $request) = @_;

    die 'Invalid scan request' unless ref $request eq 'HASH';
    die 'Invalid scan request' unless $self->store->valid_id($request->{id});
    die 'Invalid scan request' unless ($request->{token} // '') =~ /\A[0-9a-f]{64}\z/;

    my $tags = Outcrop::Tags->validate($request->{tags} // []);

    my $note = $request->{note};
    die 'Invalid scan request' if ref $note;
    die 'Invalid scan request' if length($note // '') > 2000 || ($note // '') =~ /\x00/;

    # Copy only the accepted fields. Queue entries never supply paths, command
    # arguments, mount options, or previously verified device identity.
    return {(map { $_ => $request->{$_} // '' } qw(id token note)), tags => $tags};
}

sub queued {
    my ($self, $request) = @_;
    $request = $self->validate_request($request);
    return {
        %$request,
        created_at     => Outcrop::Store::now(),
        status         => 'queued',
        phase          => 'queued',
        cleanup_status => 'not_needed',
        warnings       => []
    };
}

sub phase {
    my ($self, $scan, $phase) = @_;
    $scan->{phase} = $phase;
    $self->store->save($scan);
    $self->store->log($scan->{id}, "Phase: $phase");
}

# Resolve guest symlinks inside the guest root, including absolute /usr links.
# Host readlink/abs_path alone would follow an absolute link into the scanner OS.
sub guest_path {
    my ($self, $root, $relative) = @_;

    my @pending = split m{/+}, $relative;
    my @components;
    my $symlink_count = 0;
    while (@pending) {
        my $component = shift @pending;
        next if $component eq '' || $component eq '.';
        if ($component eq '..') {
            pop @components;
            next;
        }

        my $candidate = path($root, @components, $component);
        unless (-l $candidate) {
            push @components, $component;
            next;
        }

        $symlink_count++;
        die 'Too many guest symlinks' if $symlink_count > 40;
        my $link = readlink $candidate;
        die 'Unreadable guest symlink' unless defined $link;

        # Absolute links restart at the guest root; relative links retain the
        # resolved guest directory. Neither case can escape through host /usr.
        @components = () if $link =~ m{\A/};
        unshift @pending, split m{/+}, $link;
    }
    return path($root, @components);
}

sub inspect_root {
    my ($self, $root) = @_;

    for my $directory (qw(etc usr var)) {
        die "Not a supported Linux root: missing /$directory"
            unless -d $self->guest_path($root, $directory);
    }
    my $release = $self->guest_path($root, 'etc/os-release');
    die 'Cannot identify Linux root (missing os-release)' unless -f $release && -s $release < 65536;
    die 'Cannot identify Linux distribution'              unless $release->slurp =~ /^ID=.+/m;

    # fstab is evidence about scan scope, never a source of mount commands.
    # Refuse application/data mounts that this single-root scan cannot include.
    my $fstab = $self->guest_path($root, 'etc/fstab');
    die 'Missing /etc/fstab: cannot determine scan scope' unless -f $fstab && -s $fstab < 1048576;
    for my $line (split /\n/, $fstab->slurp) {
        $line             =~ s/#.*//;
        next unless $line =~ /\S/;
        $line             =~ s/^\s+//;
        my @fields = split /\s+/, $line;
        die 'Unrecognizable fstab entry' unless @fields >= 4;

        my ($mountpoint, $filesystem) = @fields[1, 2];
        $mountpoint =~ s/\\([0-7]{3})/chr(oct($1))/ge;
        next if $mountpoint eq '/' || $mountpoint eq '/boot' || $mountpoint eq '/boot/efi';
        next if $filesystem eq 'swap';
        next if $filesystem =~ /\A(?:
            proc | sysfs | devtmpfs | devpts | tmpfs | cgroup2? | debugfs |
            securityfs | pstore | mqueue | hugetlbfs
        )\z/x;
        die "Unsupported separate filesystem: $mountpoint ($filesystem); fstab is never mounted";
    }
    return [
        'Only the selected root filesystem was inspected; separate /boot and EFI areas are excluded.',
        'Detected files do not establish running software, completeness, or freedom from vulnerabilities.',
    ];
}

sub valid_artifact {
    my ($self, $file, $kind) = @_;

    my $data = $self->store->read_json($file);
    die "Invalid $kind JSON" unless ref $data eq 'HASH';

    # Validate the envelope before publishing or using an output as another
    # tool's input. A syntactically valid JSON document alone is insufficient.
    if ($kind eq 'syft') {
        die 'Invalid Syft SBOM' unless ref($data->{artifacts}) eq 'ARRAY';
        die 'Invalid Syft SBOM' unless ref($data->{descriptor}) eq 'HASH';
        die 'Invalid Syft SBOM' unless ($data->{descriptor}{name} // '') eq 'syft';
        die 'Invalid Syft SBOM' unless ref($data->{source}) eq 'HASH';
    }
    elsif ($kind eq 'cdx') {
        die 'Invalid CycloneDX SBOM' unless ($data->{bomFormat} // '') eq 'CycloneDX';
        die 'Invalid CycloneDX SBOM' unless $data->{specVersion};
        die 'Invalid CycloneDX SBOM'
            if exists $data->{components} && ref($data->{components}) ne 'ARRAY';
    }
    elsif ($kind eq 'grype') {
        die 'Invalid Grype result' unless ref($data->{matches}) eq 'ARRAY';
        die 'Invalid Grype result' unless ref($data->{descriptor}) eq 'HASH';
        die 'Invalid Grype result' unless ($data->{descriptor}{name} // '') eq 'grype';
    }
    return $data;
}

sub publish {
    my ($self, $temporary, $final, $kind) = @_;
    my $data = $self->valid_artifact($temporary, $kind);
    chmod 0640, $temporary or die "chmod artifact: $!";
    rename $temporary, $final or die "publish artifact: $!";
    return $data;
}

sub cleanup {
    my ($self, $scan, $target, $mountpoint) = @_;

    return 1 if $scan->{cleanup_status} eq 'not_needed';
    return 1 if $scan->{cleanup_status} eq 'unmounted';

    # Even a full database/log filesystem must not prevent an unmount attempt.
    my $phase_saved = eval {
        $self->phase($scan, 'unmounting');
        1;
    };
    push @{$scan->{warnings}}, "Could not persist cleanup phase: $@" unless $phase_saved;

    my $unmounted = eval {
        $self->disk->unmount($target, $mountpoint);
        1;
    };
    if ($unmounted) {
        $scan->{cleanup_status} = 'unmounted';
        rmdir $mountpoint if -d $mountpoint;
    }
    else {
        $scan->{cleanup_status} = 'needs_cleanup';
        push @{$scan->{warnings}}, "Unmount failed: $@";
    }
    $self->store->save($scan);
    return $unmounted;
}

sub run {
    my ($self, $request) = @_;

    $request = $self->validate_request($request);
    my $scan       = $self->_start_scan($request);
    my $mountpoint = path($self->config->mounts, $scan->{id});
    my $scan_root  = $mountpoint;
    my ($target, $error, $failed_phase, $interrupted);
    my $host_scan;

    local $SIG{TERM} = local $SIG{INT} = local $SIG{HUP} = sub {
        $interrupted = 1;
        die "Scan interrupted by stop request\n";
    };

    # Keep the success path in execution order. Every exception, including a
    # stop request or command timeout, rejoins the same cleanup path below.
    my $succeeded = eval {
        $self->phase($scan, 'validating');
        $target         = $self->disk->resolve($request->{token});
        $host_scan      = ($target->{kind} // '') eq 'host';
        $scan->{target} = $target->{identity};
        $self->store->save($scan);

        if ($host_scan) {

            # The running root is read in place. Never change its block-device
            # flags, remount it, or pass it through guest cleanup handling.
            $scan_root = path('/');
            $scan->{exclusions} = $self->disk->host_exclusions;
            push @{$scan->{warnings}},
                'Live filesystem: files may change during scanning; this is not a snapshot.';
        }
        else {
            $target = $self->disk->make_readonly($target);
            $self->_mount_and_inspect_root($scan, $target, $mountpoint);
        }
        my ($tool_config, $command_options) = $self->_prepare_tools($scan);
        $self->_generate_sboms($scan, $target, $scan_root, $tool_config, $command_options);

        # Grype reads only the saved SBOM. Release the disk before database
        # downloads and matching, and never continue after an unmount failure.
        die 'Unmount failed; vulnerability matching was not started'
            unless $host_scan || $self->cleanup($scan, $target, $mountpoint);
        $self->_match_vulnerabilities($scan, $tool_config, $command_options);
        $scan->{status} = 'completed';
        1;
    };
    unless ($succeeded) {
        $error        = $@ || 'Scan failed';
        $failed_phase = $scan->{phase};
    }

    # Repeated stop requests must not interrupt the bounded unmount attempt.
    local $SIG{TERM} = local $SIG{INT} = local $SIG{HUP} = 'IGNORE';
    $self->_cleanup_after_scan($scan, $target, $mountpoint)            if $target && !$host_scan;
    $self->_record_failure($scan, $error, $failed_phase, $interrupted) if $error;

    if ($scan->{status} eq 'completed' && !$host_scan && $scan->{cleanup_status} ne 'unmounted') {
        $scan->{status} = 'partial';
    }
    $self->_append_log_warnings($scan);
    $scan->{finished_at} = Outcrop::Store::now();
    $scan->{phase}       = 'finished';
    $self->store->save($scan);
    return $scan;
}

sub _start_scan {
    my ($self, $request) = @_;

    my $scan = $self->store->get($request->{id}) // $self->queued($request);
    die 'Scan has already been processed' unless $scan->{status} eq 'queued';

    # The validated submission supplies user fields; persisted queued state
    # cannot substitute its own target, paths, or identity at execution time.
    for my $field (qw(tags note token)) {
        $scan->{$field} = $request->{$field};
    }
    $scan->{status}     = 'running';
    $scan->{started_at} = Outcrop::Store::now();
    return $self->store->save($scan);
}

sub _mount_and_inspect_root {
    my ($self, $scan, $target, $mountpoint) = @_;

    $mountpoint->make_path({mode => 0700});
    for my $mount (@{$self->disk->mount_table}) {
        die 'Mountpoint already in use' if $mount->{target} eq "$mountpoint";
    }

    # Persist cleanup intent before mount: a command can create a mount and
    # still fail or be interrupted before returning to this process.
    $self->phase($scan, 'mounting');
    $scan->{cleanup_status} = 'mounted';
    $self->store->save($scan);
    $self->disk->mount($target, $mountpoint);

    $self->phase($scan, 'inspecting');
    push @{$scan->{warnings}}, @{$self->inspect_root($mountpoint)};
}

sub _prepare_tools {
    my ($self, $scan) = @_;

    # Explicit configuration and a private working directory prevent either
    # CLI from discovering configuration inside the scanned filesystem.
    my $directory   = $self->store->directory($scan->{id});
    my $work        = $directory->child('work')->make_path({mode => 0700});
    my $tool_config = $work->child('tools.yaml');
    $tool_config->spurt("{}\n");

    my $options = {
        cwd     => "$work",
        timeout => $self->config->command_timeout,
        log     => '' . $directory->child('scan.log'),
        env     => {
            SYFT_CHECK_FOR_APP_UPDATE          => 'false',
            GRYPE_CHECK_FOR_APP_UPDATE         => 'false',
            GRYPE_DB_CACHE_DIR                 => $self->config->state . '/grype-db',
            GRYPE_DB_VALIDATE_AGE              => 'true',
            GRYPE_DB_VALIDATE_BY_HASH_ON_START => 'true',
        },
    };
    return ($tool_config, $options);
}

sub _record_tool_versions {
    my ($self, $scan, $options) = @_;

    # Version lookup is best effort; the generated documents also identify
    # their producer, and a failed lookup must not discard usable SBOMs.
    for my $tool (qw(syft grype)) {
        my $version = eval {
            my $json = $self->command->run([$self->config->$tool, 'version', '-o', 'json'],
                %$options, timeout => 30,);
            decode_json($json);
        };
        $scan->{"${tool}_version"} = $version->{version} if ref $version eq 'HASH';
    }
}

sub _generate_sboms {
    my ($self, $scan, $target, $scan_root, $tool_config, $options) = @_;

    $self->phase($scan, 'sbom');
    $self->disk->verify_mount($target, $scan_root) unless ($target->{kind} // '') eq 'host';
    $self->_record_tool_versions($scan, $options);

    my $directory   = $self->store->directory($scan->{id});
    my $syft_output = $directory->child('sbom.syft.json.part');
    my $cdx_output  = $directory->child('sbom.cdx.json.part');
    $self->command->run(
        [
            $self->config->syft,
            'scan',
            "dir:$scan_root",
            '--config',
            "$tool_config",
            '-o',
            "syft-json=$syft_output",
            '-o',
            "cyclonedx-json=$cdx_output",
            (map { ('--exclude', $_) } @{$scan->{exclusions} // []}),
            (($target->{kind} // '') eq 'host' ? ('--parallelism', '2') : ()),
        ],
        %$options
    );

    # Publish each valid format independently. If the other output is invalid,
    # the usable SBOM survives and the result is reported as partial.
    my @outputs = (
        [$syft_output, $directory->child('sbom.syft.json'), 'syft'],
        [$cdx_output,  $directory->child('sbom.cdx.json'),  'cdx'],
    );
    my @validation_errors;
    for my $output (@outputs) {
        my $valid = eval {
            $self->publish(@$output);
            1;
        };
        push @validation_errors, $@ unless $valid;
    }
    die join('', @validation_errors) if @validation_errors;

    my $saved_sbom = $directory->child('sbom.syft.json');
    open my $handle, '<:raw', $saved_sbom or die "SBOM hash: $!";
    $scan->{sbom_sha256} = Digest::SHA->new(256)->addfile($handle)->hexdigest;
    close $handle or die "Close SBOM: $!";

    my $syft = $self->store->read_json($saved_sbom);
    $scan->{syft_version} = $syft->{descriptor}{version};
}

sub _match_vulnerabilities {
    my ($self, $scan, $tool_config, $options) = @_;

    $self->phase($scan, 'vulnerabilities');
    my $directory = $self->store->directory($scan->{id});
    my $output    = $directory->child('vulnerabilities.grype.json.part');
    $self->command->run(
        [
            $self->config->grype, 'sbom:' . $directory->child('sbom.syft.json'),
            '--config', "$tool_config", '-o', 'json',
        ],
        %$options,
        stdout => "$output"
    );

    my $grype    = $self->valid_artifact($output, 'grype');
    my $database = $grype->{descriptor}{db};
    $self->_verify_grype_database($database);

    $scan->{grype_version} = $grype->{descriptor}{version};
    $scan->{grype_db}      = $database;
    $self->publish($output, $directory->child('vulnerabilities.grype.json'), 'grype');
}

sub _verify_grype_database {
    my ($self, $database) = @_;

    # Current Grype nests validation under status; older documents place the
    # same metadata at the top level. Preserve the original document unchanged.
    my $status = $database;
    if (ref($database) eq 'HASH' && ref($database->{status}) eq 'HASH') {
        $status = $database->{status};
    }

    my $error = 'Grype database identity or validation unavailable';
    die $error unless ref $status eq 'HASH';
    die $error unless $status->{built} && defined($status->{schemaVersion});
    die $error if $status->{error};
    die $error unless $status->{valid} || ($status->{status} // '') eq 'valid';
}

sub _cleanup_after_scan {
    my ($self, $scan, $target, $mountpoint) = @_;

    my $cleanup_checked = eval {
        $self->cleanup($scan, $target, $mountpoint);
        1;
    };
    return if $cleanup_checked;

    $scan->{cleanup_status} = 'needs_cleanup';
    push @{$scan->{warnings}}, "Cleanup could not be verified: $@";
}

sub _record_failure {
    my ($self, $scan, $error, $failed_phase, $interrupted) = @_;

    $scan->{error}        = "$error";
    $scan->{failed_phase} = $failed_phase;

    # Processing outcome and cleanup safety are independent: retaining a valid
    # SBOM makes a failure partial, but never makes a remaining mount safe.
    if ($interrupted) {
        $scan->{status} = 'interrupted';
    }
    elsif ($self->store->artifact($scan->{id}, 'syft')
        || $self->store->artifact($scan->{id}, 'cdx'))
    {
        $scan->{status} = 'partial';
    }
    else {
        $scan->{status} = 'failed';
    }
    $self->store->log($scan->{id}, $error);
}

sub _append_log_warnings {
    my ($self, $scan) = @_;

    my $file = $self->store->artifact($scan->{id}, 'log');
    return unless $file;

    open my $handle, '<:encoding(UTF-8)', $file or die "Log warnings: $!";
    my @warnings;
    while (my $line = <$handle>) {
        next unless $line =~ m{\b(?:WARN(?:ING)?|ERROR|permission denied|input/output error)\b}i;
        chomp $line;
        push @warnings, substr($line, 0, 1000);
        last if @warnings >= 20;
    }
    push @{$scan->{warnings}}, @warnings;
}

1;
