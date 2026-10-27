use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Mojo::File qw(path);
use Mojo::JSON qw(decode_json);
use lib 'lib';
use Outcrop::Scan;
use Outcrop::Command;

my $scanner  = Outcrop::Scan->new;
my @excluded = qw(var/log var/crash var/lib/systemd/coredump);
my @retained = qw(
    var/lib/dpkg var/lib/rpm usr/lib/sysimage/rpm usr/share/rpm
    opt srv usr/local var/www home/user root var/cache/apt/archives
    var/cache/yum var/cache/dnf tmp var/tmp home/user/.cache
    home/user/.git home/user/.rustup/tmp opt/app/var/log var/log-old
);

sub make_root {
    my $root = path(tempdir(CLEANUP => 1));
    $root->child($_)->make_path for qw(etc usr var);
    $root->child('etc/os-release')->spurt("ID=ubuntu\nVERSION_ID=18.04\n");
    $root->child('etc/fstab')->spurt("UUID=root / ext4 defaults 0 1\n");
    return $root;
}

my $root = make_root();
is_deeply(
    $scanner->exclusions($root),
    [map { "./$_" } @excluded],
    'Only root log and crash directories are excluded'
);
for my $relative (@retained) {
    ok(!grep($relative eq $_ || index($relative, "$_/") == 0, @excluded),
        "Keep package/application evidence at /$relative");
}
for my $mount ('/var/log', '/var/log/audit', '/var/crash', '/var/lib/systemd/coredump') {
    $root->child('etc/fstab')
        ->spurt("UUID=root / xfs defaults 0 0\nUUID=logs $mount xfs defaults 0 0\n");
    ok(eval { $scanner->inspect_root($root); 1 }, "Excluded separate mount $mount is allowed");
}
for my $mount ('/usr', '/var', '/var/lib/rpm', '/var/log/../lib', '/var/log-old', '/opt') {
    $root->child('etc/fstab')
        ->spurt("UUID=root / ext4 defaults 0 1\nUUID=apps $mount ext4 defaults 0 2\n");
    like(
        join(' ', @{$scanner->inspect_root($root)}),
        qr/Uninspected separate filesystem: \Q$mount\E \(ext4\)/,
        "Separate mount $mount is reported without stopping inspection"
    );
}

{
    my $linked = make_root();
    $linked->child('srv')->make_path;
    symlink '../srv', $linked->child('var/log') or die $!;
    ok(!grep($_ eq './var/log', @{$scanner->exclusions($linked)}),
        'Redirected log directory remains searchable');
    $linked->child('etc/fstab')->spurt("UUID=apps /var/log ext4 defaults 0 2\n");
    like(
        join(' ', @{$scanner->inspect_root($linked)}),
        qr/Uninspected separate filesystem: \/var\/log/,
        'Redirected separate application mount is not silently ignored'
    );
}
{
    my $linked = path(tempdir(CLEANUP => 1));
    $linked->child('storage')->make_path;
    symlink 'storage', $linked->child('var') or die $!;
    is_deeply($scanner->exclusions($linked), [], 'Symlink ancestors disable the optimization');
}

my @releases = (
    (
        map { ["Ubuntu $_", 'etc/os-release', "ID=ubuntu\nVERSION_ID=$_\n", 'ubuntu', $_] }
            qw(18.04 20.04 22.04 24.04 26.04)
    ),
    ['CentOS 6.5',       'etc/redhat-release', "CentOS release 6.5 (Final)\n",  'centos', '6.5'],
    ['CentOS 6.10',      'etc/redhat-release', "CentOS release 6.10 (Final)\n", 'centos', '6.10'],
    ['CentOS 7',         'etc/os-release',     "ID=centos\nVERSION_ID=7\n",     'centos', '7'],
    ['CentOS Stream 8',  'etc/os-release',     "ID=centos\nVERSION_ID=8\n",     'centos', '8'],
    ['CentOS Stream 9',  'usr/lib/os-release', "ID=centos\nVERSION_ID=9\n",     'centos', '9'],
    ['CentOS Stream 10', 'usr/lib/os-release', "ID=centos\nVERSION_ID=10\n",    'centos', '10'],
    ['No release files', undef,                undef,                           '',       ''],
);
for my $release (@releases) {
    my ($label, $file, $content) = @$release;
    my $guest = make_root();
    unlink $guest->child('etc/os-release') or die $!;
    if (defined $file) {
        $guest->child($file)->dirname->make_path;
        $guest->child($file)->spurt($content);
    }
    ok(
        eval { $scanner->inspect_root($guest); 1 },
        "$label root is accepted without running guest code"
    );
}
{
    my $guest = make_root();
    $guest->child('etc/os-release')->spurt("PRETTY_NAME=not-enough\n");
    $guest->child('etc/redhat-release')->spurt("not a distribution release\n");
    ok(eval { $scanner->inspect_root($guest); 1 },
        'Unidentifiable release metadata does not reject a root');
    unlink $guest->child('etc/os-release')     or die $!;
    unlink $guest->child('etc/redhat-release') or die $!;
    unlink $guest->child('etc/fstab')          or die $!;
    like(
        join(' ', @{$scanner->inspect_root($guest)}),
        qr/Cannot inspect \/etc\/fstab/,
        'Missing scope metadata is reported without stopping inspection'
    );
}

{
    my $guest = make_root();
    $guest->child('etc/fstab')
        ->spurt("# Scope fixture\nserver:/export /mnt/nfs nfs defaults 0 0\n"
            . "malformed\nfs-example:/ /mnt/efs efs _netdev,tls 0 0\n"
            . "server:/other /mnt/shared\\040files nfs4 defaults 0 0\n"
            . "UUID=data /srv xfs defaults 0 0\n");
    my $warnings = join(' ', @{$scanner->inspect_root($guest)});
    for my $entry ('/mnt/nfs (nfs)', '/mnt/efs (efs)', '/mnt/shared files (nfs4)', '/srv (xfs)') {
        like(
            $warnings,
            qr/Uninspected separate filesystem: \Q$entry\E/,
            "Missing filesystem $entry is reported"
        );
    }
    like(
        $warnings,
        qr/fstab line 3: unrecognizable entry/,
        'Malformed entries are reported while later entries are still inspected'
    );

    $guest->child('etc/fstab')->spurt('x' x 1048576);
    like(
        join(' ', @{$scanner->inspect_root($guest)}),
        qr/Cannot inspect \/etc\/fstab/,
        'Oversized scope metadata produces a warning'
    );
    unlink $guest->child('etc/fstab') or die $!;
    symlink 'fstab', $guest->child('etc/fstab') or die $!;
    like(
        join(' ', @{$scanner->inspect_root($guest)}),
        qr/Cannot inspect \/etc\/fstab/,
        'Unresolvable scope metadata produces a warning'
    );
    rmdir $guest->child('usr') or die $!;
    rmdir $guest->child('var') or die $!;
    symlink 'var', $guest->child('var') or die $!;
    $warnings = join(' ', @{$scanner->inspect_root($guest)});
    like($warnings, qr/Uninspected directory: \/usr/, 'Missing directory produces a warning');
    like($warnings, qr/Uninspected directory: \/var/, 'Unresolvable directory produces a warning');
}

# Optional real cataloger verification. It uses only temporary regular files,
# with no mount, root permission, network download, or installed guest packages.
subtest 'Real Syft excludes logs while retaining software evidence' => sub {
    my $syft = $ENV{OUTCROP_TEST_SYFT};
    plan skip_all => 'Set OUTCROP_TEST_SYFT to an absolute Syft executable' unless $syft;
    die 'OUTCROP_TEST_SYFT must be an absolute executable' unless $syft =~ m{\A/} && -x $syft;
    my $command = Outcrop::Command->new;
    my $work    = path(tempdir(CLEANUP => 1));
    $work->child('tools.yaml')->spurt("{}\n");
    for my $release (@releases) {
        my ($label, $release_path, $content, $os_id, $version) = @$release;
        my $guest = make_root();
        unlink $guest->child('etc/os-release') or die $!;
        if (defined $release_path) {
            $guest->child($release_path)->dirname->make_path;
            $guest->child($release_path)->spurt($content);
        }
        my %expected;
        my $index = 0;
        for my $relative (@retained, @excluded) {
            my $name      = 'outcrop-fixture-' . ++$index;
            my $directory = $guest->child($relative, $name . '-1.0.0.dist-info')->make_path;
            $directory->child('METADATA')
                ->spurt("Metadata-Version: 2.1\nName: $name\nVersion: 1.0.0\n");
            $expected{$name} = 1 unless grep { $_ eq $relative } @excluded;
        }

        # Keep the native Ubuntu package inventory as well as application evidence.
        $guest->child('var/lib/dpkg/status')
            ->spurt(
            "Package: outcrop-native\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\nDescription: Test fixture\n\n"
            );
        $expected{'outcrop-native'} = 1;
        my $output = $work->child('sbom.json');
        $command->run(
            [
                $syft, 'scan', "dir:$guest", '--config', '' . $work->child('tools.yaml'),
                '-o', "syft-json=$output", map { ('--exclude', $_) } @{$scanner->exclusions($guest)}
            ],
            cwd     => "$work",
            timeout => 120,
            env     => {SYFT_CHECK_FOR_APP_UPDATE => 'false'}
        );
        my $sbom  = decode_json($output->slurp);
        my %found = map { $_->{name} => 1 } @{$sbom->{artifacts}};
        is_deeply(
            [sort keys %found],
            [sort keys %expected],
            "$label keeps all intended packages and omits only log/crash packages"
        );
        is($sbom->{distro}{id} // '',
            $os_id, "$label distribution metadata matches available evidence");
        is($sbom->{distro}{versionID} // '',
            $version, "$label version metadata matches available evidence");
    }
};

done_testing;
