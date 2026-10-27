use strict;
use warnings;
use Test::More;
use lib 'lib';
use Outcrop::Config;
use Outcrop::Disk;

# Model a scanner root on LVM and a separate ext4 clone using device numbers,
# so parent traversal can be tested without reading the host device inventory.
my $disk  = Outcrop::Disk->new(config => Outcrop::Config->new);
my %nodes = (
    '8:0' => {
        name      => '/dev/sda',
        type      => 'disk',
        'maj:min' => '8:0',
        size      => 1000000,
        serial    => 'scanner',
        diskseq   => 1,
        pttype    => 'gpt'
    },
    '8:1'   => {name => '/dev/sda1', type => 'part', 'maj:min' => '8:1',   fstype => 'LVM2_member'},
    '253:0' => {name => '/dev/dm-0', type => 'lvm',  'maj:min' => '253:0', fstype => 'ext4'},
    '8:16'  => {
        name      => '/dev/sdb',
        type      => 'disk',
        'maj:min' => '8:16',
        size      => 2000000,
        serial    => 'clone-01',
        diskseq   => 2,
        pttype    => 'gpt'
    },
    '8:17' => {
        name      => '/dev/sdb1',
        type      => 'part',
        'maj:min' => '8:17',
        size      => 1900000,
        fstype    => 'ext4',
        uuid      => 'same-fs-uuid',
        partuuid  => 'part-1',
        start     => 2048
    },
);
my %parents = ('8:1' => {'8:0' => 1}, '253:0' => {'8:1' => 1}, '8:17' => {'8:16' => 1});

sub classify {
    my ($busy_devices, $discovery_errors) = @_;
    return $disk->classify(
        \%nodes, \%parents,
        $busy_devices // {'253:0' => 'Scanner root on LVM'},
        $discovery_errors // [], 'boot-1',
    );
}
my $inventory = classify();
my ($host, $clone) = @{$inventory->{disks}};
ok(!$host->{targets}[0]{selectable}, 'LVM scanner root excludes the parent physical disk');
like(
    join(' ', @{$host->{reasons}}),
    qr/Scanner root/,
    'Host exclusion reason survives parent traversal'
);
ok($clone->{targets}[0]{selectable}, 'Independent ext4 clone can be selected');

# Reused names and UUIDs must not conceal reattachment or replacement.
my $token = $clone->{targets}[0]{token};
$nodes{'8:16'}{diskseq} = 3;
isnt(classify()->{disks}[1]{targets}[0]{token},
    $token, 'Reattachment changes token even with same path and UUID');
$nodes{'8:16'}{diskseq} = 2;
$nodes{'8:16'}{serial}  = 'replacement';
isnt(classify()->{disks}[1]{targets}[0]{token}, $token, 'Replacement serial changes identity');
$nodes{'8:16'}{serial} = '';
ok(!classify()->{disks}[1]{targets}[0]{selectable}, 'Unidentifiable disk is rejected');
$nodes{'8:16'}{serial} = 'clone-01';

# Any host use excludes the entire disk; unknown guest layouts fail closed.
for my $reason ('Mounted filesystem', 'Active swap', 'Referenced by device-mapper / RAID') {
    ok(!classify({'8:17' => $reason})->{disks}[1]{targets}[0]{selectable},
        "$reason excludes entire disk");
}
for my $fs ('crypto_LUKS', 'LVM2_member', 'linux_raid_member', 'btrfs', 'zfs_member', 'ntfs', '') {
    local $nodes{'8:17'}{fstype} = $fs;
    ok(!classify()->{disks}[1]{targets}[0]{selectable}, "Unsupported filesystem '$fs' rejected");
}
ok(!classify({}, ['Unresolved host storage'])->{disks}[1]{targets}[0]{selectable},
    'Unknown host topology fails closed');
{
    local $nodes{'8:16'}{fstype} = 'xfs';
    local $nodes{'8:16'}{pttype} = '';
    local $parents{'8:17'}       = {};
    ok(classify()->{disks}[1]{targets}[0]{selectable}, 'Whole-disk XFS is supported');
}
{

    package MissingDisk;
    use Mojo::Base 'Outcrop::Disk';
    sub inventory { return {disks => []} }
}
eval { MissingDisk->new->resolve($token) };
like($@, qr/missing, replaced/, 'Missing or swapped target cannot be resolved at execution time');
is($disk->options('ext4'), 'ro,noload,nodev,nosuid,noexec', 'ext4 disables journal replay');
is(
    $disk->options('xfs'),
    'ro,norecovery,nouuid,nodev,nosuid,noexec',
    'XFS disables recovery and UUID conflicts'
);

# Verify kernel mount state independently of the mount command's exit code.
{

    package ReadonlyCommand;
    use Mojo::Base -base;
    sub run { return "1\n" }

    package VerifiedDisk;
    use Mojo::Base 'Outcrop::Disk';
    has entries => sub { [] };
    sub mount_table     { shift->entries }
    sub verify_sequence { return 1 }
    sub device_path     { return '/dev/example' }
}
my $verified = VerifiedDisk->new(
    command => ReadonlyCommand->new,
    entries => [
        {
            target  => '/example/mount',
            root    => '/',
            number  => '8:17',
            fstype  => 'ext4',
            options => 'ro,norecovery,nodev,nosuid,noexec'
        }
    ]
);
my $target = {
    fstype    => 'ext4',
    'maj:min' => '8:17',
    identity  => {
        disk      => {name => '/dev/example'},
        partition => {name => '/dev/example1'}
    }
};
ok(eval { $verified->verify_mount($target, '/example/mount'); 1 },
    'Actual kernel option aliases are accepted');
$verified->entries->[0]{options} = 'ro,nodev,nosuid,noexec';
eval { $verified->verify_mount($target, '/example/mount') };
like($@, qr/Missing mount safety option/,
    'Read-only mount without journal suppression is rejected');
$verified->entries->[0]{number} = '8:33';
eval { $verified->verify_mount($target, '/example/mount') };
like($@, qr/source verification/, 'A different actual mount source is rejected');
{

    package SequenceCommand;
    use Mojo::Base -base;
    has calls => sub { [] };

    sub run {
        my ($self, $arguments) = @_;
        push @{$self->calls}, $arguments->[1];
        return "999\n";
    }

    package SequenceDisk;
    use Mojo::Base 'Outcrop::Disk';
    sub device_path { return '/dev/fictional' }
}
my $sequence_command = SequenceCommand->new;
my $sequence_disk    = SequenceDisk->new(command => $sequence_command);
eval { $sequence_disk->make_readonly({identity => {disk => {diskseq => 2}}}) };
like($@, qr/sequence changed/, 'Opened device with changed kernel sequence is rejected');
is_deeply($sequence_command->calls, ['--getdiskseq'], 'A changed open device never reaches setro');

# Live-host selection is independent of block-device support and never invokes
# a device command. Its token changes when the mounted root changes.
{

    package HostDisk;
    use Mojo::Base 'Outcrop::Disk';
    has root_number => '253:0';

    sub mount_table {
        my ($self) = @_;
        return [
            {
                target => '/',
                number => $self->root_number,
                source => '/dev/mapper/root',
                fstype => 'ext4'
            },
            {target => '/mnt/other', number => '8:17', source => '/dev/sdb1', fstype => 'ext4'},
        ];
    }
}
my $live_disk = HostDisk->new(config => Outcrop::Config->new);
my $live      = $live_disk->host_target;
is($live_disk->resolve($live->{token})->{kind},
    'host', 'Mounted LVM root can be selected for live reading');
is($live->{identity}{partition}{name}, '/', 'Live target is fixed to the running root');
my $exclusions = $live_disk->host_exclusions;
ok(grep($_ eq './var/lib/outcrop', @$exclusions), 'Live scan excludes its own generated results');
ok(grep($_ eq './mnt/other',       @$exclusions), 'Live scan excludes other mounts');
ok(!grep($_ eq '.' || $_ eq './',  @$exclusions), 'Live scan never excludes its root');
$live_disk->root_number('253:1');
isnt($live_disk->host_target->{token},
    $live->{token}, 'Changing the mounted root invalidates host selection');

# Root-to-disk presentation follows the same topology as clone protection,
# while retaining the live target and its identity when no disk can be mapped.
{

    package InventoryDisk;
    use Mojo::Base 'HostDisk';
    sub _read_block_devices      { return (\%nodes, \%parents) }
    sub _read_sysfs              { return }
    sub _protect_scanner_storage { return }
    sub _exclude_active_swap     { return }
}
my $inventory_disk = InventoryDisk->new(config => Outcrop::Config->new);
my $mapped         = $inventory_disk->inventory;
is_deeply([map { $_->{name} } grep { $_->{system_root} } @{$mapped->{disks}}],
    ['/dev/sda'], 'LVM root is displayed on its physical backing disk');
is(
    $mapped->{host}{token},
    $inventory_disk->host_target->{token},
    'Presentation metadata does not change the live scan token'
);
{
    local $parents{'253:0'} = {'8:1' => 1, '8:17' => 1};
    is_deeply(
        [map { $_->{name} } grep { $_->{system_root} } @{$inventory_disk->inventory->{disks}}],
        ['/dev/sda', '/dev/sdb'],
        'A root spanning multiple disks marks every backing disk'
    );
}
$inventory_disk->root_number('8:16');
is_deeply([map { $_->{name} } grep { $_->{system_root} } @{$inventory_disk->inventory->{disks}}],
    ['/dev/sdb'], 'A whole-disk root is identified without a partition');
$inventory_disk->root_number('0:999');
$mapped = $inventory_disk->inventory;
ok(!grep($_->{system_root}, @{$mapped->{disks}}), 'Unknown root topology never guesses a disk');
ok($mapped->{host}{selectable}, 'Live scanning remains available without a physical disk mapping');
done_testing;
