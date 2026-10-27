use strict;
use warnings;
use Test::More;
use Mojo::File qw(path);
use lib 'lib';
use Outcrop::Disk;

# CI supplies a disposable loop device. This test only reads its metadata;
# regular test runs do not need root or access to the host's block devices.
my $device = $ENV{OUTCROP_TEST_BLOCK_DEVICE};
plan skip_all => 'Set OUTCROP_TEST_BLOCK_DEVICE to a disposable loop device' unless $device;
die 'Expected a loop device' unless $device =~ m{\A/dev/loop\d+\z} && -b $device;

my $disk   = Outcrop::Disk->new;
my $number = $disk->device_number($device);
my ($nodes, $parents) = $disk->_read_block_devices;
ok($nodes->{$number}, 'System lsblk discovers the loop device with the requested columns');
$disk->_read_sysfs($nodes, $parents, {});
my $sequence = path('/sys/dev/block', $number, 'diskseq')->slurp;
chomp $sequence;
open my $handle, '<', $device or die "Open loop device: $!";
is($disk->_disk_sequence($handle), $sequence, 'Native ioctl agrees with the sysfs disk sequence');
ok(
    eval {
        $disk->verify_sequence(
            {handles => [$handle, $handle], identity => {disk => {diskseq => $sequence}}});
        1;
    },
    'Held device descriptors pass sequence verification'
);

done_testing;
