package App::Outcrop;
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Basename qw(dirname);
use File::Spec;

our $VERSION = '0.001';

# Keep assets available regardless of where cpanm installs the executable.
sub resource_root {
    my $module = abs_path(__FILE__) or die "Cannot locate App::Outcrop\n";
    my $directory = dirname($module);
    my $source = abs_path(File::Spec->catdir($directory, '..', '..'));
    return $source if defined $source && -d File::Spec->catdir($source, 'templates');

    my $installed = File::Spec->catdir($directory, 'Outcrop', 'share');
    return $installed if -d File::Spec->catdir($installed, 'templates');

    die "Cannot locate Outcrop templates and static files\n";
}

1;

__END__

=head1 NAME

App::Outcrop - SBOM generation and vulnerability scanning of cloned disks

=head1 DESCRIPTION

Outcrop is a self-hosted application that uses Syft and Grype to scan cloned
disks and inspect the resulting SBOMs and vulnerabilities in a web interface.

The C<outcrop> command runs the web service or the privileged worker.
See the README for prerequisites, deployment and security requirements.

=head1 LICENSE

Apache License 2.0.

=cut
