package App::Outcrop::Paths;
use strict;
use warnings;
use Cwd        qw(abs_path);
use Mojo::File qw(path);

# Resolve from the loaded module, never from the working directory or PATH.
my $modules   = path(abs_path(__FILE__))->dirname;
my $checkout  = $modules->dirname->dirname->dirname;
my $installed = -d $modules->child('share');

sub root   { return $installed ? $modules                 : $checkout }
sub assets { return $installed ? $modules->child('share') : $checkout }

sub web_script {
    return $installed ? assets()->child('outcrop-web') : $checkout->child('script/outcrop-web');
}

1;
