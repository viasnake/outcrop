use strict;
use warnings;
use Test::More;
use lib 'lib';
use App::Outcrop;

is($App::Outcrop::VERSION, '0.001', 'CPAN release version');
my $root = App::Outcrop::resource_root();
ok(-f "$root/templates/index.html.ep", 'web templates are available');
ok(-f "$root/public/outcrop.js", 'browser assets are available');
done_testing;
