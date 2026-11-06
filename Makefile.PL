use strict;
use warnings;
use ExtUtils::MakeMaker;
use File::Find qw(find);

# Install assets beside the modules so relocatable/local::lib installs work
# without a writable source checkout or a separate asset installer.
my %files;
find(
    sub {
        return unless -f $_;
        my $source = $File::Find::name;
        (my $target = $source) =~ s{^lib/}{};
        $files{$source} = "\$(INST_LIB)/$target";
    },
    'lib'
);
for my $directory (qw(templates public systemd)) {
    find(
        sub {
            return unless -f $_;
            my $source = $File::Find::name;
            $files{$source} = "\$(INST_LIB)/App/Outcrop/share/$source";
        },
        $directory
    );
}
$files{'script/outcrop-web'} = '$(INST_LIB)/App/Outcrop/share/outcrop-web';

WriteMakefile(
    NAME               => 'App::Outcrop',
    VERSION_FROM       => 'lib/App/Outcrop.pm',
    ABSTRACT           => 'Read-only Linux disk SBOM and vulnerability inspection with a web UI',
    AUTHOR             => 'snake <admin@viasnake.com>',
    LICENSE            => 'apache_2_0',
    MIN_PERL_VERSION   => '5.034000',
    CONFIGURE_REQUIRES => {'ExtUtils::MakeMaker' => '6.64'},
    PREREQ_PM          => {
        'Mojolicious'             => '9.42',
        'Minion'                  => '11.0',
        'Minion::Backend::SQLite' => 'v5.0.7',
        'Mojo::SQLite'            => '3.009',
        'DBI'                     => '1.647',
        'DBD::SQLite'             => '1.78',
        'Cpanel::JSON::XS'        => '4.20',
        'JSON::SL'                => '1.0.7',
    },
    TEST_REQUIRES => {'Test::More' => '1.302183', 'Test::Mojo' => 0},
    EXE_FILES     => ['script/outcrop'],
    PM            => \%files,
    META_MERGE    => {
        'meta-spec' => {version => 2},
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/viasnake/outcrop.git',
                web  => 'https://github.com/viasnake/outcrop'
            },
            bugtracker => {web => 'https://github.com/viasnake/outcrop/issues'},
        },
        prereqs => {develop => {requires => {'Perl::Tidy' => '20260826'}}},
    },
);
