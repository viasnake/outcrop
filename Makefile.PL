use strict;
use warnings;
use ExtUtils::MakeMaker;
use File::Find;

# Install the application's templates and static assets alongside the modules.
my %files;
find(
    {
        no_chdir => 1,
        wanted => sub {
            my $source = $File::Find::name;
            return unless -f $source;
            $source =~ s{\A\./}{};

            if ($source =~ m{\Alib/(.+\.pm)\z}) {
                $files{$source} = '$(INST_LIB)/' . $1;
            }
            elsif ($source =~ m{\A(?:public|templates)/}) {
                $files{$source} = '$(INST_LIB)/App/Outcrop/share/' . $source;
            }
        },
    },
    qw(lib public templates)
);

WriteMakefile(
    NAME => 'App::Outcrop',
    VERSION_FROM => 'lib/App/Outcrop.pm',
    ABSTRACT => 'SBOM and vulnerability scanning for cloned disks',
    AUTHOR => 'Takuya Oshima',
    LICENSE => 'apache_2_0',
    MIN_PERL_VERSION => '5.034000',
    EXE_FILES => ['script/outcrop', 'script/outcrop-web'],
    PM => \%files,
    PREREQ_PM => {
        'Mojolicious' => '9.42',
        'Minion' => '11.0',
        'Minion::Backend::SQLite' => 'v5.0.7',
        'Mojo::SQLite' => '3.009',
        'DBI' => '1.647',
        'DBD::SQLite' => '1.78',
        'Cpanel::JSON::XS' => '4.20',
        'JSON::SL' => '1.0.7',
    },
    TEST_REQUIRES => {
        'Test::More' => '1.302183',
    },
    META_MERGE => {
        'meta-spec' => {
            version => 2,
            url => 'https://metacpan.org/pod/CPAN::Meta::Spec',
        },
        dynamic_config => 0,
        no_index => {
            namespace => ['Outcrop'],
            package => ['Outcrop'],
        },
        resources => {
            homepage => 'https://github.com/viasnake/outcrop',
            bugtracker => { web => 'https://github.com/viasnake/outcrop/issues' },
            repository => {
                type => 'git',
                url => 'https://github.com/viasnake/outcrop.git',
                web => 'https://github.com/viasnake/outcrop',
            },
        },
    },
);
