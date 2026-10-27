requires 'perl', '5.038002';

# Runtime dependencies are locked, including transitive modules, by Carton.
requires 'Mojolicious',             '9.42';
requires 'Minion',                  '11.0';
requires 'Minion::Backend::SQLite', 'v5.0.7';
requires 'Mojo::SQLite',            '3.009';
requires 'DBI',                     '1.647';
requires 'DBD::SQLite',             '1.78';

# Mojo's native decoder keeps large host SBOMs practical to display.
requires 'Cpanel::JSON::XS', '4.20';

on 'test' => sub {
    requires 'Test::More', '1.302190';

    # Test::Mojo ships with Mojolicious and has no independent version.
    requires 'Test::Mojo';
};

on 'develop' => sub {
    requires 'Perl::Tidy', '20260826';
};
