requires 'perl', '5.034000';

# Runtime dependencies are locked, including transitive modules, by Carton.
requires 'Mojolicious',             '9.42';
requires 'Minion',                  '11.0';
requires 'Minion::Backend::SQLite', 'v5.0.7';
requires 'Mojo::SQLite',            '3.009';
requires 'DBI',                     '1.647';
requires 'DBD::SQLite',             '1.78';

# Native JSON decoding for metadata; streaming validation for tool artifacts.
requires 'Cpanel::JSON::XS', '4.20';
requires 'JSON::SL',         '1.0.7';

on 'test' => sub {
    requires 'Test::More', '1.302183';

    # Test::Mojo ships with Mojolicious and has no independent version.
    requires 'Test::Mojo';
};

on 'develop' => sub {
    requires 'Perl::Tidy', '20260826';
};
