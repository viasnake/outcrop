use strict;
use warnings;
use utf8;
use Test::More;
use Test::Mojo;
use File::Temp qw(tempdir);
use Mojo::File qw(path);
use Mojo::JSON qw(from_json);
use lib 'lib';
use App::Outcrop;
use App::Outcrop::I18N;

my @languages = (
    [undef,                   'en'],
    ['fr-FR,de;q=0.9',        'en'],
    ['ja-JP,en-US;q=0.8',     'ja'],
    ['en-GB;q=0.5,ja;q=0.9',  'ja'],
    ['en,ja',                 'en'],
    ['ja;q=0,en;q=0.5',       'en'],
    ['JA-jp',                 'ja'],
    ['ja;q=invalid,en;q=0.5', 'en'],
    ['../../ja',              'en'],
);

for my $case (@languages) {
    is(App::Outcrop::I18N::negotiate($case->[0]),
        $case->[1], 'Negotiate ' . ($case->[0] // 'missing header'));
}

# A missing key or placeholder would otherwise surface only during an action.
my $english  = App::Outcrop::I18N::messages('en');
my $japanese = App::Outcrop::I18N::messages('ja');
is_deeply([sort keys %$english], [sort keys %$japanese], 'Both catalogs cover the same messages');
my @mismatched;
for my $key (sort keys %$english) {
    my @en = sort $english->{$key}  =~ /(\{[a-z_]+\})/g;
    my @ja = sort $japanese->{$key} =~ /(\{[a-z_]+\})/g;
    push @mismatched, $key if join(',', @ja) ne join(',', @en);
}
is_deeply(\@mismatched, [], 'Both catalogs preserve all interpolation values');
my @sources = (
    path('lib/App/Outcrop.pm'), path('public/outcrop.js'),
    path('public/results.js'),  path('templates')->list_tree->each
);
my @missing;
my $client_messages = App::Outcrop::I18N::client_messages('en');
for my $source (@sources) {
    my $text = $source->slurp;
    while ($text =~ /(?:\bl|OutcropI18n\.t)\('([a-z_]+)'/g) {
        my $key = $1;
        push @missing, "$source: $key" unless exists $english->{$key};
        push @missing, "$source client: $key"
            if "$source" =~ /\.js\z/ && !exists $client_messages->{$key};
    }
}
is_deeply(\@missing, [], 'All UI messages exist in the appropriate catalogs');

my $root   = tempdir(CLEANUP => 1);
my $config = App::Outcrop::Config->new(state => $root, runtime => "$root/run");
my $store  = App::Outcrop::Store->new(config => $config, writable => 1);
$store->initialize;
path($root, 'web.secret')->spurt('test-secret-' x 8);
my $diagnostic = 'Unsupported or unknown partition: /dev/example1 <unsafe>';
$store->atomic_json(
    "$root/inventory.json",
    {
        updated_at => time,
        errors     => [],
        disks      => [{name => '/dev/example', targets => [], reasons => [$diagnostic]}]
    }
);
my $id   = 'a' x 32;
my $scan = {
    id             => $id,
    tags           => ['日本語 <script>'],
    note           => 'Original 日本語 note',
    created_at     => '2026-11-07T12:34:56Z',
    status         => 'failed',
    phase          => 'sbom',
    failed_phase   => 'sbom',
    cleanup_status => 'needs_cleanup',
    error          => 'Original diagnostic <script>',
};
$store->save($scan);
$store->atomic_json($store->directory($id)->child('sbom.syft.json'), {artifacts => []});
my $app =
    App::Outcrop->new(settings => $config, store => App::Outcrop::Store->new(config => $config));
$app->log->level('error');
my $t = Test::Mojo->new($app);
$t->get_ok('/')
    ->status_is(200)
    ->header_is('Content-Language', 'en')
    ->element_exists('html[lang="en"]')
    ->text_is('h1', 'Scan');
$t->get_ok('/' => {'Accept-Language' => 'ja-JP,en;q=0.8'})
    ->status_is(200)
    ->header_is('Content-Language', 'ja')
    ->text_is('h1', 'スキャン');
$t->get_ok('/?lang=../../ja' => {'Accept-Language' => 'fr'})
    ->status_is(200)
    ->header_is('Content-Language', 'en');
$t->get_ok('/inventory' => {Cookie => 'outcrop_language=../../ja', 'Accept-Language' => 'ja'})
    ->status_is(200)
    ->header_is('Content-Language', 'ja');

for my $locale (qw(en ja)) {
    my $messages = App::Outcrop::I18N::messages($locale);
    $t->get_ok("/?lang=$locale")
        ->status_is(200)
        ->header_is('Content-Language', $locale)
        ->element_exists("html[lang=\"$locale\"]")
        ->element_exists_not('input[name="clone"]')
        ->element_exists("select[name=\"lang\"] option[value=\"$locale\"][selected]")
        ->text_is('h1', $messages->{scan})
        ->content_like(qr/\Q$messages->{unsupported_partition}\E: \/dev\/example1 &lt;unsafe&gt;/);
    like(
        $t->tx->res->headers->set_cookie,
        qr/outcrop_language=$locale;.*path=\//i,
        'Preference persists for the whole application'
    );
    my $client = from_json($t->tx->res->dom->at('script[src="/i18n.js"]')->attr('data-messages'));
    is(
        $client->{save_failed},
        $messages->{save_failed},
        'JavaScript receives the same locale as the page'
    );
    my $csrf     = $t->tx->res->dom->at('input[name="csrf_token"]')->attr('value');
    my $opposite = $locale eq 'en' ? 'ja' : 'en';
    $t->get_ok('/history?tag=example&page=2' => {'Accept-Language' => $opposite})
        ->status_is(200)
        ->header_is('Content-Language', $locale)
        ->text_is('h1', $messages->{history});
    my $switch = $t->tx->res->dom->at('[data-language-form]');
    is($switch->attr('action'), '/history', 'Language form stays on the current page');
    is($switch->at('input[name="tag"]')->attr('value'),
        'example', 'Switch preserves history filter');
    is($switch->at('input[name="page"]')->attr('value'), '2', 'Switch preserves history page');
    $t->get_ok('/inventory')->status_is(200)->header_is('Content-Language', $locale);
    $t->post_ok("/scans/$id/note" => form => {csrf_token => $csrf, note => 'x' x 2001})
        ->status_is(400)
        ->content_is($messages->{note_limit});
    $t->post_ok('/scans')->status_is(403)->content_is($messages->{invalid_csrf});
    $t->get_ok("/scans/$id/results/syft")
        ->status_is(409)
        ->json_is('/error', $messages->{create_list_first});
    $t->get_ok("/scans/$id")
        ->status_is(200)
        ->content_like(qr/\Q$messages->{do_not_disconnect}\E/)
        ->content_like(qr/Original diagnostic &lt;script&gt;/)
        ->content_unlike(qr/<script>/);
    my $date = $locale eq 'ja' ? '2026/11/07 12:34:56' : '11/07/2026, 12:34:56';
    like($t->tx->res->text, qr/\Q$date\E/,
        'Display date follows the selected locale and keeps UTC');
    $t->get_ok("/scans/$id/download/metadata")
        ->status_is(200)
        ->json_is('/created_at', $scan->{created_at})
        ->json_is('/note',       $scan->{note});
    $t->get_ok('/missing-page')->status_is(404)->text_is('h1', $messages->{not_found});
}
is_deeply($store->get($id), $scan, 'Language changes leave the stored scan and annotations intact');

done_testing;
