package App::Outcrop::I18N;
use strict;
use warnings;
use Mojo::JSON qw(decode_json to_json);
use App::Outcrop::Paths;

my %catalogs;

sub supported {
    my ($locale) = @_;
    return defined($locale) && ($locale eq 'ja' || $locale eq 'en');
}

sub negotiate {
    my ($header) = @_;
    my @choices;
    my $order = 0;
    for my $entry (split /,/, substr($header // '', 0, 4096)) {
        next
            unless $entry =~
            /\A\s*([a-z]{1,8}(?:-[a-z0-9]{1,8})*|\*)\s*(?:;\s*q=(0(?:\.\d{0,3})?|1(?:\.0{0,3})?))?\s*\z/i;
        my ($tag, $quality) = (lc($1), defined($2) ? 0 + $2 : 1);
        next unless $quality > 0;
        my ($language) = split /-/, $tag;
        $language = 'en' if $tag eq '*';
        next unless supported($language);
        push @choices, {locale => $language, quality => $quality, order => $order++};
    }
    @choices = sort { $b->{quality} <=> $a->{quality} || $a->{order} <=> $b->{order} } @choices;
    return @choices ? $choices[0]{locale} : 'en';
}

sub messages {
    my ($locale) = @_;
    $locale = 'en' unless supported($locale);
    return $catalogs{$locale} //= decode_json(
        App::Outcrop::Paths::assets()->child('public', 'locales', "$locale.json")->slurp);
}

sub translate {
    my ($locale, $key, %values) = @_;
    my $text = messages($locale)->{$key} // messages('en')->{$key} // $key;
    $text =~ s/\{([a-z_]+)\}/defined($values{$1}) ? $values{$1} : "{$1}"/ge;
    return $text;
}

sub client_messages {
    my ($locale) = @_;
    my $messages = messages($locale);
    my @keys     = qw(
        tag_limit remove_tag inventory_refresh_failed submitting view_progress
        scan_accepted start_scan saving save_failed tag_added tag_removed saved
        result_range result_count result_count_one result_filtered result_filtered_one
        no_results table_load_failed browser_unsupported packages matches
        cache_save_failed list_separator cache_cleared cache_clear_failed loading
        building rebuild_packages rebuild_matches build_failed build_failed_detail
        result_format_invalid
    );
    return {map { $_ => $messages->{$_} } @keys};
}

sub register {
    my ($class, $app) = @_;
    $app->hook(
        before_dispatch => sub {
            my ($controller) = @_;
            my $requested    = $controller->req->url->query->param('lang');
            my $saved        = $controller->cookie('outcrop_language');
            my $locale =
                supported($saved)
                ? $saved
                : negotiate($controller->req->headers->accept_language);
            if ($controller->req->method eq 'GET' && supported($requested)) {
                $locale = $requested;
                $controller->cookie(
                    outcrop_language => $locale,
                    {
                        path     => '/',
                        max_age  => 31536000,
                        samesite => 'Lax',
                        httponly => 1,
                        secure   => $controller->req->is_secure ? 1 : 0,
                    }
                );
            }
            $controller->stash(locale => $locale);
            $controller->res->headers->content_language($locale);
        }
    );
    $app->helper(locale          => sub { return shift->stash('locale') // 'en' });
    $app->helper(l               => sub { my $c = shift; return translate($c->locale, @_) });
    $app->helper(locale_messages => sub { return to_json(client_messages(shift->locale)) });
    $app->helper(
        date_time => sub {
            my ($controller, $value) = @_;
            return $controller->l('unknown') unless defined $value && length $value;

            # Stored timestamps and downloadable metadata remain in UTC.
            return $value
                unless $value =~ /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z\z/;
            return $controller->locale eq 'ja' ? "$1/$2/$3 $4" : "$2/$3/$1, $4";
        }
    );
}

1;
