package Outcrop::ResultStream;
use strict;
use warnings;
use parent 'JSON::SL::Tuba';

# Retain the envelope and one result at a time. Tool metadata outside the
# descriptor is validated by the parser but never materialized in Perl.
sub read {
    my ($class, $file, $kind, $consume, $digest) = @_;
    my %arrays = (syft => 'artifacts', grype => 'matches', cdx => 'components');
    die 'Unknown result kind' unless $arrays{$kind};
    my $parser = $class->new(utf8 => 1, cb_unified => 1);
    $parser->{array}   = $arrays{$kind};
    $parser->{consume} = $consume;
    $parser->{stack}   = [];
    open my $handle, '<:raw', $file or die "Open result: $!";

    while (1) {
        my $size = CORE::read($handle, my $chunk, 65536);
        die "Read result: $!" unless defined $size;
        last                  unless $size;
        $digest->add($chunk) if $digest;
        $parser->parse($chunk);
    }
    close $handle or die "Close result: $!";
    die 'Incomplete JSON result' unless $parser->{finished} && !@{$parser->{stack}};
    return $parser->{envelope};
}

sub on_any {
    my ($self, $info, $data) = @_;
    my ($type, $mode) = ("$info->{Type}", "$info->{Mode}");
    if ($type eq 'D') {
        if ($mode eq '+') {
            die 'Multiple JSON documents' if $self->{started}++;
        }
        else {
            $self->{finished} = 1;
        }
        return;
    }
    my $stack = $self->{stack};
    if ($mode eq '-') {
        my $frame = pop @$stack;
        $self->{consume}->($frame->{value}) if $frame->{item} && $self->{consume};
        return;
    }
    my $depth = @$stack;
    my $key   = $info->{Key};
    my $item  = $depth == 2 && ($stack->[1]{key} // '') eq $self->{array};
    my $collect =
           !$depth
        || ($depth == 1 && ($key // '') eq 'descriptor')
        || ($depth > 1  && $stack->[-1]{collect})
        || ($item       && $self->{consume});
    my $container = $type eq '{' || $type eq '[';
    my $value = $container ? ($type eq '{' ? {} : []) : ($type eq '?' ? ($data ? 1 : 0) : $data);
    if (!$depth) {
        die 'Invalid JSON result envelope' unless $type eq '{';
        $self->{envelope} = $value;
    }
    elsif (!$item && ($depth == 1 || $stack->[-1]{collect})) {
        my $parent = $stack->[-1]{value};
        if (ref $parent eq 'HASH') { $parent->{$key} = $value; }
        else                       { push @$parent, $value; }
    }
    if ($container) {
        push @$stack, {key => $key, collect => $collect, item => $item, value => $value};
    }
    elsif ($item && $self->{consume}) {
        $self->{consume}->($value);
    }
}

1;
