package Outcrop::Config;
use Mojo::Base -base;

has state              => '/var/lib/outcrop';
has runtime            => '/run/outcrop';
has syft               => '/usr/local/bin/syft';
has grype              => '/usr/local/bin/grype';
has command_timeout    => 3600;
has worker_jobs        => sub { $ENV{OUTCROP_WORKER_JOBS} // 2 };
has inventory_interval => 10;

sub queue {
    my ($self) = @_;
    return $self->state . '/queue/minion.sqlite';
}

sub annotations {
    my ($self) = @_;
    return $self->state . '/annotations/tags.sqlite';
}

sub mounts {
    my ($self) = @_;
    return $self->runtime . '/mounts';
}

1;
