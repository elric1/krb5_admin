# 
#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Krb5Host::Client;

use base qw(Krb5Admin::Krb5Host Kharon::Class::Client);

use Kharon::Protocol::ArrayHash;
use Kharon::Engine::Client;
use Kharon::Engine::Client::Knc;

use Krb5Admin::C;

use strict;
use warnings;

sub new {
	my ($proto, $host, %opts) = @_;
	my $class = ref($proto) || $proto;

	my $self;
	my $ctx  = $self->{ctx};

	my $port;
	$port = $opts{port} if exists($opts{port});
	$port = 'krb5_admin' if !defined($port);

	my $ahr = Kharon::Protocol::ArrayHash->new(banner => {version=>'2.0'});
	my $pec = Kharon::Engine::Client::Knc->new(protocols => [$ahr]);

	$pec->SetServerDefaults({KncService=>'host', PeerPort=>$port});
	if (!$pec->Connect($host)) {
		die [500, qq{Can't connect to $host}];
	}
	$self->{pec} = $pec;

	bless($self, $class);
}

1;

__END__

=head1 NAME

Krb5Admin::Krb5Host::Client - remotely manipulate a Kerberos host

=head1 SYNOPSIS

	use Krb5Admin::Krb5Host::Client;

	my $kmdb = Krb5Admin::Krb5Host::Client->new();

=head1 DESCRIPTION

=head1 CONSTRUCTOR

=over 4

=item new(HOST, OPTS)

Creates a new "Krb5Admin::Krb5Host::Client" object connected to
HOST.  OPTS is a hash which can contain:

=over 4

=item port

the port on the host to which to connect.  This may be specified as either
an integer or as a string which is looked up in the services map.

=back

=back

=head1 METHODS

All of the user-visible methods are inherited from Krb5Admin::Krb5Host
and are documented there as well.

=head1 SEE ALSO

L<Krb5Admin::Krb5Host>
