#
#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Client;

use base qw(Krb5Admin Kharon::Class::Client);

use Kharon::Protocol::ArrayHash;
use Kharon::Engine::Client;
use Kharon::Engine::Client::Knc;

use Krb5Admin;
use Krb5Admin::C;

use strict;
use warnings;

sub new {
	my ($proto, $princ, $opts, @servers) = @_;
	my $class = ref($proto) || $proto;

	#
	# XXXrcd: we may need to define a mechanism for passing args
	#         to this...

	my $self = $class->SUPER::new();
	my $ctx  = $self->{ctx};

	my $port;
	$port = $opts->{port} if exists($opts->{port});
	$port = 'krb5_admin' if !defined($port);

	my $realm = '';
	$realm = $opts->{realm} if exists($opts->{realm});

	if (scalar(@servers) < 1) {
		my $kdcs = Krb5Admin::C::krb5_get_kdcs($ctx, $realm);
		@servers = @$kdcs;
	}

	if (scalar(@servers) < 1) {
		die [500, "Cannot connect: could not find any KDCs."];
	}

	my $ahr = Kharon::Protocol::ArrayHash->new(banner => {version=>'2.0'});

	my $pec;
	if (exists($opts->{stdin_protocol})) {
		$pec = Kharon::Engine::Client->new(protocols => [$ahr]);
	} else {
		$pec = Kharon::Engine::Client::Knc->new(protocols => [$ahr]);
	}

	if (defined($princ)) {
		Krb5Admin::C::kinit_kt($ctx, $princ, undef, undef);
	}

	$pec->SetServerDefaults({KncService=>'krb5_admin', PeerPort=>$port});
	if (!$pec->Connect(@servers)) {
		die [500, qq{Can't connect to any servers}];
	}
	$self->{pec} = $pec;

	bless($self, $class);
}

1;

__END__

=head1 NAME

Krb5Admin::Client - remotely manipulate a Kerberos DB

=head1 SYNOPSIS

	use Krb5Admin::Client;

	my $kmdb = Krb5Admin::Client->new();

=head1 DESCRIPTION

=head1 CONSTRUCTOR

=over 4

=item new(PRINCIPAL, OPTS, KDC[, KDC, ...])

Creates a new "Krb5Admin::Client" object.  If PRINCIPAL is defined,
then Krb5Admin::Client will obtain client credentials for PRINCIPAL
from the configured keytab before connecting to the KDC.  If a list
of KDCs are provided they will be contacted in order until one
responds.  If no list is provided, the KDCs will be discovered
using the Kerberos libraries and will generally be defined either
in DNS or in /etc/krb5.conf.  OPTS is a hash reference which can
contain:

=over 4

=item realm

the realm's KDC to contact.  If this is not specified, the host's default
realm is assumed.

=item port

the port on the KDC to which to connect.  This may be specified as either
an integer or as a string which is looked up in the services map.

=item stdin_protocol

this is a debugging option.  If set to true, Krb5Admin::Client will
run its protocol on stdin/stdout allowing a developer to simulate
krb5_admind's behaviour.

=back

=back

=head1 METHODS

All of the user-visible methods are inherited from Krb5Admin and are
documented there as well.

=head1 SEE ALSO

L<Krb5Admin>
