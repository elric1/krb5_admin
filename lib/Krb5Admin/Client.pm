# 
#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Client;

use Kharon::Protocol::ArrayHash;
use Kharon::Engine::Client;
use Kharon::Engine::Client::Knc;
use Kharon::utils qw/mk_methods mk_array_methods mk_scalar_methods/;

use Krb5Admin::C;

use strict;
use warnings;

our $KINIT    = '/usr/bin/kinit';

sub new {
	my ($isa, $princ, $opts, @servers) = @_;
	my $self;

	my $port;
	$port = $opts->{port} if exists($opts->{port});
	$port = 'krb5_admin' if !defined($port);

	my $ctx = Krb5Admin::C::krb5_init_context();
	if (scalar(@servers) < 1) {
		my $kdcs = Krb5Admin::C::krb5_get_kdcs($ctx, '');
		@servers = @$kdcs;
	}

	if (scalar(@servers) < 1) {
		die "Cannot connect: could not find any KDCs.";
	}

	my $ahr = Kharon::Protocol::ArrayHash->new(banner => {version=>'2.0'});

	my $pec;
	if (exists($opts->{stdin_protocol})) {
		$pec = Kharon::Engine::Client->new(protocols => [$ahr]);
	} else {
		$pec = Kharon::Engine::Client::Knc->new(protocols => [$ahr]);
	}

	if (defined($princ) && system($KINIT, "-l", "10m", "-k", $princ)) {
		die "can't use host principal?";
	}

	$pec->SetServerDefaults({KncService=>'krb5_admin', PeerPort=>$port});
	if (!$pec->Connect(@servers)) {
		die [500, qq{Can't connect to any servers}];
	}
	$self->{pec} = $pec;

	bless($self, $isa);
}

eval mk_array_methods(undef, qw{
	fetch
	fetch_tickets
	list
	listpols
	mquery
	query_ticket
	query_host
	query_hostmap
});

eval mk_scalar_methods(undef, qw{
	change
	change_passwd
	create
	create_host
	create_user
	disable
	enable
	insert_hostmap
	insert_ticket
	master
	query
	remove
	remove_hostmap
	remove_ticket
});

1;
