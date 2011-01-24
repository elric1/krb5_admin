# 
#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5_Admin::Client;

use Kharon::Protocol::ArrayHash;
use Kharon::Engine::Client;
use Kharon::Engine::Client::Knc;
use Kharon::utils qw/mk_methods mk_array_methods mk_scalar_methods/;

use Krb5_Admin::C;

use strict;
use warnings;

our $KINIT    = '/ms/dist/kerberos/PROJ/mitkrb5/1.4-lib-prod/bin/kinit';

sub new {
	my ($isa, $princ, $opts, @servers) = @_;
	my $self;

	my $port;
	$port = $opts->{port} if exists($opts->{port});
	$port = 'krb5_admin' if !defined($port);

	my $ctx = Krb5_Admin::C::krb5_init_context();
	if (scalar(@servers) < 1) {
		my $kdcs = Krb5_Admin::C::krb5_get_kdcs($ctx, '');
		@servers = @$kdcs;
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

	$pec->SetServerDefaults({KncService=>'keytab', PeerPort=>$port});
	if (!$pec->Connect(@servers)) {
		die [500, qq{Can't connect to any servers}];
	}
	$self->{pec} = $pec;

	bless($self, $isa);
}

eval mk_array_methods(undef, qw{
	create_proid
	fetch
	list
	listpols
	mquery
	nkkps
});

eval mk_scalar_methods(undef, qw{
	change
	change_passwd
	create
	create_user
	disable
	enable
	master
	proid_passwd
	query
	remove
	upgrade_to_strong_human
});

1;
