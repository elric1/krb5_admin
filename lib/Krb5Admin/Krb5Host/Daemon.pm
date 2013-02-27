#

package Krb5Admin::Krb5Host::Daemon;

@EXPORT_OK = qw/run/;

use Kharon::Protocol::ArrayHash;
use Kharon::Engine::Server v0.3;
use Kharon::Entitlement::ACLFile;
use Kharon::Entitlement::Equals;
use Kharon::Entitlement::Object;
use Kharon::Entitlement::Stack;
use Kharon::Entitlement::SimpleSQL;

use Krb5Admin::Krb5Host::Local;
use Krb5Admin::Krb5Host::Log;

use strict;
use warnings;

sub mk_krb5host {
	my ($pes, $config, %args) = @_;
	my @acls = ();
	my $krb5host_class = 'Krb5Admin::Krb5Host::Local';

	my $acl     = Kharon::Entitlement::Stack->new();

	my $objacl  = Kharon::Entitlement::Object->new();
	push(@acls, $objacl);

	$acl->set_subobjects(@acls);
	$acl->set_creds($args{CREDS});
	$pes->set_acl($acl);

	my %krb5host_args = (
		verbose		 => $config->{verbose},
		user2service	 => $config->{user2service},
		allowed_enctypes => $config->{allowed_enctypes},
		admin_users	 => $config->{admin_users},
		krb5_libs	 => $config->{krb5_libs},
		krb5_lib_quirks	 => $config->{krb5_lib_quirks},
		default_krb5_lib => $config->{default_krb5_lib},
		user_libs	 => $config->{user_libs},
		use_fetch	 => $config->{use_fetch},

		ktdir		 => $config->{ktdir},
		lockdir		 => $config->{lockdir},

		#
		# XXXrcd: these settings all need to be be diddled a
		#         bit, some of them will require a small bit
		#         of thought, eh?

		invoking_user	 => 'root',	# XXXrcd!
		testing		 => 0,
		local		 => 0,
	);

	if (defined($args{CREDS}) && defined($args{REMOTE_IP})) {
		$config->{logger}->log('info', $args{CREDS} .
		    ' connected from ' .  $args{REMOTE_IP});
	}

	if (defined($config->{krb5host_class})) {
		$krb5host_class = $config->{krb5host_class};
	}
	my $ret = $krb5host_class->new(%krb5host_args);

	$objacl->set_subobject($ret);

	return $ret;
}

sub run {
	my ($config, %inargs) = @_;

	my $creds	= $inargs{CREDS};
	   $creds	= $ENV{KNC_CREDS}	if !defined($creds);
	my $remote_ip	= $inargs{REMOTE_IP};
	   $remote_ip	= $ENV{KNC_REMOTE_IP}	if !defined($remote_ip);

	$config->{logger} //= Krb5Admin::Krb5Host::Log->new();

	my $ahr = Kharon::Protocol::ArrayHash->new(banner => {version=>'2.0'});
	my $pes = Kharon::Engine::Server->new(protocols => [$ahr]);
	$pes->Connect();

	my %args;
	$args{master} = $config->{master}	if defined($config->{master});

	if (defined($config->{preforked}) && $config->{preforked}) {
		$args{object} = sub { mk_krb5host($pes, $config, @_) };
		$pes->RunKncAcceptor(%args);
	} else {
		$args{object} = mk_krb5host($pes, $config, CREDS => $creds,
		    REMOTE_IP => $remote_ip);
		$pes->RunObj(%args);
	}
}

1;
