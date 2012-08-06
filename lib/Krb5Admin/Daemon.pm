#!/usr/pkg/bin/perl

package Krb5Admin::Daemon;

use IO::File;

use Socket;
use Sys::Syslog;

use Kharon::Protocol::ArrayHash;
use Kharon::Engine::Server v0.3;
use Kharon::Entitlement::ACLFile;
use Kharon::Entitlement::Equals;
use Kharon::Entitlement::Object;
use Kharon::Entitlement::Stack;
use Kharon::Entitlement::SimpleSQL;

use Krb5Admin::KerberosDB;
use Krb5Admin::Log;

use strict;
use warnings;

sub mk_kmdb {
	my ($pes, $config, %args) = @_;
	my @acls = ();
	my $kmdb_class = 'Krb5Admin::KerberosDB';

	my $acl     = Kharon::Entitlement::Stack->new();

	my $objacl  = Kharon::Entitlement::Object->new();
	push(@acls, $objacl);

	my $sqlacl  = Kharon::Entitlement::SimpleSQL->new(
	    table => 'krb5_admin_simple_acls');
	$sqlacl->set_del_check(sub { $acl->check($_[0]); });
	push(@acls, $sqlacl);

	#
	# When the ACL file is not present, don't bother with file ACL checks

	if (defined($config->{acl_file}) && -f $config->{acl_file}) {
		my $subacls = Kharon::Entitlement::Equals->new();
		my $aclfile = Kharon::Entitlement::ACLFile->new(
					filename => $config->{acl_file},
					subobject => $subacls);
		push(@acls, $aclfile);
	}

	$acl->set_subobjects(@acls);
	$acl->set_creds($args{CREDS});
	$pes->set_acl($acl);

	my %kmdb_args = (
		acl			=> $acl,
		sacls			=> $sqlacl,
		client			=> $args{CREDS},
		addr			=> $args{REMOTE_IP},
		allow_fetch		=> $config->{allow_fetch},
		xrealm_bootstrap	=> $config->{xrealm_bootstrap},
		win_xrealm_bootstrap	=> $config->{win_xrealm_bootstrap},
		prestash_xrealm		=> $config->{prestash_xrealm},
		sqlite			=> $config->{sqlite},
		dbname			=> $config->{dbname},
	);

	if (defined($args{CREDS}) && defined($args{REMOTE_IP})) {
		$config->{logger}->log('info', '%s connected from %s',
		    $args{CREDS}, $args{REMOTE_IP});
	}

	$kmdb_class = $config->{kmdb_class} if defined($config->{kmdb_class});
	my $ret = $kmdb_class->new(%kmdb_args);

	$objacl->set_subobject($ret);
	$sqlacl->set_dbh($ret->get_dbh());

	return $ret;
}

sub run {
	my ($config, %inargs) = @_;

	my $creds	= $inargs{CREDS};
	   $creds	= $ENV{KNC_CREDS}	if !defined($creds);
	my $remote_ip	= $inargs{REMOTE_IP};
	   $remote_ip	= $ENV{KNC_REMOTE_IP}	if !defined($remote_ip);

	my $logger = $config->{logger};
	$logger = Krb5Admin::Log->new()		if !defined($logger);

	my $ahr = Kharon::Protocol::ArrayHash->new(banner => {version=>'2.0'});
	my $pes = Kharon::Engine::Server->new(protocols => [$ahr],
	    logger => $logger);
	$pes->Connect();

	my %args;
	$args{master} = $config->{master}	if defined($config->{master});

	if (defined($config->{preforked}) && $config->{preforked}) {
		$args{object}	= sub { mk_kmdb($pes, $config, @_) };
		$pes->RunKncAcceptor(%args);
	} else {
		$args{object}	= mk_kmdb($pes, $config, CREDS => $creds,
		    REMOTE_IP => $remote_ip);
		$pes->RunObj(%args);
	}
}

1;
