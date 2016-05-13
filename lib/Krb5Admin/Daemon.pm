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
use Kharon::InputValidation::Object;

use Krb5Admin::KerberosDB;
use Krb5Admin::Log;
use Krb5Admin::Utils qw/mk_kmdb_with_config/;

use strict;
use warnings;

sub mk_kmdb {
	my ($pes, $config, %args) = @_;
	my @acls = ();

	my $acl     = Kharon::Entitlement::Stack->new();

	my $sqlacl  = Kharon::Entitlement::SimpleSQL->new(
	    table => 'krb5_admin_simple_acls');
	$sqlacl->set_del_check(sub {
		my $ret;

		eval { $ret = $acl->check($_[0]); };
		return 1 if defined($ret) && $ret eq '1';
		eval { $ret = $acl->check('sacls_add'); };
		return 1 if defined($ret) && $ret eq '1';
		eval { $ret = $acl->check('sacls_del'); };
		return 1 if defined($ret) && $ret eq '1';
	});
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

	my $objacl  = Kharon::Entitlement::Object->new();
	push(@acls, $objacl);

	$acl->set_subobjects(@acls);
	$pes->set_acl($acl);

	$args{acl}   = $acl;
	$args{sacls} = $sqlacl;
	my $kmdb = mk_kmdb_with_config($config, \%args);

	$objacl->set_subobject($kmdb);
	$sqlacl->set_dbh($kmdb->get_dbh());

	my $iv = Kharon::InputValidation::Object->new(subobject => $kmdb);
	$pes->set_iv($iv);

	return (kmdb => $kmdb, acl => $acl);
}

sub connect_kmdb {
	my (%args) = @_;

	$args{acl}->set_creds($args{CREDS})	if defined($args{CREDS});
	$args{kmdb}->set_addr($args{REMOTE_IP})	if defined($args{REMOTE_IP});

	if (defined($args{CREDS}) && defined($args{REMOTE_IP})) {
		$args{logger}->log('info', $args{CREDS} .
		    ' connected from ' .  $args{REMOTE_IP});
	}

	return $args{kmdb};
}

sub run {
	my ($config, %inargs) = @_;

	$config->{logger} //= Krb5Admin::Log->new();

	my $ahr = Kharon::Protocol::ArrayHash->new(banner => {version=>'2.0'});
	my $pes = Kharon::Engine::Server->new(protocols => [$ahr],
	    logger => $config->{logger});
	$pes->Connect();

	my %args;
	$args{master} = $config->{master}	if defined($config->{master});

	my %kal = mk_kmdb($pes, $config);
	$kal{logger} = $config->{logger};

	if (defined($config->{preforked}) && $config->{preforked}) {
		$args{object} = sub { connect_kmdb(%kal, @_) };
		$pes->RunKncAcceptor(%args);
		return;
	}

	$kal{CREDS}	= $inargs{CREDS}	// $ENV{KNC_CREDS};
	$kal{REMOTE_IP}	= $inargs{REMOTE_IP}	// $ENV{KNC_REMOTE_IP};

	$args{object} = connect_kmdb(%kal);
	$pes->RunObj(%args);
}

1;
