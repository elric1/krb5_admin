#
#
# This is where the ugly code goes.  If I hide it---maybe no one will
# actually SEE it!

package Krb5Admin::Utils;
use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw/reverse_the host_list force_symlink
		load_krb5hostd_config mk_krb5host_with_config
		load_config mk_kmdb_with_config
		unparse_princ/;

BEGIN {
	eval { require Krb5Admin::SiteKerberosDB; };
}

#
# Host list will, given an IP/Hostname return a list of all of the valid
# host principals which we would expect that host to contain in their
# entirety.  We strive to make the code less ugly than in.dstd:

sub host_list {
	my ($hostname) = @_;

	return ($hostname);
}

sub reverse_the {
	my ($addr) = @_;

#	my $iaddr = inet_aton($addr);
#	$name  = gethostbyaddr($iaddr, AF_INET);
#
#	$name;
	return undef;	# unimplemented.
}

sub force_symlink {
	my ($to, $from) = @_;

	my $l = readlink($from);
	if (!defined($l) || $l ne $to) {
		symlink($to, "$from.$$");
		rename("$from.$$", $from) or
		    die "$0: Can't create $from as a link to $to: $!\n";
	}
}

sub mk_kmdb_with_config {
	my ($config, $args) = @_;

	my %kmdb_args = (
		acl			=> $args->{acl},
		sacls			=> $args->{sacls},
		client			=> $args->{CREDS},
		addr			=> $args->{REMOTE_IP},
		local			=> $args->{local},
		lockdir			=> $config->{lockdir},
		testing			=> $config->{testing},
		allow_fetch		=> $config->{allow_fetch},
		allow_fetch_old		=> $config->{allow_fetch_old},
		deleg_to		=> $config->{deleg_to},
		enable_host_subdomain	=> $config->{enable_host_subdomain},
		xrealm_bootstrap	=> $config->{xrealm_bootstrap},
		win_xrealm_bootstrap	=> $config->{win_xrealm_bootstrap},
		prestash_xrealm		=> $config->{prestash_xrealm},
		sqlite			=> $config->{sqlite},
		dbname			=> $config->{dbname},
	);

	my $kmdb_class   = $config->{kmdb_class};

	if (!defined($kmdb_class)) {
		eval {
			if (defined(Krb5Admin::SiteKerberosDB->can('new'))) {
				$kmdb_class = 'Krb5Admin::SiteKerberosDB';
			}
		};
	}

	$kmdb_class //= 'Krb5Admin::KerberosDB';

	return $kmdb_class->new(%kmdb_args);
}

sub mk_krb5host_with_config {
	my ($config, $args) = @_;

	my %krb5host_args = (
		verbose		 => $config->{verbose},
		user2service	 => $config->{user2service},
		allowed_enctypes => $config->{allowed_enctypes},
		admin_users	 => $config->{admin_users},
		keytab_retries	 => $config->{keytab_retries},
		krb5_libs	 => $config->{krb5_libs},
		krb5_lib_quirks	 => $config->{krb5_lib_quirks},
		default_krb5_lib => $config->{default_krb5_lib},
		user_libs	 => $config->{user_libs},
		use_fetch	 => $config->{use_fetch},
		ext_sync_func	 => $config->{ext_sync_func},

		ktdir		 => $config->{ktdir},
		lockdir		 => $config->{lockdir},
		tixdir		 => $config->{tixdir},

		kmdb_config	 => $config->{kmdb_config},
		kmdb_config_provided => $config->{kmdb_config_provided},

		testing		 => $config->{testing},
		local		 => $config->{local},

		#
		# XXXrcd: these settings all need to be be diddled a
		#         bit, some of them will require a small bit
		#         of thought, eh?

		invoking_user	 => 'root',	# XXXrcd!
	);

	my $krb5host_class = 'Krb5Admin::Krb5Host::Local';
	if (defined($config->{krb5host_class})) {
		$krb5host_class = $config->{krb5host_class};
	}
	return $krb5host_class->new(%krb5host_args);
}

sub _load_config {
	my ($config) = @_;
	my $file = $config->{config};
	my $provided = $config->{config_provided};
	my $no_file = !defined($file) || ! -f $file;

	return $config				if $no_file && !$provided;
	die "Couldn't find config: $file\n"	if $no_file;

	my $ret = do $file;
	die "Couldn't parse $file: $@\n"	if $@;
	die "Couldn't open $file: $!\n"		if !defined($ret);
}

sub load_config {
	my ($config) = @_;

	_load_config($config);

	$config->{acl_file}		  = $acl_file;
	$config->{dbname}		//= $dbname;
	$config->{testing}		  = $testing;
	$config->{sqlite}		//= $sqlite;
	$config->{lockdir}		  = $lockdir;
	$config->{allow_fetch}		  = $allow_fetch;
	$config->{allow_fetch_old}	  = $allow_fetch_old;
	$config->{deleg_to}		  = $deleg_to;
	$config->{subdomain_prefix}	  = $subdomain_prefix;
	$config->{maxconns}		  = $maxconns;
	$config->{kmdb_class}		  = $kmdb_class;
	$config->{xrealm_bootstrap}	  = \%xrealm_bootstrap;
	$config->{win_xrealm_bootstrap}	  = \%win_xrealm_bootstrap;
	$config->{prestash_xrealm}	  = \%prestash_xrealm;
	$config->{timeout}		//= $timeout;

	return $config;
}

sub load_krb5hostd_config {
	my ($config) = @_;

	_load_config($config);

	$config->{verbose}		//=  $verbose;
	$config->{user2service}		  = \%user2service;
	$config->{allowed_enctypes}	  = \@allowed_enctypes;
	$config->{admin_users}		  = \@admin_users;
	$config->{keytab_retries}	  =  $keytab_retries;
	$config->{krb5_libs}		  = \%krb5_libs;
	$config->{krb5_lib_quirks}	  = \%krb5_lib_quirks;
	$config->{default_krb5_lib}	  =  $default_krb5_lib;
	$config->{user_libs}		  = \%user_libs;
	$config->{use_fetch}		  =  $use_fetch;
	$config->{ktdir}		  =  $ktdir;
	$config->{lockdir}		  =  $lockdir;
	$config->{ext_sync_func}	  =  $ext_sync_func;
	$config->{tixdir}		  =  $tixdir;
	$config->{testing}		  =  $testing;
	$config->{kmdb_config}		  =  $kmdb_config;

	if (defined($kmdb_config)) {
		$config->{kmdb_config_provided} = 1;
	}
}

# XXXrcd: maybe we should perform a little validation later.
# XXXrcd: also lame because it is code duplication.
sub unparse_princ {
	my ($realm, @comps) = @{$_[0]};

	return join('/', @comps) . '@' . $realm;
}

1;
