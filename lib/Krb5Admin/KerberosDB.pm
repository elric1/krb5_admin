#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::KerberosDB;

use base qw/Krb5Admin CURVE25519_NWAY::Kerberos/;
use Digest::SHA qw(hmac_sha256_base64);
use MIME::Base64;

use DBI;
use Sys::Hostname;
use Sys::Syslog;
use Data::Dumper;

use Krb5Admin::Utils qw/reverse_the host_list/;
use Krb5Admin::NotifyClient;
use Krb5Admin::C;
use Kharon::Entitlement::ACLFile;
use Kharon::Entitlement::Equals;
use Kharon::Entitlement::SimpleSQL;
use Kharon::InputValidation qw(KHARON_IV_NO_ARGS KHARON_IV_ONE_SCALAR);

use Kharon::dbutils qw/sql_exec generic_query generic_modify/;
use Kharon::utils qw/getclassvar/;

use Krb5Admin::dbutils qw/generic_query_union/;

use strict;
use warnings;

use constant {
	DISALLOW_POSTDATED	=> 0x00000001,
	DISALLOW_FORWARDABLE	=> 0x00000002,
	DISALLOW_TGT_BASED	=> 0x00000004,
	DISALLOW_RENEWABLE	=> 0x00000008,
	DISALLOW_PROXIABLE	=> 0x00000010,
	DISALLOW_DUP_SKEY	=> 0x00000020,
	DISALLOW_ALL_TIX	=> 0x00000040,
	REQUIRES_PRE_AUTH	=> 0x00000080,
	REQUIRES_HW_AUTH	=> 0x00000100,
	REQUIRES_PWCHANGE	=> 0x00000200,
	UNKNOWN_0x00000400	=> 0x00000400,
	UNKNOWN_0x00000800	=> 0x00000800,
	DISALLOW_SVR		=> 0x00001000,
	PWCHANGE_SERVICE	=> 0x00002000,
	SUPPORT_DESMD5		=> 0x00004000,
	NEW_PRINC		=> 0x00008000,
	SQL_DB_FILE		=> '/var/kerberos/krb5_admin.db',
	GROUP_RECURSION		=> 16,
	MAX_TIX_PER_HOST	=> 1024,
};

our %flag_map = (
	allow_postdated			=>	[DISALLOW_POSTDATED,   1],
	allow_forwardable		=>	[DISALLOW_FORWARDABLE, 1],
	allow_tgs_req			=>	[DISALLOW_TGT_BASED,   1],
	allow_renewable			=>	[DISALLOW_RENEWABLE,   1],
	allow_proxiable			=>	[DISALLOW_PROXIABLE,   1],
	allow_dup_skey			=>	[DISALLOW_DUP_SKEY,    1],
	allow_tix			=>	[DISALLOW_ALL_TIX,     1],
	requires_preauth		=>	[REQUIRES_PRE_AUTH,    0],
	requires_hwauth			=>	[REQUIRES_HW_AUTH,     0],
	needchange			=>	[REQUIRES_PWCHANGE,    0],
	allow_svr			=>	[DISALLOW_SVR,         1],
	password_changing_service	=>	[PWCHANGE_SERVICE,     0],
	support_desmd5			=>	[SUPPORT_DESMD5,       0],
);

sub require_scalar {
	my ($usage, $argnum, $arg) = @_;

	die [503, "Syntax error: arg $argnum undefined\nusage: $usage"]
	    if !defined($arg);
	die [503, "Syntax error: arg $argnum not a scalar\nusage: $usage"]
	    if ref($arg) ne '';
}

sub require_scalars {
	my ($usage, $argnum, @args) = @_;

	my $i = $argnum;
	for my $arg (@args) {
		require_scalar($usage, $i++, $arg);
	}

	return undef;
}

sub require_localrealm {
	my ($ctx, $hndl, $realm) = @_;

	eval {
		Krb5Admin::C::krb5_query_princ($ctx, $hndl,
		    unparse_princ([$realm, "krbtgt", $realm]));
	};

	if ($@) {
		die [502, "KDC does not support realm $realm"];
	}
}

sub require_princ {
	my ($ctx, $usage, $argnum, $princ) = @_;

	eval {
		Krb5Admin::C::krb5_parse_name($ctx, $princ);
	};

	if ($@) {
		die [503, "Syntax error: arg $argnum must be a principal: " .
		    "$@\nusage: $usage"];
	}
}

sub canonicalise_fqprinc {
	my ($ctx, $usage, $argnum, $princ) = @_;
	my @p;
	my $ret;

	require_scalar($usage, $argnum, $princ);

	eval {
		@p = Krb5Admin::C::krb5_parse_name($ctx, $princ);
		$ret = unparse_princ(\@p);
	};

	if ($@) {
		die [503, "Syntax error: arg $argnum must be a fully " .
		    "qualified principal: $@\nusage: $usage"];
	}

	return $ret;
}

sub require_fqprinc {
	my ($ctx, $usage, $argnum, $princ) = @_;

	my $tmp = canonicalise_fqprinc(@_);

	if ($tmp ne $princ) {
		die [503, "Syntax error: arg $argnum must be a fully " .
		    "qualified principal: $tmp ne $princ\nusage: $usage"];
	}
}

sub require_hashref {
	my ($usage, $argnum, $arg) = @_;

	die [503, "Syntax error: arg $argnum undefined\nusage: $usage"]
	    if !defined($arg);
	die [503, "Syntax error: arg $argnum not a hashref\nusage: $usage"]
	    if ref($arg) ne 'HASH';
}

# XXXrcd: maybe we should perform a little validation later.
# XXXrcd: also lame because it is code duplication.
sub unparse_princ {
	my ($realm, @comps) = @{$_[0]};

	return join('/', @comps) . '@' . $realm;
}

sub KHARON_SET_CREDS {
	my ($self, @creds) = @_;

	return if @creds == 0;

	if (@creds > 1) {
		die "Krb5Admin::KerberosDB does not support multiple " .
		    "credentials";
	}

	$self->set_creds(@creds);
}

#
# KHARON_COMMON_ACL should return:
#
#	undef		no decision has been made.
#	0		Permission denied, no reason given.
#	1		Access allowed, no further ACLs are checked.
#	a string	Permission denied, the string is the reason.

sub KHARON_COMMON_ACL {
	my ($self, $verb, @predicate) = @_;
	my $subject = $self->{client};

	#
	# As a zeroth step, we prohibit everyone from accessing rules
	# with certain predicates.  This is mainly a safety mechanism to
	# ensure that people do not disable the TGS Key and that sort of
	# thing by mistake.  If we need to do this later administratively
	# then we will like use a different interface or a later version
	# of this interface with a better ACL structure...  We exempt query
	# and list from this rule...

	if ($verb ne 'query' && $verb ne 'list' && defined($predicate[0]) &&
	    $predicate[0] =~ m,^krbtgt/|^kadmin/|^afs(\@.*)?$,) {
		return "Modification of $predicate[0] prohibited.";
	}

	#
	# We also need creds.  This is mainly for my use running this
	# by hand, but be that as it may...

	if (!defined($subject)) {
		return "Permission denied: not an authenticated user";
	}

	#
	# Now, we let the individual functions supply their own ACLs.
	# Perhaps eventually, we'll get rid of most of this function...

	return undef;
}

sub is_account_map {
	my ($self, $local_authz, $username, @princ) = @_;

	return 1 if !defined $local_authz || $local_authz;

	my $princ = unparse_princ(\@princ);
	my $account_map = $self->principal_map_query($username, $princ);

	return undef if !defined $account_map || $account_map == 0;
	return 1;
}

#
# This function supplies the logic which we use to provide self-service
# keytab management.  This is a default and it can be overridden.  The
# function has the same arguments and return values as KHARON_COMMON_ACL.
# This function will always return success or failure, though.  So, it
# should be called last in the various other routines.

sub acl_keytab {
	my ($self, $verb, @predicate) = @_;
	my $subject = $self->{client};
	my $ctx = $self->{ctx};
	my $denied;
	my $kvno;
	my $name;
	my %args;
	my @args;
	my $username;
	my $local_authz;
	my $account_map;

	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $subject);

	my @pprinc;
	if (defined($predicate[0])) {
		@pprinc = Krb5Admin::C::krb5_parse_name($ctx, $predicate[0]);
	}

	if ($verb eq 'create') {
		($name, %args) = @predicate;
	} else {
		($name, $kvno, @args) = @predicate;
		if (@args == 1) {
			# XXXrcd: legacy usage.
			# XXXmsw: copy/pasted
			%args = (keys => $args[0]);
		} else {
			%args = @args;
		}
	}

	$username = $args{invoking_user};
	$local_authz = $args{local_authz};

	#
	# We allow host/foo@REALM to access <service>/foo@REALM for any
	# <service>. If the requested principal is not name/instance,
	# defer to the coarse grained ACLs, for example "create" is also
	# used to create application user principals.

	return if (@pprinc != 3); # Requested principal was invalid

	# These instances are not to be treated as hosts
	return if ($pprinc[2] eq "admin" || $pprinc[2] eq "root");

	# OK if subject is the host principal in the same realm
	# Or a direct sub-domain of that host, if that's enabled.
	my $basedomain = $pprinc[2];
	my $sdp = '';
	$sdp = $self->{subdomain_prefix} if defined $self->{subdomain_prefix};
	$basedomain =~ s/^[a-z0-9](?:[-]?[a-z0-9]+)*\.//i;

	my $valid = 0;
	if (@sprinc == 3 && $sprinc[0] eq $pprinc[0] && $sprinc[1] eq "host") {
		$valid = 1	if $sprinc[2] eq $pprinc[2];
		$valid = 1	if $sdp.$sprinc[2] eq $basedomain;

		if (!$valid && $pprinc[1] ne "host") {
			# OK if the subject is a cluster member of the logical
			# host named by $pprinc[2].

			if ($self->is_cluster_member($pprinc[2], $sprinc[2])) {
				$valid = 1;
			}
		}
	}

	if ($valid == 1) {
		return $self->is_account_map($local_authz, $username, @pprinc);
	}

	#
	# If Krb5Admin::Utils::reverse_the is defined then we
	# will have $self->{hostname} and we'll use it to validate
	# that the request is coming from a properly mapped host.
	# Otherwise, we ignore it.

	if (!defined($self->{hostname})) {
		$self->{hostname} = reverse_the($self->{addr});
	}

	my $host_ok = defined($self->{hostname}) ?
	    grep { $_ eq $pprinc[2] } host_list($self->{hostname}) : 1;

	#
	# We first allow hosts to change their own keys:

	if ($host_ok == 1 && @sprinc == 3 && @pprinc == 3 &&
	    $sprinc[0] eq $pprinc[0] && $sprinc[1] eq $pprinc[1] &&
	    $sprinc[2] eq $pprinc[2]) {
		return 1;
	}

	#
	# We check to see if we are doing an xrealm bootstrap, we
	# do this by generating a list of principals that we will
	# accept first and then seeing if our client is one of them.

	my @xbs = ();
	if (@sprinc == 3 && $sprinc[1] eq 'host' &&
	    ref($self->{xrealm_bootstrap}) eq 'HASH' &&
	    ref($self->{xrealm_bootstrap}->{$sprinc[0]}) eq 'ARRAY') {
		@xbs = @{$self->{xrealm_bootstrap}->{$sprinc[0]}};
		@xbs = map { unparse_princ([$_, @sprinc[1,2]]) } @xbs;
	}

	#
	# Windows principals are case insensitive, so we canonicalize
	# the non-realm part of the principal name to lower-case,
	# and expect the lookup keys in win_xrealm_bootstrap to be
	# likewise lower case.

	my $up_sprinc =
	    unparse_princ([$sprinc[0],
			   map {lc $_} @sprinc[1..$#sprinc]]);
	my $win_xrealm_bootstrap = $self->{win_xrealm_bootstrap};
	if (ref($win_xrealm_bootstrap) eq 'HASH' &&
	    ref($win_xrealm_bootstrap->{$up_sprinc}) eq 'ARRAY') {
		push(@xbs, @{$win_xrealm_bootstrap->{$up_sprinc}});
	}

	my $up_pprinc = unparse_princ(\@pprinc);
	return 1 if $host_ok == 1 && grep {$_ eq $up_pprinc} @xbs;

	return undef;
}

sub new {
	my ($proto, %args) = @_;
	my $class = ref($proto) || $proto;

	#
	# First, we look for obsolete ACL usage and toss an exception
	# if we find it.  We are trying to ensure that if someone upgrades
	# krb5_admind without upgrading the libraries that we will fail to
	# start and hence not provide a security exposure.

	if ((!defined($args{acl}) || !$args{acl}->isa('Kharon::Entitlement')) &&
	    (!defined($args{local}) || $args{local} != 1)) {
		die "Obsolete usage";
	}

	my $self = $class->SUPER::new(%args);

	#
	# set defaults:

	my $sqlite   = SQL_DB_FILE;
	my $dbname;
	my $dbh;

	$dbname   = $args{dbname}	if defined($args{dbname});
	$dbh      = $args{dbh}		if defined($args{dbh});
	$sqlite   = $args{sqlite}	if defined($args{sqlite});

	# initialize our database handle
	if (!defined($dbh)) {
		$dbh = DBI->connect("dbi:SQLite:$sqlite", "", "",
		    {RaiseError => 1, PrintError => 0, AutoCommit => 1});
		die "Could not open database " . DBI::errstr if !defined($dbh);
		$dbh->do("PRAGMA foreign_keys = ON");
		$dbh->do("PRAGMA journal_mode = WAL");
		$self->{my_dbh} = 1;
	}
	$dbh->{PrintError} = 0;
	$dbh->{RaiseError} = 1;

	my $ctx = $self->{ctx};

	$self->{debug}	  = $args{debug};
	$self->{local}	  = $args{local};
	$self->{client}	  = $args{client};
	$self->{addr}	  = $args{addr};
	$self->{hostname} = undef;
	$self->{dbname}	  = $dbname;
	$self->{acl}	  = $args{acl};
	$self->{sacls}	  = $args{sacls};
	$self->{dbh}	  = $dbh;

	$self->{my_dbh} = 0			if !defined($self->{my_dbh});
	$self->{local}	= 0			if !defined($self->{local});
	$self->{client}	= "LOCAL_MODIFICATION"	if          $self->{local};
	$self->{debug}	= 0			if !defined($self->{debug});

	$self->{allow_fetch}		= $args{allow_fetch};
	$self->{allow_fetch_old}	= $args{allow_fetch_old};
	$self->{subdomain_prefix}	= $args{subdomain_prefix};
	$self->{xrealm_bootstrap}	= $args{xrealm_bootstrap};
	$self->{win_xrealm_bootstrap}	= $args{win_xrealm_bootstrap};
	$self->{prestash_xrealm}	= $args{prestash_xrealm};

	if (defined($self->{client})) {
		$self->{hndl} = Krb5Admin::C::krb5_get_kadm5_hndl($ctx,
		    $dbname, $self->{client});
	}

	#
	# If we are not provided with sacls, then we make them in the
	# default way...

	if (!defined($self->{sacls})) {
		$self->{sacls} = Kharon::Entitlement::SimpleSQL->new(
		    table => 'krb5_admin_simple_acls');
		$self->{sacls}->set_dbh($dbh);
	}

	my @rosccmds = getclassvar($self, "KHARON_RO_SC_EXPORT");
	my @roaccmds = getclassvar($self, "KHARON_RO_AC_EXPORT");
	my @rwsccmds = getclassvar($self, "KHARON_RW_SC_EXPORT");
	my @rwaccmds = getclassvar($self, "KHARON_RW_AC_EXPORT");

	my @rocmds = (@rosccmds, @roaccmds);
	my @rwcmds = (@rwsccmds, @rwaccmds);

	$self->{sacls}->set_verbs(@rocmds, @rwcmds);

	if (!defined($self->{allow_fetch})) {
		$self->{allow_fetch} = 0;
		$self->{allow_fetch} = 1	if $self->{local};
	}

	bless($self, $class);
}

sub set_addr {
	my ($self, $addr) = @_;

	$self->{addr} = $addr;
}

sub set_creds {
	my ($self, $creds) = @_;

	$self->{client} = $creds;

	undef($self->{hndl});
	$self->{hndl} = Krb5Admin::C::krb5_get_kadm5_hndl($self->{ctx},
	    $self->{dbname}, $self->{client});
}
 
#
# We use KHARON_{PRE,POST}COMMAND to deal with our database transactions.

sub KHARON_PRECOMMAND {
	my ($self) = @_;
	my $dbh = $self->{dbh};

	$dbh->begin_work();
}

sub KHARON_POSTCOMMAND {
	my ($self, $cmd, $code) = @_;
	my $dbh = $self->{dbh};

	return			if $dbh->{AutoCommit};
	return $dbh->rollback()	if $code >= 500;
	return $dbh->commit();
}

sub DESTROY {
	my ($self) = @_;

	if ($self->{my_dbh} && defined($self->{dbh})) {
		$self->{dbh}->disconnect();
		undef($self->{dbh});
	}
	undef($self->{acl});
	undef($self->{sacls});
	undef($self->{dbh});
}

sub get_dbh {
	my ($self) = @_;

	return $self->{dbh};
}

#
# Define the SQL-based tables:

our %field_desc = (
	principals	=> {
		pkey		=> [qw/principal/],
		uniq		=> [qw/principal/],
		fields		=> [qw/principal type/],
		lists		=> [ [qw/prestashed principal host/] ],
	},
	features	=> {
		pkey		=> [qw/feature/],
		uniq		=> [qw/feature/],
		fields		=> [qw/feature/],
	},
	labels		=> {
		pkey		=> [qw/label/],
		uniq		=> [qw/label/],
		fields		=> [qw/label desc/],
	},
	appids		=> {
		pkey		=> [qw/appid/],
		uniq		=> [qw/appid/],
		fields		=> [qw/appid desc/],
		lists		=> [ [qw/appid_acls appid acl owner/],
				     [qw/appid_cstraints appid cstraint/] ],
		wontgrow	=> 0,
	},
	appid_acls	=> {
		pkey		=> [qw/appid acl/],
		uniq		=> [],
		fields		=> [qw/appid acl/],
		wontgrow	=> 1,
		fkey		=> [[qw/acl acls name/]],
	},
	appid_cstraints => {
		pkey		=> [qw/appid cstraint/],
		uniq		=> [],
		fields		=> [qw/appid cstraint/],
		wontgrow	=> 1,
	},
	acls		=> {
		pkey		=> [qw/name/],
		uniq		=> [qw/name/],
		fields		=> [qw/name type/],
		lists		=> [ [qw/acls_owner name owner owner/],
				     [qw/aclgroups aclgroup acl member/]],
		wontgrow	=> 0,
	},
	aclgroups	=> {
		pkey		=> undef,
		uniq		=> [],
		fields		=> [qw/aclgroup acl/],
		wontgrow	=> 1,
	},
	acls_owner	=> {
		pkey		=> [qw/name/],
		uniq		=> [qw/name/],
		fields		=> [qw/name owner/],
		wontgrow	=> 1,
		fkey		=> [[qw/owner acls name/]],
	},
	hosts_owner	=> {
		pkey		=> [qw/name/],
		uniq		=> [qw/name/],
		fields		=> [qw/name owner/],
		wontgrow	=> 1,
	},
	account_principal_map => {
		pkey		=> [qw/servicename accountname
				       instance realm/],
		uniq		=> [],
		fields		=> [qw/servicename accountname
				       instance realm/],
		wontgrow	=> 1
	},
	hosts		=> {
		pkey		=> 'name',
		uniq		=> [qw/name ip_addr bootbinding/],
		fields		=> [qw/name realm ip_addr bootbinding
				      is_logical/],
		lists		=> [[qw/host_labels host label/],
				    [qw/hosts_owner name owner owner/],
				    [qw/hostmap logical physical member/]],
		wontgrow	=> 0,
	},
	hostmap		=> {
		pkey		=> undef,
		uniq		=> [],
		fields		=> [qw/logical physical/],
		wontgrow	=> 1,
	},

	# Begin Externally populated tables these tables are
	# populated externally.
	#

	external_account_principal_map => {
		pkey		=> [qw/servicename accountname instance realm/],
		uniq		=> [qw/servicename accountname instance realm/],
		fields		=> [qw/servicename accountname instance realm/],
		wontgrow	=> 1
	},
	external_hostmap	=> {
		pkey		=> undef,
		uniq		=> [],
		fields		=> [qw/logical physical/],
		wontgrow	=> 1,
	},
);

sub init_db {
	my ($self) = @_;
	my $dbh = $self->{dbh};
	my $sacls = $self->{sacls};

	Krb5Admin::C::init_kdb($self->{ctx}, $self->{hndl});

	$dbh->do(qq{
		CREATE TABLE db_version (
			version		INTEGER
		)
	});

	$dbh->do(qq{
		INSERT INTO db_version (version) VALUES (1)
	});

	$dbh->do(qq{
		CREATE TABLE features (
			feature		VARCHAR PRIMARY KEY
		)
	});

	$dbh->do(qq{
		CREATE TABLE labels (
			label		VARCHAR PRIMARY KEY,
			desc		VARCHAR NOT NULL
		)
	});

	$dbh->do(qq{
		CREATE TABLE appids (
			appid		VARCHAR PRIMARY KEY,
			desc		VARCHAR
		)
	});

	$dbh->do(qq{
		CREATE TABLE appid_acls (
			appid		VARCHAR NOT NULL,
			acl		VARCHAR NOT NULL,

			PRIMARY KEY (appid, acl)
			FOREIGN KEY (appid) REFERENCES appids(appid)
				ON DELETE CASCADE
			FOREIGN KEY (acl)   REFERENCES acls(name)
		)
	});

	$dbh->do(qq{
		CREATE TABLE appid_cstraints (
			appid		VARCHAR NOT NULL,
			cstraint	VARCHAR NOT NULL,

			PRIMARY KEY (appid, cstraint)
			FOREIGN KEY (appid)	REFERENCES appids(appid)
				ON DELETE CASCADE
			FOREIGN KEY (cstraint)	REFERENCES labels(label)
		)
	});

	$dbh->do(qq{
		CREATE TABLE acls (
			name		VARCHAR NOT NULL,
			type		VARCHAR NOT NULL,

			PRIMARY KEY (name)
		)
	});

	$dbh->do(qq{
		CREATE TABLE acls_owner (
			name		VARCHAR,
			owner		VARCHAR,
			PRIMARY KEY (name, owner)
			FOREIGN KEY (name) REFERENCES acls(name)
				ON DELETE CASCADE
			FOREIGN KEY (owner) REFERENCES acls(name)
		)
	});

	$dbh->do(qq{
		CREATE TABLE aclgroups (
			aclgroup	VARCHAR NOT NULL,
			acl		VARCHAR NOT NULL,

			PRIMARY KEY (aclgroup, acl)
			FOREIGN KEY (aclgroup) REFERENCES acls(name)
				ON DELETE CASCADE
			FOREIGN KEY (acl)      REFERENCES acls(name)
				ON DELETE CASCADE
		)
	});

	#
	# XXXrcd: the hosts structure should likely point to a list of
	#	  addresses or something more like that...

	$dbh->do(qq{
		CREATE TABLE hosts (
			name		VARCHAR NOT NULL PRIMARY KEY,
			realm		VARCHAR NOT NULL,
			ip_addr		VARCHAR,
			bootbinding	VARCHAR,
			is_logical	BOOLEAN
		)
	});

	$dbh->do(qq{
		CREATE TABLE host_secrets (
			name		VARCHAR REFERENCES hosts(name),
			id		INTEGER REFERENCES host_secret_ids(id),
			PRIMARY KEY (name)
		)
	});

	$dbh->do(qq{
		CREATE TABLE host_secret_ids (
			id		INTEGER NOT NULL PRIMARY KEY,
			secret		VARCHAR NOT NULL
		)
	});

	$dbh->do(qq{
		CREATE TABLE host_labels (
			host		VARCHAR NOT NULL,
			label		VARCHAR NOT NULL,

			PRIMARY KEY (host, label)
			FOREIGN KEY (host)	REFERENCES hosts(name)
				ON DELETE CASCADE
			FOREIGN KEY (label)	REFERENCES labels(label)
		)
	});

	$dbh->do(qq{
		CREATE TABLE hostmap (
			logical		VARCHAR NOT NULL,
			physical	VARCHAR NOT NULL,

			PRIMARY KEY (logical, physical)
			FOREIGN KEY (logical)  REFERENCES hosts(name)
			FOREIGN KEY (physical) REFERENCES hosts(name)
		)
	});

	$dbh->do(qq{
		CREATE TABLE hosts_owner (
			name		VARCHAR,
			owner		VARCHAR,
			PRIMARY KEY (name, owner)
			FOREIGN KEY (name) REFERENCES hosts(name)
				ON DELETE CASCADE
			FOREIGN KEY (owner) REFERENCES acls(name)
		)
	});

	$dbh->do(qq{
		CREATE TABLE prestashed (
			principal	VARCHAR NOT NULL,
			host		VARCHAR NOT NULL,

			PRIMARY KEY (principal, host)
			FOREIGN KEY (host) REFERENCES hosts(name)
		)
	});

	$dbh->do(qq{
		CREATE TABLE account_principal_map (
			servicename	VARCHAR,
			accountname	VARCHAR,
			instance	VARCHAR,
			realm		VARCHAR,

			PRIMARY KEY (servicename, accountname, instance)
			FOREIGN KEY (instance)
			REFERENCES hosts(name)
			ON DELETE CASCADE
		)
	});

	# The referential integrity constraints are relaxed on the external
	# tables. We assume the feed from the external thing will keep things
	# roughly correct

	$dbh->do(qq{
		CREATE TABLE external_account_principal_map (
			servicename	VARCHAR,
			accountname	VARCHAR,
			instance	VARCHAR,
			realm		VARCHAR,

			PRIMARY KEY (servicename, accountname, instance)
		)
	});

	$self->upgrade_db();

	$sacls->init_db([[qw/subject acls name/]])	if defined($sacls);

	return undef;
}

sub upgrade_replace_tables {
	my ($self, %new_tables) = @_;
	my $dbh = $self->{dbh};

	for my $t (keys %new_tables) {
		$dbh->do("DROP TABLE IF EXISTS TMPNEW_$t");
		$dbh->do($new_tables{$t});
		$dbh->do("INSERT INTO TMPNEW_$t SELECT * FROM $t");
		$dbh->do("DROP TABLE $t");
		$dbh->do("ALTER TABLE TMPNEW_$t RENAME TO $t");
	}
}

sub upgrade_db_add_more_cascades {
        my ($self) = @_;
        my $dbh = $self->{dbh};

	$self->upgrade_replace_tables(
		appid_acls => qq{
			CREATE TABLE TMPNEW_appid_acls (
				appid		VARCHAR NOT NULL,
				acl		VARCHAR NOT NULL,

				PRIMARY KEY (appid, acl)
				FOREIGN KEY (appid) REFERENCES appids(appid)
					ON DELETE CASCADE
				FOREIGN KEY (acl)   REFERENCES acls(name)
					ON DELETE CASCADE
			)
		},
		acls_owner => qq{
			CREATE TABLE TMPNEW_acls_owner (
				name		VARCHAR,
				owner		VARCHAR,

				PRIMARY KEY (name, owner)
				FOREIGN KEY (name) REFERENCES acls(name)
					ON DELETE CASCADE
				FOREIGN KEY (owner) REFERENCES acls(name)
					ON DELETE CASCADE
			)
		},
		hosts_owner => qq{
			CREATE TABLE TMPNEW_hosts_owner (
				name		VARCHAR,
				owner		VARCHAR,

				PRIMARY KEY (name, owner)
				FOREIGN KEY (name) REFERENCES hosts(name)
					ON DELETE CASCADE
				FOREIGN KEY (owner) REFERENCES acls(name)
					ON DELETE CASCADE
			)
		},
		prestashed => qq{
			CREATE TABLE TMPNEW_prestashed (
				principal	VARCHAR NOT NULL,
				host		VARCHAR NOT NULL,

				PRIMARY KEY (principal, host)
				FOREIGN KEY (host) REFERENCES hosts(name)
					ON DELETE CASCADE
			)
		},
	);

	$dbh->do("UPDATE db_version SET version = 2");

	return 2;
}

my %schema_upgrades = (
	1	=> \&upgrade_db_add_more_cascades,
);

sub upgrade_db {
	my ($self) = @_;
	my $dbh = $self->{dbh};
	my $sth;

	my $version;
	eval {
		my $sth = sql_exec($dbh, "SELECT version FROM db_version");
		$version = $sth->fetchrow();
	};
	die "Can't upgrade because we don't know the current version: $@\n"
	    if $@;

	while ($schema_upgrades{$version}) {
		$version = $schema_upgrades{$version}($self);
	}
}

sub drop_db {
	my ($self) = @_;
	my ($dbh) = $self->{dbh};
	my $sacls = $self->{sacls};

	# XXXrcd: should we unlink(2) the Kerberos DB?  Maybe not.

	$sacls->drop_db()	if defined($sacls);

	$dbh->do('DROP TABLE IF EXISTS db_version');
	$dbh->do('DROP TABLE IF EXISTS features');
	$dbh->do('DROP TABLE IF EXISTS aclgroups');
	$dbh->do('DROP TABLE IF EXISTS appid_cstraints');
	$dbh->do('DROP TABLE IF EXISTS appid_acls');
	$dbh->do('DROP TABLE IF EXISTS acls_owner');
	$dbh->do('DROP TABLE IF EXISTS appids');
	$dbh->do('DROP TABLE IF EXISTS prestashed');
	$dbh->do('DROP TABLE IF EXISTS hosts_owner');
	$dbh->do('DROP TABLE IF EXISTS host_secrets');
	$dbh->do('DROP TABLE IF EXISTS host_secret_ids');
	$dbh->do('DROP TABLE IF EXISTS hostmap');
	$dbh->do('DROP TABLE IF EXISTS host_labels');
	$dbh->do('DROP TABLE IF EXISTS acls');
	$dbh->do('DROP TABLE IF EXISTS hosts');
	$dbh->do('DROP TABLE IF EXISTS labels');
	$dbh->do('DROP TABLE IF EXISTS account_principal_map');
	$dbh->do('DROP TABLE IF EXISTS external_account_principal_map');
}

sub KHARON_ACL_master { return 1; }

sub master { hostname(); }

sub KHARON_ACL_has_feature { return 1; }

sub has_feature {
	my ($self, $feature) = @_;
	my $dbh = $self->{dbh};

	return generic_query($dbh, \%field_desc, 'features', ['feature'],
	    feature => $feature);
}

sub add_feature {
	my ($self, $feature) = @_;
	my $dbh = $self->{dbh};

	require_scalar("add_feature <feature>", 1, $feature);

	my $stmt = 'INSERT INTO features(feature) VALUES (?)';

	sql_exec($dbh, $stmt, $feature);

	return undef;
}

sub del_feature {
	my ($self, $feature) = @_;
	my $dbh = $self->{dbh};

	require_scalar("add_feature <feature>", 1, $feature);

	my $stmt = 'DELETE FROM features WHERE feature = ?';

	sql_exec($dbh, $stmt, $feature);

	return undef;
}

#
# We override the methods in CURVE25519_NWAY::Kerberos to perform the
# writing to the Kerberos database.  These functions are passed $priv
# which is expected to be a list reference documented in:
# CURVE25519_NWAY::Kerberos.
#
# We also provide ACLs for the functions as they are expected to be
# called remotely.

sub KHARON_ACL_curve25519_start		{ KHARON_ACL_curve25519_final(@_); }
sub KHARON_ACL_curve25519_step		{ return 1; }

my @curve25519_ops = qw(change create bootstrap_host_key);

sub KHARON_ACL_curve25519_final {
	my ($self, $cmd, $priv, $hnum, $nonces, $pub) = @_;

	my ($op, $user, $name, $lib, $kvno, %args) = @$priv;
	# XXXrcd: SANITY CHECK!

	if ((grep { $op eq $_ } @curve25519_ops) < 1) {
		return "arg1 must be one of: " . join(', ', @curve25519_ops);
	}

	$args{invoking_user} = $user;

	if ($op eq "create") {
		return $self->{acl}->check($op, $name, %args);
	} else {
		return $self->{acl}->check($op, $name, $kvno, %args);
	}
}

#
# XXXrcd: KDC must check in curve25519_start() whether we are allowed to
#         write this key.  We must consider what happens along the way,
#         though...

sub curve25519_start {
	my ($self, $priv, $hnum, $pub) = @_;
	my ($op, $user, $name, $lib, $kvno, %args) = @$priv;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	my $rets = $self->SUPER::curve25519_start($priv, $hnum, $pub);

	my $kdcret;
	if (!defined($kvno)) {
		my $ret;
		eval {
			$ret = Krb5Admin::C::krb5_query_princ($ctx, $hndl,
			    $name);
		};

		$kdcret->{kvno} = 2;
		$kdcret->{kvno} = $ret->{kvno} + 1	if defined($ret);
	}

	return [@$rets, $kdcret];
}

sub curve25519_final {
	my ($self, $priv, $hnum, $nonces, $pub) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};
	my ($op, $user, $name, $lib, $kvno, %args) = @$priv;

	my $keys = $self->SUPER::curve25519_final($priv, $hnum, $nonces, $pub);

	if ($kvno < 2) {
		die [500, "can't create pricipals with kvno ($kvno) < 2"];
	}
	if ($kvno > 2 || ! eval {
		Krb5Admin::C::krb5_createkey($ctx, $hndl, $name, $keys); 1}) {
		Krb5Admin::C::krb5_setkey($ctx, $hndl, $name, $kvno, $keys);
	}

	if ($op eq 'bootstrap_host_key') {
		$self->remove_bootbinding($name);
	}

	return;
}


# -----------------------------------------------------------------
#		BEGIN DEPRECATED KEY AGREEMENT CODE
# -----------------------------------------------------------------

#
# If generate_ecdh_key1() is provided with $operation and $name then it
# will perform ACL checks based on those.  Otherwise it will simply return
# a key.  The ACLs will be rechecked later by the method that actually
# performs the work---this check is merely a shorthand to catch ACL errors
# earlier in the process and as such it is not necessary to use it...

my @gek_operations = qw(change create create_bootstrap_id bootstrap_host_key);

sub KHARON_ACL_generate_ecdh_key1 {
	my ($self, $verb, $operation, @args) = @_;

	if (defined($operation) || @args > 0) {
		if (!defined($operation) || !defined($args[0])) {
			die [503, "If arg1 or arg2 are defined then both " .
			    "must be defined."];
		}

		if ((grep { $operation eq $_ } @gek_operations) < 1) {
			die [503, "arg1 must be one of: " .
			    join(', ', @gek_operations)];
		}

		return $self->{acl}->check($operation, @args);
	}

	return 1;
}

sub generate_ecdh_key1 {
	my ($self, $operation, $name, @args) = @_;
	my $ctx = $self->{ctx};

	my ($secret, $public) = @{Krb5Admin::C::curve25519_pass1($ctx)};

	$self->{curve25519KerberosDBsecret} = $secret;
	return $public;
}

sub generate_ecdh_key2 {
	my ($self, $hispublic) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	my $mysecret = $self->{curve25519KerberosDBsecret};

	die [503, "Must call genkey first"]	if !defined($mysecret);

	my $ret = Krb5Admin::C::curve25519_pass2($ctx, $mysecret, $hispublic);

	return $ret;
}

# -----------------------------------------------------------------
#		END DEPRECATED KEY AGREEMENT CODE
# -----------------------------------------------------------------

sub KHARON_ACL_create { acl_keytab(@_); }

sub create {
	my ($self, $name, @args) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("create <princ>", 1, $name);

	return $self->internal_create($name, 1, @args);
}

sub internal_create {
	my ($self, $name, $kvno, %args) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	#
	# If we are not provided with a public key, we simply create a
	# principal with a random key.  This can be used when knowledge
	# of the key is not required, e.g. creating a TGS key for a realm
	# which the KDC serves.

	if (!exists($args{public})) {
		Krb5Admin::C::krb5_createkey($ctx, $hndl, $name, []);
		return undef;
	}

	#
	# Now, for the more interesting ECDH negotiation of new keys:

	if (!defined($args{public}) || ref($args{public}) ne '') {
		die [503, "create must be provided with a scalar public key"];
	}

	if (!defined($args{enctypes})) {
		die [503, "must provide enctypes"];
	}

	my $passwd = $self->generate_ecdh_key2($args{public});

	if ($kvno == 1) {
		my @pprinc = Krb5Admin::C::krb5_parse_name($ctx, $name);
		if (@pprinc == 3 && $pprinc[1] eq "host") {
			# Because host keys are highly privileged we want
			# to ensure that they are not forwarded
			Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
				   principal => $name,
				   policy=>'default',
				   attributes=>DISALLOW_FORWARDABLE,
				   }, $args{enctypes}, $passwd);
		} else {
			Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
				   principal => $name,
				   }, $args{enctypes}, $passwd);
		}
	} else {
		Krb5Admin::C::krb5_setpass($ctx, $hndl, $name, $kvno,
		    $args{enctypes}, $passwd);
	}

	return undef;
}

#
# determine if a user can execute the
# $act function with args @r
#
# This is for use in the typical, make DB update, check new state of db for
# policy consistency, rollback on violation
#
sub can_user_act {
	my ($self, $msg, $name, $act, @r) = @_;
	my $dbh = $self->{dbh};

	if (defined($self->{acl})) {
		eval { $self->{acl}->check($act, @r); };
		if ($@) {
			die [503, $msg];
		}
	}
}

#
# XXXrcd: this needs to be fixed...

sub KHARON_IV_create_appid {
	my ($self, $act, $appid, %args) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};
	my $usage = "create_appid <appid> [key=val ...]";

	$appid = canonicalise_fqprinc($ctx, $usage, 1, $appid);

	my @app_name = Krb5Admin::C::krb5_parse_name($ctx, $appid);
	if (@app_name != 2 || $app_name[1] !~ m{[A-Z][-A-Z0-9_]*}i) {
		die [503, "$appid is an invalid appid\n"];
	}

	require_localrealm($ctx, $hndl, $app_name[0]);

	return [$appid, %args];
}

sub create_appid {
	my ($self, $appid, %args) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};
	my $usage = "insert <appid> [key=val ...]";

	if (!$self->{local} && !exists($args{owner})) {
		$args{owner} = [$self->{client}];
	}

	my $stmt = "INSERT INTO appids(appid) VALUES (?)";

	eval {
		sql_exec($dbh, $stmt, $appid);
		generic_modify($dbh, \%field_desc, 'appids', $appid, %args);
	};
	if ($@) {
		my $err = $@;
		if ($err =~ /unique/i) {
			die [500, "Appid $appid already exists."];
		}
		die $err;
	}

	$self->can_user_act("Can't create appid's you don't own",
	    $self->{client}, "modify" , $appid, %args);

	$self->create($appid);
	$self->internal_modify($appid,
	    {attributes => [qw/+requires_preauth -allow_svr/]});

	return undef;
}

sub KHARON_IV_create_user {
	my ($self, $verb, $name, $passwd) = @_;

	require_scalar("create_user <princ>", 1, $name);
	die [500, "malformed name"]	if $name =~ m,[^-A-Za-z0-9_/@.],;

	return undef;
}

sub create_user {
	my ($self, $name, $passwd) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("create_user <princ>", 1, $name);
	die [500, "malformed name"]	if $name =~ m,[^-A-Za-z0-9_/@.],;

	my $ret = Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $name,
			policy		=> 'default',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR |
					   REQUIRES_PWCHANGE,
		}, [], $passwd);
	$ret;
}

#
# We provide a default ACL for creating bootstrap ids.  As our code
# will by default use pkinit to WELLKNOWN/ANONYMOUS@REALM to create
# these ids, we limit the ACL to these anonymous principals.

sub KHARON_ACL_create_bootstrap_id {
	my ($self, $verb) = @_;

	my @pp = Krb5Admin::C::krb5_parse_name($self->{ctx}, $self->{client});

	if (@pp == 3 && $pp[1] eq 'WELLKNOWN' && $pp[2] eq 'ANONYMOUS') {
		return 1;
	}

	return undef;
}

sub create_bootstrap_id {
	my ($self, %args) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};
	my $princ;
	my $realm = $args{realm};

	if (!defined($args{public}) || !defined($args{enctypes})) {
		die [503, "Must provide public key and enctypes"];
	}

	if (ref($args{enctypes}) ne 'ARRAY') {
		die [503, "enctypes must be an ARRAY ref of encryption types"];
	}

	#
	# XXXrcd: For now, we require that enctypes are aes256-cts (18) only.
	#         We require that the client specify enctypes so that we can
	#         apply a more interesting policy on this in the future.  We
	#         will review this soon---we should probably allow any
	#         ``secure'' cipher and we may need a more interesting way
	#         to let a client know that one of the provided enctypes is
	#         unacceptable.  Maybe we should return a list of enctypes
	#         that we accepted.  If we do this, we should do the same
	#         from create/change.  We can do this without affecting the
	#         API as they current have returns that are basically ignored.
	#         If we do this, we must also do it for bootstrap_host_key().

	if (@{$args{enctypes}} != 1 || $args{enctypes}->[0] ne '18') {
		die [503, "create_tmpid: enctypes must only contain " .
		    "aes256-cts"];
	}

	if (defined($realm)) {
		require_localrealm($ctx, $hndl, $realm);
	}

	my $passwd = $self->generate_ecdh_key2($args{public});

	while (!defined($princ)) {
		my $tmpname;

		#
		# We construct bootstrap ids by generating a random
		# key and converting it into text.  We do this by taking
		# a 32 byte aes256-cts key and applying a few transforms
		# to make the characters more likely to be boring.
		# We then discard all of the interesting characters and
		# take the first 16 remaining characters.  If we fail,
		# we restart the loop.  Empirically, this does not happen
		# terribly often.  This should give us 16 characters chosen
		# with roughly even odds from a character set of 62 which
		# comes out to about (2^5)^16 = 2^80 possibilities. This
		# should be enough to avoid most collisions.

		#
		# XXXrcd: as noted below, we may have a race condition between
		#         the erasure of keys and another client requesting a
		#         bootstrap key.  For now, we ignore this but we may
		#         want to take care of it appropriately later.  OTOH,
		#         we will always need to have a background process
		#         which cleans up the Kerberos database periodically
		#         and maybe this is sufficient.

		my $rnd = Krb5Admin::C::krb5_make_a_key($ctx, 18)->{key};

		$rnd =~ s/([^A-Za-z0-9])/sprintf("%c", ord($1)      & 0x7f)/ego;
		$rnd =~ s/([^A-Za-z0-9])/sprintf("%c", ord($1) + 65 & 0x7f)/ego;
		$rnd =~ s/([^A-Za-z0-9])//go;
		$rnd =~ s/^(.{16}).*$/$1/o;

		next	if length($rnd) < 16;

		$tmpname  = 'bootstrap';
		$tmpname .= '/' . $rnd;
		$tmpname .= '@' . $realm	if defined($realm);

		$tmpname = unparse_princ([Krb5Admin::C::krb5_parse_name($ctx,
		    $tmpname)]);

		#
		# XXXrcd: maybe we should use a passwd policy that rejects all
		#         passwd change requests?

		eval {
			Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
					principal  => $tmpname,
					policy     => 'default',
					attributes => REQUIRES_PRE_AUTH |
						      DISALLOW_POSTDATED |
						      DISALLOW_FORWARDABLE |
						      DISALLOW_PROXIABLE,
				}, $args{enctypes}, $passwd)
		};

		if (!$@) {
			$princ = $tmpname;
		}

		#
		# XXXrcd: we should likely have a look at the error message
		#         that is returned to ensure that it makes sense
		#         rather than just blindly continuing.  Maybe, I
		#         should simply write this part in C as it's a little
		#         easier for my to DTRT in that case---I could lock
		#         the DB and all that...  In fact, it is quite unlikely
		#         that we'll have a collision so it should be the
		#         unusual case.
	}

	return $princ;
}

sub KHARON_IV_bootstrap_host_key {
	my ($self, $cmd, $princ, $kvno, %args) = @_;
	my $ctx  = $self->{ctx};
	my $usage = "bootstrap_host_key <princ> <kvno> public=>key " .
	    "enctypes=>etypes";

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalar($usage, 2, $kvno);
	return undef;
}

sub KHARON_ACL_bootstrap_host_key {
	my ($self, $cmd, $princ, $kvno, %args)  = @_;
	my $ctx     = $self->{ctx};
	my $dbh     = $self->{dbh};
	my $subject = $self->{client};

	return "Invalid argument" if !defined($princ);

	my @pprinc = Krb5Admin::C::krb5_parse_name($ctx, $princ);

	if (@pprinc != 3 || $pprinc[1] ne 'host') {
		return "Permission denied: bootstrap_host_key " .
		    "may only be used on host principals.";
	}

	my ($realm, $h, $host) = @pprinc;

	my $stmt = qq{
		SELECT COUNT(*) FROM hosts
		WHERE realm = ? AND name = ? AND bootbinding = ?
	};
	my $sth = sql_exec($dbh, $stmt, $realm, $host, $subject);

	if ($sth->fetchrow_arrayref()->[0] != 1) {
		return "Permission denied: you are not bound to $host";
	}

	return 1;
}

sub bootstrap_host_key {
	my ($self, $princ, $kvno, %args) = @_;
	my $ctx  = $self->{ctx};
	my $usage = "bootstrap_host_key <princ> <kvno> public=>key " .
	    "enctypes=>etypes";

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalar($usage, 2, $kvno);

	$self->internal_create($princ, $kvno, %args);
	$self->remove_bootbinding($princ);
	return undef;
}

sub remove_bootbinding {
	my ($self, $princ) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};
	my $binding = $self->{client};
	my $dbh  = $self->{dbh};
	my $stmt;
	my $sth;

	my ($realm, $h, $host) = Krb5Admin::C::krb5_parse_name($ctx, $princ);

	#
	# XXXrcd: and then delete the mapping from the host entry in the
	#         kmdb and if there are no more entries, then delete the
	#         bootstrap key from the Kerberos database.

	$stmt = "UPDATE hosts SET bootbinding = NULL WHERE name = ?";
	sql_exec($dbh, $stmt, $host);

	#
	# We do not want to remove principals from the Kerberos DB if
	# they are not used solely in conjunxion with the bootbinding
	# framework:

	($realm, $h, $host) = Krb5Admin::C::krb5_parse_name($ctx, $princ);
	return undef if $h ne 'bootstrap';

	#
	# We now check to see if the binding is no longer being used and
	# if it is not then we remove the krb5 principal.  XXXrcd: maybe
	# this will cause a race condition, though, as another principal
	# may very well get this binding after we delete the principal..
	# Will this cause a problem?  Yes, it's a problem.  We should
	# change the code for selecting a binding id to use an incrementing
	# counter instead of a random number, perhaps...

	$stmt = "SELECT COUNT(name) FROM hosts WHERE bootbinding = ?";
	$sth = sql_exec($dbh, $stmt, $binding);

	if ($sth->fetch()->[0] == 0) {
		Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $binding);
	}

	return undef;
}

sub KHARON_ACL_listpols { return 1; }

sub listpols {
	my ($self, $exp) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	my $ret = Krb5Admin::C::krb5_list_pols($ctx, $hndl, $exp);
	@$ret;
}

sub KHARON_ACL_list { return 1; }

sub list {
	my ($self, $exp) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	my $ret = Krb5Admin::C::krb5_list_princs($ctx, $hndl, $exp);
	@$ret;
}

sub KHARON_ACL_fetch {
	my ($self) = @_;

	if (!$self->{allow_fetch}) {
		return "Permission denied: fetch is administratively " .
		    "prohibited";
	}
	acl_keytab(@_);
}

sub fetch {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("fetch <princ>", 1, $name);
	@{Krb5Admin::C::krb5_getkey($ctx, $hndl, $name)};
}

sub KHARON_ACL_fetch_old {
	my ($self) = @_;

	if (!$self->{allow_fetch_old}) {
		return "Permission denied: fetch_old is administratively " .
		    "prohibited";
	}
	acl_keytab(@_);
}

sub fetch_old {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("fetch_old <princ>", 1, $name);

	my @ret = @{Krb5Admin::C::krb5_getkey($ctx, $hndl, $name)};
	return @ret if (@ret == 0);

	# Return only keys with a kvno less than the largest
	my $kvno = [sort { $b <=> $a } map { $_->{"kvno"} } @ret]->[0];
	return grep { $_->{"kvno"} < $kvno } @ret;
}

sub KHARON_ACL_change { acl_keytab(@_); }

sub change {
	my ($self, $name, $kvno, @args) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("change <princ>", 1, $name);

	my %args;
	if (@args == 1) {
		# XXXrcd: legacy usage.
		%args = (keys => $args[0]);
	} else {
		%args = @args;
	}

	if (exists($args{keys}) && ! $self->{allow_fetch}) {
		die [502, "Permission denied: keys may not be specified"];
	}

	if (!exists($args{keys}) && !exists($args{public})) {
		die [503, "change: must provide either keys or public."];
	}

	if (exists($args{keys}) &&
	    (exists($args{public})|| exists($args{enctypes}))) {
		die [503, 'change: supplying keys mutually exclusive with ' .
		    'public or enctypes'];
	}

	if (exists($args{keys})) {
		Krb5Admin::C::krb5_setkey($ctx, $hndl, $name, $kvno,
		    $args{keys});
		return undef;
	}

	if (!defined($args{enctypes})) {
		die [503, "must provide enctypes"];
	}

	my $passwd = $self->generate_ecdh_key2($args{public});

	Krb5Admin::C::krb5_setpass($ctx, $hndl, $name, $kvno, $args{enctypes},
	    $passwd);

	return undef;
}

sub KHARON_IV_change_passwd {
	my ($self, $cmd, $name, $passwd, $opt) = @_;
	my $usage = "change_passwd <princ> [<passwd> [+needchange]]";

	require_scalar($usage, 1, $name);
	if (defined($passwd)) {
		require_scalar($usage, 2, $passwd);
	}
	if (defined($opt)) {
		require_scalar($usage, 3, $opt);
	}

	return undef;
}

sub change_passwd {
	my ($self, $name, $passwd, $opt) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};
	my $usage = "change_passwd <princ> [<passwd> [+needchange]]";

	require_scalar($usage, 1, $name);
	if (defined($passwd)) {
		require_scalar($usage, 2, $passwd);
	}
	if (defined($opt)) {
		require_scalar($usage, 3, $opt);
	}

	if (defined($passwd)) {
		Krb5Admin::C::krb5_setpass($ctx, $hndl, $name, -1, [], $passwd);
	} else {
		$passwd = Krb5Admin::C::krb5_randpass($ctx, $hndl, $name, []);
	}

	return $passwd if !defined($opt);

	if ($opt eq '+needchange') {
		$self->internal_modify($name, {attributes => [ $opt ]});
	}

	return $passwd;
}

sub KHARON_IV_reset_passwd {
	my ($self, $cmd, $name) = @_;

	require_scalar("reset_passwd <princ>", 1, $name);
	return undef;
}

sub reset_passwd {
	my ($self, $name) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("reset_passwd <princ>", 1, $name);

	my $passwd = Krb5Admin::C::krb5_randpass($ctx, $hndl, $name, []);
	$self->internal_modify($name, {attributes => [ '+needchange' ]});

	return $passwd;
}

sub KHARON_IV_modify {
	my ($self, $verb, $name, %mods) = @_;
	my $ctx = $self->{ctx};

	$name = canonicalise_fqprinc($ctx, "modify <princ> %mods", 1, $name);
	require_hashref("modify <princ> [key=val ...]", 2, \%mods);

	#
	# We query the principal here to make sure that it exists:

	$self->query($name);

	return [$name, %mods];
}

sub KHARON_ACL_modify {
	my ($self, $verb, $name, %mods) = @_;

	#
	# This ACL supports self-service modification of ``appid''
	# principals but only their ``appid'' bits:

	my @actions = qw{desc owner add_owner del_owner
			 cstraint add_cstraint del_cstraint};

	for my $mod (keys %mods) {
		return undef if !grep {$_ eq $mod} @actions;
	}

	return 1	if $self->is_appid_owner($self->{client}, $name);
	return undef;
}

sub modify {
	my ($self, $name, %mods) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};
	my $usage = "modify <princ> [key=val ...]";

	$name = canonicalise_fqprinc($ctx, $usage, 1, $name);
	require_hashref($usage, 2, \%mods);

	generic_modify($dbh, \%field_desc, 'appids', $name, %mods);

	my $is_appid_owner_mod = 0;
	my @actions = qw{owner add_owner del_owner};

	# Did we modify the ownership of the appid
	for my $act (@actions) {
		if (exists $mods{$act}) {
			$is_appid_owner_mod = 1;
			last;
		}
	}

	# Ensure we aren't giving away our access
	if ($is_appid_owner_mod && defined($self->{acl})) {
		eval {
			$self->{acl}->check('modify', $name);
		};
		die [503, "You cannot relinquish permissions."] if $@;
	}

	$self->internal_modify($name, \%mods);
	return undef;
}

#
# internal modify is a routine which only modifies the krb5 principal in
# the underlying Kerberos DB.  It can be called from other routines that
# are only interested in modifying the Kerberos attributes.

sub internal_modify {
	my ($self, $name, $mods) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	# XXXrcd: MUST LOCK BEFORE DOING THESE OPERATIONS
	# XXXrcd: SANITY CHECK VALUES!

	my $tmp = Krb5Admin::C::krb5_query_princ($ctx, $hndl, $name);
	my $attrs = $tmp->{attributes};

	my %attrs = ((map {       $_ => 1 } @{$mods->{attributes}}),
		     (map { '+' . $_ => 1 } @{$mods->{add_attributes}}),
		     (map { '-' . $_ => 1 } @{$mods->{del_attributes}}));

	for my $i (keys %attrs) {
		$i =~ s/^(.)//;
		my $sign = $1;

		if (($sign ne '+' && $sign ne '-') || !defined($flag_map{$i})) {
			die [504, "Invalid attribute $sign$i"];
		}

		if (($flag_map{$i}->[1] == 0 && $sign eq '+') ||
		    ($flag_map{$i}->[1] == 1 && $sign eq '-')) {
			$attrs |= $flag_map{$i}->[0];
		} else {
			$attrs &= ~$flag_map{$i}->[0];
		}
	}
	$mods->{attributes} = $attrs;
	$mods->{principal}  = $name;

	Krb5Admin::C::krb5_modprinc($ctx, $hndl, $mods);
	return undef;
}

sub KHARON_ACL_mquery { return 1; }

sub mquery {
	my ($self, @args) = @_;

	@args = ('*')	if scalar(@args) == 0;	# empty args is a wildcard.

	my @ret;
	for my $i (map { $self->list($_) } (@args)) {
		# XXXrcd: we ignore errors under the presumption that
		#	  the principal may have been deleted in the
		#	  middle of the operation...

		eval { push(@ret, $self->query($i)); };
	}
	@ret;
}

sub KHARON_ACL_query { return 1; }

sub query {
	my ($self, @names) = @_;
 
	my @ret;
	for my $name (@names) {
		push(@ret, $self->internal_query($name));
	}
 
	return @ret;
}

sub internal_query {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};
	my $dbh  = $self->{dbh};

	require_scalar("query <princ>", 1, $name);
	my $ret = Krb5Admin::C::krb5_query_princ($ctx, $hndl, $name);

	#
	# now, let's map our flags...

	my @flags;
	for my $i (keys %flag_map) {
		if ($ret->{attributes} & $flag_map{$i}->[0]) {
			push(@flags, ($flag_map{$i}->[1]?"-":"+") . $i);
		}
	}
	$ret->{attributes} = \@flags;

	my @tmp = @{Krb5Admin::C::krb5_getkey($ctx, $hndl, $name)};

	$ret->{keys} = [ map {
		{ kvno => $_->{kvno}, enctype => $_->{enctype} }
	} @tmp ];

	my $appid = generic_query($dbh, \%field_desc, 'appids', ['appid'],
	    appid => $ret->{principal});

	if (defined($appid)) {
		for my $k (keys %$appid) {
			$ret->{$k} = $appid->{$k};
		}
	}

	$ret;
}

sub KHARON_IV_enable { KHARON_IV_ONE_SCALAR(@_); }

sub enable {
	my ($self, $princ) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("enable <princ>", 1, $princ);
	$self->internal_modify($princ, { attributes => ['+allow_tix'] });
}

sub KHARON_IV_disable { KHARON_IV_ONE_SCALAR(@_); }

sub disable {
	my ($self, $princ) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("disable <princ>", 1, $princ);

	#
	# We fist also delete an associated admin principal if it exists,
	# we accomplish this by attempting to delete it and ignoring
	# the return code.

	if ($princ =~ m,^([^/@]+)(\@[^/@]+)?$,) {
		my $adm_princ = "$1/admin";

		$adm_princ .= $2 if defined($2);

		eval {
			Krb5Admin::C::krb5_deleteprinc($ctx,
			    $hndl, $adm_princ);
		};
	}

	$self->internal_modify($princ, { attributes => ['-allow_tix'] });
}

sub KHARON_IV_remove {
	my ($self, $cmd, $name) = @_;
	my $ctx  = $self->{ctx};

	$name = canonicalise_fqprinc($ctx, "remove <princ>", 1, $name);
	return [$name];
}

sub remove {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};
	my $dbh  = $self->{dbh};

	$name = canonicalise_fqprinc($ctx, "remove <princ>", 1, $name);

	#
	# First, we remove any associated appid record for the principal.

	# XXX: Remove should first drop any associated ACLs,
	# so that this does not have to be done manually to avoid
	# foreign-key constraint violations.

	my $stmt = "DELETE FROM appids WHERE appid = ?";

	sql_exec($dbh, $stmt, $name);

	#
	# And then we nuke the princ:

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $name);
	return undef;
}

sub KHARON_IV_is_appid_owner {
	my ($self, $cmd, $princ, $appid) = @_;
	my $ctx = $self->{ctx};

	my $usage = "is_appid_owner <princ> <appid>";
	$princ = canonicalise_fqprinc($ctx, $usage, 1, $princ);
	$appid = canonicalise_fqprinc($ctx, $usage, 2, $appid);

	return [$princ, $appid];
}

sub KHARON_ACL_is_appid_owner { return 1; }

sub is_appid_owner {
	my ($self, $princ, $appid) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};

	my $usage = "is_appid_owner <princ> <appid>";
	$princ = canonicalise_fqprinc($ctx, $usage, 1, $princ);
	$appid = canonicalise_fqprinc($ctx, $usage, 2, $appid);

	#
	# We implement here a single SQL statement that will deal
	# with recursive groups up to N levels.	 After this, we give
	# up...	 XXXrcd: should we deal with more recursion than this
	# or simply define N as being a hard limit?

	my @joins = ('LEFT JOIN acls ON appid_acls.acl = acls.name');
	my @where = ('acls.name = ?');
	my @bindv = ($princ);

	for (my $i=0; $i < GROUP_RECURSION; $i++) {
		my $join = "LEFT JOIN aclgroups AS aclgroups$i ";
		if ($i) {
			$join .= "ON aclgroups$i.aclgroup = aclgroups" .
			    ($i - 1) . ".acl";
		} else {
			$join .= "ON aclgroups$i.aclgroup = acls.name";
		}

		push(@joins, $join);
		push(@where, "aclgroups$i.acl = ?");
		push(@bindv, $princ);
	}

	my $stmt = q{SELECT COUNT(appid_acls.appid) FROM appid_acls } .
	    join(' ', @joins) . ' WHERE appid_acls.appid = ? AND (' .
	    join(' OR ', @where) . ")";

	my $sth = sql_exec($dbh, $stmt, $appid, @bindv);

	return $sth->fetch()->[0] ? 1 : 0;
}


#
# Export the Kharon::Entitlement::SimpleSQL interface:

sub KHARON_ACL_sacls_add {
	my ($self, $verb, $acl_verb, $acl_princ) = @_;

	# Avoid some accidents. Delegation to "ALL" requires "local" privs.
	return undef if defined($acl_princ) && $acl_princ eq "ALL";

	$self->{sacls}->check1($acl_verb);
}

sub KHARON_ACL_sacls_del	{ KHARON_ACL_sacls_add(@_); }

sub KHARON_ACL_sacls_query	{ return 1; }

sub sacls_add		{ my $self = shift(@_); $self->{sacls}->add(@_) }
sub sacls_del		{ my $self = shift(@_); $self->{sacls}->del(@_) }
sub sacls_query		{ my $self = shift(@_); $self->{sacls}->query(@_) }
sub sacls_init_db	{ my $self = shift(@_); $self->{sacls}->init_db(@_) }

sub add_label {
	my ($self, $label, $desc) = @_;
	my $dbh = $self->{dbh};

	require_scalar("add_label <label> <desc>", 1, $label);
	require_scalar("add_label <label> <desc>", 2, $desc);

	my $stmt = 'INSERT INTO labels(label, desc) VALUES (?, ?)';

	sql_exec($dbh, $stmt, $label, $desc);

	return undef;
}

sub del_label {
	my ($self, $label) = @_;
	my $dbh = $self->{dbh};

	require_scalar("del_label <label>", 1, $label);

	my $stmt = 'DELETE FROM labels WHERE label = ?';

	sql_exec($dbh, $stmt, $label);

	# toss errors if label not found...

	return undef;
}

sub KHARON_ACL_list_labels { return 1; }

sub list_labels {
	my ($self, $label) = @_;
	my $dbh = $self->{dbh};

	return generic_query($dbh, \%field_desc, 'labels', []);
}

# sub KHARON_ACL_list_table { return 1; }
sub list_table {
    my ($self, $table) = @_;
    my $dbh = $self->{dbh};

    my %allowed = ('appids' => 1,
		   'hosts' => 1,
		   'prestashed' => 1,
		   'account_principal_map' =>  1);


    require_scalar("list_table <table> ", 1, $table);

    if ($allowed{$table} == 1) {
	return generic_query($dbh, \%field_desc, $table, []);
    }

    die [500, "Raw query of $table unsupported"] ;
}

sub KHARON_IV_create_host {
	my ($self, $verb, $host, %args) = @_;

	require_scalar("create_host <host> [key=val ...]", 1, $host);

	return undef;
}

sub create_host {
	my ($self, $host, %args) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	my $is_logical = $args{is_logical} // 0;
	$args{owner} //= [$self->{client}]	if $is_logical;
	$args{realm} //= Krb5Admin::C::krb5_get_realm($ctx);

	my $lhost = $self->query_host($host);
	die [406, "$host already exists.\n"] if defined($lhost);

	my %fields = map { $_ => 1 } @{$field_desc{hosts}->{fields}};

	my @args = ('name');
	my @vals = ($host);
	delete $args{name};
	for my $arg (keys %args) {
		next if !defined($fields{$arg});

		push(@args, $arg);
		push(@vals, $args{$arg});
		delete $args{$arg};
	}

	my $stmt = "INSERT INTO hosts(" . join(',', @args) . ")" .
		   "VALUES (" . join(',', map {"?"} @args) . ")";

	sql_exec($dbh, $stmt, @vals);

	generic_modify($dbh, \%field_desc, 'hosts', $host, %args);

	if ($is_logical) {
		$self->can_user_act("Can't create logical hosts you don't own",
		    $self->{client}, "add_host_owner", $host);
	}

	return undef;
}

sub KHARON_ACL_create_logical_host	{ return 1; }
sub KHARON_IV_create_logical_host	{ KHARON_IV_create_host(@_); }
sub create_logical_host			{ create_host(@_, is_logical => 1); }

sub KHARON_IV_modify_host {
	my ($self, $cmd, $logical, %mods) = @_;

	require_scalar("modify_host <host> [args]", 1, $logical);
	return undef;
}

sub acl_host_secret {
	my ($self, $cmd, @args) = @_;
	my $subject = $self->{client};
	my $ctx = $self->{ctx};
	my $drealm = Krb5Admin::C::krb5_get_realm($ctx);
	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $subject);

	# Use of explicit hostname and perhaps keyid requires admin privs, and
	# furthermore, admins MUST at least provide the hostname in args[0].
	#
	if (@args == 0) {
		if (@sprinc != 3 || $sprinc[0] ne $drealm ||
		    $sprinc[1] ne "host") {
			return 0;
		}
		my $host = $self->query_host($sprinc[2]);
		if (! defined($host) || $host->{realm} ne $drealm) {
			return 0;
		}
		return 1;
	}
	return undef;
}

sub KHARON_ACL_bind_host_secret { acl_host_secret(@_); }
sub KHARON_ACL_read_host_secret { acl_host_secret(@_); }

sub bind_host_secret {
	my ($self, @args) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};
	my $subject = $self->{client};
	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $subject);
	my $stmt;
	my $sth;
	my $maxid;

	if (@args < 2) {
		$stmt = qq{ SELECT max(id) as maxid FROM host_secret_ids };
		$sth = sql_exec($dbh, $stmt);
		my $results = $sth->fetchall_arrayref({});
		$maxid = $results->[0]->{"maxid"};
		if ($sth->rows != 1 || ! $maxid) {
			die [500, "No host_secrets found."];
		}
	} else {
		$maxid = $args[1];
	}

	my $host = @args ? $args[0] : $sprinc[2];
	$stmt = qq { DELETE FROM host_secrets WHERE name = ? };
	sql_exec($dbh, $stmt, $host);
	$stmt = qq { INSERT INTO host_secrets(name, id) VALUES (?, ?) };
	sql_exec($dbh, $stmt, $host, $maxid) ;

	# Self-service calls from hosts, get id and value,
	# While administrators binding the host get only the id.
	#
	return [ $maxid ] if (@args);
	return [ $maxid, $self->read_host_secret() ];
}

sub read_host_secret {
	my ($self, @args) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};
	my $subject = $self->{client};
	my $sth;
	my $secret;

	# Administrator creates synthetic subject for salting the
	# secret for the appropriate host.
	#
	if (@args) {
		my $drealm = Krb5Admin::C::krb5_get_realm($ctx);
		$subject = sprintf(q{host/%s@%s}, $args[0], $drealm);
	}
	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $subject);

	# No explicit id, use the designated id of the host,
	# otherwise some (past) id for data recovery, ...
	#
	if (@args < 2) {
		my $stmt = qq {
			SELECT host_secret_ids.secret as secret
			FROM hosts
			LEFT JOIN host_secrets
				ON hosts.name = host_secrets.name
			LEFT JOIN host_secret_ids
				ON host_secrets.id = host_secret_ids.id
			WHERE hosts.name = ?
		};
		$sth = sql_exec($dbh, $stmt, $sprinc[2]);
	} else {
		my $stmt = qq {
			SELECT secret
			FROM host_secret_ids
			WHERE id = ?
		};
		$sth = sql_exec($dbh, $stmt, $args[1]);
	}
	my $results = $sth->fetchall_arrayref({});

	if ($sth->rows != 1 ||
	    !defined($secret = $results->[0]->{"secret"})) {
		die [500, "Host key not found."];
	}

	return hmac_sha256_base64($secret, $subject);
}

sub new_host_secret {
	my ($self) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};
	my $rnd = Krb5Admin::C::krb5_make_a_key($ctx, 18)->{key};

	my $stmt = qq{ SELECT max(id) as maxid FROM host_secret_ids };
	my $sth = sql_exec($dbh, $stmt);
	my $results = $sth->fetchall_arrayref({});
	my $maxid = $results->[0]->{"maxid"};
	$maxid //= 0;

	$stmt = qq { INSERT INTO host_secret_ids(id, secret) VALUES(?, ?) };
	$sth = sql_exec($dbh, $stmt, $maxid + 1, encode_base64($rnd, ""));
	$dbh->commit();
}

sub KHARON_ACL_modify_host {
	my ($self, $cmd, $logical, %mods) = @_;
	my $dbh = $self->{dbh};
	my $lhost = $self->query_host($logical);
	my @actions = qw{owner add_owner del_owner
			 label add_label del_label
			 member add_member del_member};

	return undef	if !defined($lhost);
	return undef	if !$lhost->{is_logical};
	return undef	if !is_owner($dbh, 'hosts', $self->{client}, $logical);

	for my $mod (keys %mods) {
		return undef if !grep {$_ eq $mod} @actions;
	}

	return 1;
}

sub modify_host {
	my ($self, $host, %args) = @_;
	my $dbh = $self->{dbh};

	require_scalar("modify_host <host> [key=val ...]", 1, $host);

	generic_modify($dbh, \%field_desc, 'hosts', $host, %args);

	$self->can_user_act("Can't create logical hosts you don't own",
	    $self->{client}, "modify_host", $host);

	return undef;
}

sub KHARON_IV_query_host  { KHARON_IV_ONE_SCALAR(@_); }
sub KHARON_ACL_query_host { return 1; }

sub query_host {
	my ($self, $name, @fields) = @_;
	my $dbh = $self->{dbh};
	my $ret;

	$ret = generic_query($dbh, \%field_desc, 'hosts', ['name'],
	    name => $name);

	return $ret			if @fields == 0;
	return $ret->{$fields[0]}	if @fields == 1;
	return {%$ret{@fields}};
}

sub KHARON_IV_bind_host {
	my ($self, $cmd, $host, $binding) = @_;
	my $ctx = $self->{ctx};

	require_scalar("bind_host <host> <binding>", 1, $host);
	require_fqprinc($ctx, "bind_host <host> <binding>", 2, $binding);

	return undef;
}

sub bind_host {
	my ($self, $host, $binding) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	require_scalar("bind_host <host> <binding>", 1, $host);
	require_fqprinc($ctx, "bind_host <host> <binding>", 2, $binding);

	my $stmt = "UPDATE hosts SET bootbinding = ? WHERE name = ?";
	my $sth  = sql_exec($dbh, $stmt, $binding, $host);

	if ($sth->rows != 1) {
		die [500, "Host $host does not exist."];
	}

	# XXXrcd: we must check if we successfully bound the host.
	return undef;
}

sub KHARON_IV_remove_host {
	my ($self, $cmd, @hosts) = @_;

	require_scalar("remove_host <host> [<host> ...]", 1, $hosts[0]);

	return undef;
}

sub KHARON_ACL_remove_host {
	my ($self, $cmd, @hosts) = @_;

	for my $host (@hosts) {
		my $perm = $self->KHARON_ACL_modify_host($cmd, $host);

		return undef if !defined($perm) || $perm ne '1';
	}
}

sub remove_host {
	my ($self, @hosts) = @_;
	my $dbh = $self->{dbh};

	require_scalar("remove_host <host> [<host> ...]", 1, $hosts[0]);

	my $i = 2;
	for my $host (@hosts) {
		require_scalar("remove_host <princ> <host> [<host> ...]",
		    $i++, $host);
	}

	while (@hosts) {
		my @curhosts = splice(@hosts, 0, 500);

		sql_exec($dbh, "DELETE FROM hosts WHERE "
		    . join(' OR ', map {"name=?"} @curhosts), @curhosts);

		#
		# XXXrcd: error handling and all that.
	}

	return;
}

sub KHARON_IV_insert_hostmap {
	my ($self, $cmd, @hosts) = @_;
	my $usage = "$cmd <logical> <physical>";

	require_scalar($cmd, 1, $hosts[0]);
	require_scalar($cmd, 2, $hosts[1]);
	return undef;
}

sub KHARON_ACL_insert_hostmap { return hostmap_acl(@_); }

sub insert_hostmap {
	my ($self, @hosts) = @_;
	my $dbh = $self->{dbh};
	my $usage = "insert_hostmap <logical> <physical>";

	require_scalar($usage, 1, $hosts[0]);
	require_scalar($usage, 2, $hosts[1]);

	@hosts = map { lc($_) } @hosts;

	my $phost = $self->query_host($hosts[1]);
	if (!defined $phost) {
		die [500, "Physical host doesn't exist\n"];
	}

	my $lhost = $self->query_host($hosts[0]);
	if (!defined $lhost) {
		die [404, "Logical host ". $hosts[0] ." doesn't exist"];
	}

	if (!$lhost->{is_logical}) {
		die [504, "There was a problem creating the logical name " .
		    "(likely a physical host named the same)."];
	}

	my $stmt = "INSERT INTO hostmap (logical, physical) VALUES (?, ?)";
	eval {
		sql_exec($dbh, $stmt, @hosts);
	};

	if ($@) {
		if ($@ =~ /unique/i) {
			die [500, $hosts[1] . ' is already in cluster ' .
			    $hosts[0]];
		}
		die $@;
	}

	# Always commit before notify_update_required.
	$dbh->commit();

	# A cluster member has been added, its important for the new member
	# to fetch its tickets now
	eval {
	    Krb5Admin::NotifyClient::notify_update_required($self, $hosts[1]);
	};
	if ($@) {
	    print STDERR "$@";
	}

	return undef;
}

sub KHARON_ACL_query_hostmap { return 1; }

sub query_hostmap {
	my ($self, $host) = @_;
	my $dbh = $self->{dbh};

	if (defined($host)) {
		return generic_query($dbh, \%field_desc, 'hostmap',
		    [qw/logical/], logical => $host);
	}

	return generic_query($dbh, \%field_desc, 'hostmap', []);
}

sub is_cluster_member {
	my ($self, $logical, $physical) = @_;
	my $dbh = $self->{dbh};

	my %w = ( "logical" => $logical, "physical" => $physical );
	return generic_query($dbh, \%field_desc, 'hostmap', [keys %w], %w);
}

sub KHARON_IV_remove_hostmap  { KHARON_IV_insert_hostmap(@_); }
sub KHARON_ACL_remove_hostmap { return hostmap_acl(@_); }

sub remove_hostmap {
	my ($self, @hosts) = @_;
	my $dbh = $self->{dbh};
	my $usage = "remove_hostmap <logical> <physical>";

	require_scalar($usage, 1, $hosts[0]);
	require_scalar($usage, 2, $hosts[1]);

	@hosts = map { lc($_) } @hosts;

	my $stmt = "DELETE FROM hostmap WHERE logical = ? AND physical = ?";

	sql_exec($dbh, $stmt, @hosts);

	return;
}

#
# XXXrcd: These three are actually ACLs!
#         They should be migrated to the ACL code.

sub _deny_xrealm {
	my ($pname, $prealm, $hname, $hrealm) = @_;

	die [504, sprintf("Realm %s of principal %s not compatible with " .
	    "realm %s of host %s", $prealm, $pname, $hrealm, $hname)];
}

sub _deny_nohost {
	my ($host) = @_;
	die [504, "Host $host not pre-defined in krb5_admin database." .
	    " Please contact your system administrator."];
}

sub _check_hosts {
	my ($self, $princ, $prealm, $realms, @hosts) = @_;

	for my $host (@hosts) {
		my $hrealm = $self->query_host($host, 'realm');

		_deny_nohost($host)	if !defined($hrealm);
		if (!grep($_ eq $hrealm, @$realms)) {
			_deny_xrealm($princ, $prealm, $host, $hrealm);
		}
	}
}

sub KHARON_IV_insert_ticket {
	my ($self, $verb, $princ, @hosts) = @_;
	my $ctx = $self->{ctx};
	my $usage = "$verb <princ> <host> [<host> ...]";

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalars($usage, 2, @hosts);

	return undef;
}

sub KHARON_ACL_insert_ticket {
	my ($self, $verb, $princ, @hosts) = @_;

	my $is_owner;
	eval {
		my $appid;

		#
		# don't check host labels if the appid doesn't have
		# cstraints or on ticket removal...

		@hosts = ()			if $verb eq 'remove_ticket';
		$appid = $self->query($princ)	if @hosts > 0;
		@hosts = ()			if !defined($appid->{cstraint});

		for my $host (@hosts) {
			my $h = $self->query_host($host);
			if (!defined($h)) {
				die "Host $h does not exist.\n";
			}

			for my $c (@{$appid->{cstraint}}) {
				if (!grep {$c eq $_} @{$h->{label}}) {
					die "Appid constraints not met by " .
					    "host labels.\n";
				}
			}
		}
		$is_owner = $self->is_appid_owner($self->{client}, $princ);
	};
	return "Permission denied: $@" if $@;

	return 1 if $is_owner eq '1';
	return undef;
}

sub insert_ticket {
	my ($self, $princ, @hosts) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};
	my $usage = "insert_ticket <princ> <host> [<host> ...]";

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalar($usage, 2, $hosts[0]);

	for (my $i = 1; $i <= $#hosts; ++$i) {
		require_scalar("insert_ticket <princ> <host> [<host> ...]",
		    $i+2, $hosts[$i]);
	}

	#
	# The ACL-check is host-insensitive, the caller just needs to
	# own the principal.

	#
	# If no host realm list is explicitly configured for the given
	# principal's realm, the principal's realm must match the realm
	# of each host. Otherwise, the realm of each host must be one of
	# the explicitly configured list values.

	my $prealm = [Krb5Admin::C::krb5_parse_name($self->{ctx}, $princ)]->[0];
	my $realms = $self->{prestash_xrealm}->{$prealm};
	$realms ||= [$prealm];
	$self->_check_hosts($princ, $prealm, $realms, @hosts);

	my @notify_hosts;
	for my $host (map {lc($_)} @hosts) {
		my $sth;

		my $stmt = qq{
			INSERT INTO prestashed (principal, host) VALUES (?, ?)
		};

		eval {
			$sth = sql_exec($dbh, $stmt, $princ, $host);
		};

		if ($@) {
			next if $@ =~ /unique/i;
			die $@;
		}

		$sth = sql_exec($dbh,
			"SELECT count(principal) FROM prestashed" .
			" WHERE host = ?", $host);

		my ($count) = $sth->fetchrow_array();

		if ($count > MAX_TIX_PER_HOST) {
			die [500, 'limit exceeded: you can only prestash ' .
				  MAX_TIX_PER_HOST .
				  ' tickets on a single host or service address']
		}
		push(@notify_hosts, $host);
	}
	# Always commit before notify_update_required.
	$dbh->commit();

	for my $host (@notify_hosts) {
		eval {
			Krb5Admin::NotifyClient::notify_update_required($self,
			    $host);
		};
		if ($@) {
			print STDERR "$@";
		}
	}

	return undef;
}

sub KHARON_IV_refresh_ticket {
	my ($self, $verb, $princ, @hosts) = @_;
	my $ctx = $self->{ctx};
	my $usage = "refresh_ticket <princ> <host> [<host> ...]";

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalars($ctx, $usage, 2, @hosts);

	return undef;
}

sub KHARON_ACL_refresh_ticket {
	my ($self, $verb, $princ, @hosts) = @_;

	if ($princ eq $self->{client}) {
		return 1;
	}

	KHARON_ACL_insert_ticket(@_);
}

sub refresh_ticket {
	my ($self, $princ, @hosts) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};
	my $usage = "refresh_ticket <princ> <host> [<host> ...]";

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalar($usage, 2, $hosts[0]);

	for (my $i = 1; $i <= $#hosts; ++$i) {
		require_scalar("insert_ticket <princ> <host> [<host> ...]",
		    $i+2, $hosts[$i]);
	}

	# lc() and de-dup host list
	@hosts = keys %{{map { lc($_) => 1 } @hosts}};

	my ($sth, $str) = sql_exec($dbh,
		"SELECT count(host) FROM prestashed" .
		"  WHERE principal = ?".
		"  AND host IN (".
		join(',', map { "?" } @hosts) .
		")", $princ, @hosts);
	my ($count) = $sth->fetchrow_array();

	if ($count != @hosts) {
		die [500, 'Principal not configured on all hosts provided'];
	}

	for my $host (@hosts) {
		eval {
			Krb5Admin::NotifyClient::notify_update_required($self,
			    $host);
		};
	}
	return undef;
}

sub KHARON_ACL_query_ticket { return 1; }

# XXX - MSW - Query ticket seems to predate generic query :(
#	      Extend it
#
sub query_ticket {
	my ($self, %query) = @_;
	my $dbh = $self->{dbh};

	#
	# XXXrcd: validation should be done.

	$query{expand} = 1 if $query{verbose};

	my @where;
	my @bindv;

	if (exists($query{host})) {
		my $tmp  = "target = ?";
		   $tmp .= " OR configured = ?"	if $query{expand};
		push(@where, $tmp);
		push(@bindv, $query{host});
		push(@bindv, $query{host})	if $query{expand};
	}

	if (exists($query{principal})) {
		push(@where, "principal = ?");
		push(@bindv, $query{principal});
	}

	if (exists($query{realm})) {
		if ($query{realm} =~ /\@_%/) {
			die [503, "Invalid character in supplied realm."];
		}

		push(@where, "principal LIKE ?");
		push(@bindv, '%@' . $query{realm});
	}

	my $where = join( ' AND ', @where );
	$where = "WHERE $where" if length($where) > 0;

	my $fields = "principal, host AS target";
	my $from   = "prestashed";

	if ($query{expand}) {
		$from .= qq{
			LEFT JOIN hostmap ON prestashed.host = hostmap.logical
		};

		$fields = qq{
			prestashed.principal	AS principal,
			prestashed.host		AS configured,
			hostmap.physical	AS target
		};
	}

	my $stmt = "SELECT $fields FROM $from $where";

	my $sth = sql_exec($dbh, $stmt, @bindv);

	#
	# We now reformat the result to be comprised of the simplest
	# data structure we can imagine that represents the query
	# results, we also remove duplicates and whatnot.  We do this
	# processing on the server because (1) we have the canonical
	# information and so it's more accurate, and (2) it reduces
	# the size of the data structure that is sent over the wire.

	my %ret;
	if ($query{verbose} || (!exists($query{host}) &&
	    !exists($query{principal}))) {
		for my $i (@{$sth->fetchall_arrayref({})}) {
			my $r;

			my $conf = $i->{configured};
			my $targ = $i->{target};

			if ($query{verbose}) {
				push(@{$r}, $conf);
				push(@{$r}, $targ)	if defined($targ);
			} else {
				$r = $conf;
				$r = $targ		if defined($targ);
			}

			push(@{$ret{$i->{principal}}}, $r);
		}
		return \%ret;
	}

	if (exists($query{host}) && exists($query{principal})) {
		return 1 if defined($sth->fetch());
		return 0;
	}

	if (exists($query{host})) {
		for my $i (@{$sth->fetchall_arrayref({})}) {
			$ret{$i->{principal}} = 1;
		}
		return [keys %ret];
	}

	#
	# At this point, we know that $query{principal} has been defined.

	for my $i (@{$sth->fetchall_arrayref({})}) {
		my $host;

		$host = $i->{configured};
		$host = $i->{target}		if defined($i->{target});

		$ret{$host} = 1;
	}
	return [keys %ret];
}

sub KHARON_ACL_fetch_tickets {
	my ($self, $cmd, $realm, $host) = @_;
	my $ctx = $self->{ctx};

	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $self->{client});

	return if @sprinc != 3;
	return if $sprinc[1] ne 'host';

	$host //= $sprinc[2];
	return if $sprinc[2] ne $host;

	# Now, we must also check to ensure that the client is
	# in the correct realm for the host that we have in our DB.

	$host = $self->query_host($host);
	return if !defined($host) || $host->{realm} ne $sprinc[0];

	# The request is authorised.
	return 1;
}

sub fetch_tickets {
	my ($self, $realm, $host) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};

	if (!defined($host) && $self->{local}) {
		$host = hostname();
	}

	#
	# If the hostname is not explicitly specified, it may be implied
	# via the subject principal. XXX: This logic must match the ACL!

	if (!defined($host)) {
		my @sprinc = Krb5Admin::C::krb5_parse_name($ctx,
		    $self->{client});

		if (@sprinc == 3 && $sprinc[1] eq 'host') {
			$host = $sprinc[2];
		}
	}

	if (! defined($host)) { die "fetch_tickets: no hostname specified\n"; }

	my $tix = $self->query_ticket(host => $host, realm => $realm,
	    expand => 1);

	# XXXrcd: make configurable...
	return { map {
		$_ => Krb5Admin::C::mint_ticket($ctx, $hndl, $_, 7 * 3600 * 24,
		    7 * 3600 * 24);
	} @$tix };
}

sub KHARON_IV_remove_ticket {
	my ($self, $princ, @hosts) = @_;
	my $usage = "remove_ticket <princ> <host> [<host> ...]";
	my $ctx = $self->{ctx};

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalars($usage, 2, @hosts);

	return undef;
}

sub KHARON_ACL_remove_ticket { KHARON_ACL_insert_ticket(@_) }

sub remove_ticket {
	my ($self, $princ, @hosts) = @_;
	my $usage = "remove_ticket <princ> <host> [<host> ...]";
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalars($usage, 2, @hosts);

	while (@hosts) {
		my @curhosts = splice(@hosts, 0, 500);

		sql_exec($dbh, qq{
			DELETE FROM prestashed WHERE principal = ? AND (
		    } . join(' OR ', map {"host=?"} @curhosts) . qq{
			)
		    }, $princ, @curhosts);

		#
		# XXXrcd: error handling and all that.
	}

	return undef;
}

sub KHARON_IV_create_subject {
	my ($self, $cmd, $subj, %args) = @_;
	my $ctx = $self->{ctx};
	my $usage = "$cmd <subj> [key=val ...]";

	require_scalar($usage, 1, $subj);

	die [503, "Must supply type."]	if !defined($args{type});
	return				if $args{type} eq 'group';
	die [503, "ACL type invalid."]	if $args{type} ne 'krb5';

	$subj = canonicalise_fqprinc($ctx, $usage, 1, $subj);

	return [$subj, %args];
}

#
# XXXrcd: TODO: we must prevent adding members to type != group

sub create_subject {
	my ($self, $subj, %args) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};
	my $princ = $self->{client};
	my $usage = "create_subject <subj> [key=val ...]";

	require_scalar($usage, 1, $subj);

	my $type = $args{type};

	if ($type eq 'group') {
		if ($subj !~ m/^[A-Za-z0-9][-_A-Za-z0-9 ]*$/) {
			die [503, "Invalid group name."];
		}
	} elsif ($type eq 'krb5') {
		$subj = canonicalise_fqprinc($ctx, $usage, 1, $subj);
	} else {
		die [503, "ACL type invalid."];
	}

	my $stmt = "INSERT INTO acls(name, type) VALUES (?, ?)";
	eval { sql_exec($dbh, $stmt, $subj, $type); };
	if ($@) {
		if ($@ =~ /unique/i) {
			die [500, $subj . ' already exists.'];
		}
		die $@;
	}

	generic_modify($dbh, \%field_desc, 'acls', $subj, %args);
	return;
}

sub KHARON_ACL_list_subject	{ return 1; }

sub list_subject {
	my ($self, %query) = @_;
	my $dbh = $self->{dbh};

	my $res = generic_query($dbh, \%field_desc, 'acls', [keys %query],
	    %query);
	return keys %$res;
}

sub KHARON_IV_modify_subject {
	my ($self, $cmd, $subj, %args) = @_;
	my $usage = "$cmd <subj> [key=val ...]";

	require_scalar($usage, 1, $subj);

	return;
}

sub modify_subject {
	my ($self, $subj, %args) = @_;
	my $dbh = $self->{dbh};
	my $ctx = $self->{ctx};
	my $princ = $self->{client};
	my $usage = "modify_subject <subj> [key=val ...]";

	generic_modify($dbh, \%field_desc, 'acls', $subj, %args);
	# XXXrcd: check we still have permissions.
	return;
}

sub KHARON_ACL_query_subject	{ return 1; }

sub query_subject {
	my ($self, $subj, @fields) = @_;
	my $dbh = $self->{dbh};
	my $ret;

	require_scalar("query_subject <subj>", 1, $subj);

	$ret = generic_query($dbh, \%field_desc, 'acls', ['name'],
	    name => $subj);

	return $ret			if @fields == 0;
	return $ret->{$fields[0]}	if @fields == 1;
	return {%$ret{@fields}};
}

sub KHARON_IV_remove_subject	{ KHARON_IV_ONE_SCALAR(@_); }

sub remove_subject {
	my ($self, $subj) = @_;
	my $dbh = $self->{dbh};

	require_scalar("remove_subject <subj>", 1, $subj);

	my $stmt = "DELETE FROM acls WHERE name = ?";
	sql_exec($dbh, $stmt, $subj);
	return;
}

#
# The group interfaces are largely just mapped directly into the subject
# interfaces and are only provided because we feel that users will understand
# them more intuitively.

my %gtype = ( type => 'group' );
sub KHARON_IV_create_group	{ KHARON_IV_create_subject(@_, %gtype); }
sub KHARON_ACL_create_group	{ KHARON_ACL_create_subject(@_, %gtype); }
sub create_group		{ create_subject(@_, %gtype); }

sub KHARON_IV_list_group	{ KHARON_IV_list_subject(@_, %gtype); }
sub KHARON_ACL_list_group	{ KHARON_ACL_list_subject(@_, %gtype); }
sub list_group			{ list_subject(@_, %gtype); }

sub KHARON_IV_modify_group	{ KHARON_IV_modify_subject(@_, %gtype); }
sub KHARON_ACL_modify_group	{ KHARON_ACL_modify_subject(@_, %gtype); }
sub modify_group		{ modify_subject(@_, %gtype); }

sub KHARON_IV_query_group	{ KHARON_IV_query_subject(@_); }
sub KHARON_ACL_query_group	{ KHARON_ACL_query_subject(@_); }
sub query_group			{ query_subject(@_); }

sub KHARON_IV_remove_group	{ KHARON_IV_remove_subject(@_); }
sub KHARON_ACL_remove_group	{ KHARON_ACL_remove_subject(@_); }
sub remove_group		{ remove_subject(@_); }

#
# XXXrcd: the {add,del,query}_acl framework will be deprecated at some
#         point.  It will be replaced with the
#         {create,query_remove}_{subject,group} interfaces.

sub KHARON_IV_add_acl {
	my ($self, $cmd, $acl, $type) = @_;

	require_scalar("add_acl <acl> <type> [key=val ...]", 1, $acl);
	require_scalar("add_acl <acl> <type> [key=val ...]", 2, $type);

	return undef;
}

sub KHARON_ACL_add_acl {
	my ($self, $cmd, $acl, $type) = @_;

	return 1 if $type eq 'group';
	return undef;
}

sub add_acl {
	my ($self, $acl, $type, %args) = @_;
	my $usage = "add_acl <acl> <type> [key=val ...]";

	require_scalar($usage, 1, $acl);
	require_scalar($usage, 2, $type);

	$args{type} = $type;
	$args{owner} = [$args{owner}] if defined $args{owner};
	return $self->create_subject($acl, %args);
}

sub KHARON_IV_del_acl {
	my ($self, $cmd, $acl) = @_;
	my $acls = $self->query_acl(name => $acl);

	require_scalar("del_acl <acl>", 1, $acl);

	return undef;
}

sub KHARON_ACL_del_acl {
	my ($self, $cmd, $acl) = @_;
	my $acls = $self->query_acl(name => $acl);

	return undef if $acls->{type} ne 'group';
	return 1     if is_owner($self->{dbh}, 'acls', $self->{client}, $acl);
	return undef;
}

sub del_acl {
	my ($self, $acl) = @_;

	return $self->remove_subject($acl);
}

sub KHARON_ACL_query_acl { return 1; }

sub query_acl {
	my ($self, %query) = @_;
	my $dbh = $self->{dbh};

	return generic_query($dbh, \%field_desc, 'acls', [keys %query], %query);
}

# Replacements for aclgroup modifications
# Allows the "owner" to modify the group

sub KHARON_IV_insert_aclgroup {
	my ($self, $cmd, @acls) = @_;

	require_scalar("$cmd <aclgroup> <acl>", 1, $acls[0]);
	require_scalar("$cmd <aclgroup> <acl>", 2, $acls[1]);

	return undef;
}

sub KHARON_ACL_insert_aclgroup { KHARON_ACL_del_acl(@_); }

sub insert_aclgroup {
	my ($self, @acls) = @_;
	my $dbh = $self->{dbh};
	my $usage = "insert_aclgroup <aclgroup> <acl>";

	require_scalar($usage, 1, $acls[0]);
	require_scalar($usage, 2, $acls[1]);

	my $acls = $self->query_acl(name => $acls[0]);

	if ($acls->{type} ne 'group') {
		die [503, "LHS of an aclgroup must be of type group"];
	}

	my $stmt = "INSERT INTO aclgroups (aclgroup, acl) VALUES (?, ?)";

	eval {
		sql_exec($dbh, $stmt, @acls);
	};

	if ($@) {
		if ($@ =~ /unique/i) {
			die [500, $acls[1] . ' is already in group ' .
			    $acls[0]];
		}
		die $@;
	}

	return undef;
}

sub KHARON_ACL_remove_aclgroup { return KHARON_ACL_insert_aclgroup (@_); }

sub remove_aclgroup {
	my ($self, @acls) = @_;
	my $dbh = $self->{dbh};
	my $usage = "remove_aclgroup <aclgroup> <acl>";

	require_scalar($usage, 1, $acls[0]);
	require_scalar($usage, 2, $acls[1]);

	my $stmt = "DELETE FROM aclgroups WHERE aclgroup = ? AND acl = ?";

	sql_exec($dbh, $stmt, @acls);

	return;
}

sub KHARON_ACL_query_aclgroup { return 1; }

sub query_aclgroup {
	my ($self, $acl) = @_;
	my $dbh = $self->{dbh};
	my %args;

	$args{aclgroup} = $acl	if defined($acl);

	return generic_query($dbh, \%field_desc, 'aclgroups', [keys %args],
	    %args);
}

sub KHARON_ACL_add_acl_owner { return KHARON_ACL_del_acl(@_); }

sub add_acl_owner {
	my ($self, $obj, $owner) = @_;
	my $res = owner_add_f('acls', 'name', @_);
	$self->{dbh}->commit();
	return;
}

sub KHARON_ACL_remove_acl_owner { return KHARON_ACL_del_acl(@_); }
sub remove_acl_owner { return owner_del_f('acls',@_); }

sub hostmap_acl {
	# If the logical host exists and the user is an owner of that
	# "host" then allow the user to perform the action fallthrough
	# otherwise
	my ($self, $cmd, $logical ) = @_;
	my $dbh = $self->{dbh};
	my $lhost = $self->query_host($logical);

	return undef	if !defined($lhost);
	return undef	if !$lhost->{is_logical};
	return 1	if is_owner($dbh, 'hosts', $self->{client}, $logical);
	return undef;
}

sub remove_object_owner {
	my ($dbh, $obj_type, $objname, $ownerprinc) = @_;
	my $stmt = "DELETE FROM ${obj_type}_owner where owner = ? and name = ?";
	sql_exec($dbh, $stmt, $ownerprinc, $objname);
}

sub add_object_owner {
	my ($dbh, $obj_type, $objname, $ownerprinc) = @_;
	my $stmt= "INSERT INTO ${obj_type}_owner(name, owner) VALUES (?,?)";
	sql_exec($dbh, $stmt, $objname, $ownerprinc);
}

sub owner_del_f {
	my ($type_name, $self,  $obj, $owner) = @_;
	my $dbh = $self->{dbh};
	my $cmdline =  "del_".$type_name."_owner <".$type_name."> <owner>";
	my $verb = "add_".$type_name."_owner";
	$verb = "add_acl_owner" if $type_name eq "acls";

	require_scalar($cmdline, 1, $obj);
	my $princ = canonicalise_fqprinc($self->{ctx}, $cmdline, 2, $owner);

	my $res = remove_object_owner($dbh, $type_name, $obj, $owner);

	if ($self->{client} eq $princ) {
	    $self->can_user_act("You can't remove your own ownership",
		$self->{client}, $verb, $obj, $owner);
	}
	$dbh->commit();
	return $res;
}

sub owner_add_f {
	my ($type_name, $type_key, $self, $obj, $owner) = @_;
	my $dbh = $self->{dbh};
	my $cmdline =  "add_".$type_name."_owner <".$type_name."> <owner>";

	require_scalar($cmdline, 1, $obj);
	require_scalar($cmdline, 2, $owner);
	my $princ = $owner;	# canonicalise_fqprinc($self->{ctx}, $cmdline,
				#     2, $owner);

	my $res = generic_query($dbh, \%field_desc, $type_name, [$type_key],
		$type_key=>$obj);

	my $owner_res = generic_query($dbh, \%field_desc, "acls", ["name"],
	    name=>$princ);
	if (!defined $owner_res) {
		die [504, $princ. " doesn't exists"];
	}

	# The object must exist
	# also we must we don't want to create extras
	# so only add if the object doesn't already exist
	if (defined $res) {
		$res = generic_query($dbh, \%field_desc, $type_name."_owner",
		    ['name'], name=>$obj, owner=>$princ);
		if (!defined($res)) {
			add_object_owner($dbh, $type_name, $obj, $princ);
		}
		return 1;
	} else {
		die [503, "$type_name object $obj must exists before " .
		    "attaching additional owners"];
	}
}

sub KHARON_ACL_remove_host_owner { return hostmap_acl(@_); }
sub remove_host_owner { return owner_del_f('hosts',@_); }

sub KHARON_ACL_add_host_owner { return hostmap_acl(@_); }
sub add_host_owner {
	my ($self)  = @_;
	my $res = owner_add_f('hosts', 'name', @_);
	return $res;
}

sub is_owner {
	my ($dbh, $obj_type, $princ, $obj_id) = @_;

	#
	# We implement here a single SQL statement that will deal
	# with recursive groups up to N levels.	 After this, we give
	# up...	 XXXrcd: should we deal with more recursion than this
	# or simply define N as being a hard limit?

	my @joins = ('LEFT JOIN acls ON '.$obj_type.'_owner.owner = acls.name');
	my @where = ('acls.name = ?');
	my @bindv = ($princ);

	for (my $i=0; $i < GROUP_RECURSION; $i++) {
		my $join = "LEFT JOIN aclgroups AS aclgroups$i ";
		if ($i) {
			$join .= "ON aclgroups$i.aclgroup = aclgroups" .
			    ($i - 1) . ".acl";
		} else {
			$join .= "ON aclgroups$i.aclgroup = acls.name";
		}

		push(@joins, $join);
		push(@where, "aclgroups$i.acl = ?");
		push(@bindv, $princ);
	}

	my $stmt;
	$stmt = "SELECT COUNT(${obj_type}_owner.name) FROM ${obj_type}_owner ".
	    join(' ', @joins) . " WHERE ${obj_type}_owner.name = ? AND (" .
	    join(' OR ', @where) . ")";

	my $sth = sql_exec($dbh, $stmt, $obj_id, @bindv);

	my $res = $sth->fetch()->[0] ? 1 : 0;

	$sth->finish;
	return $res;
}

sub query_owner_f {
	my ($obj_type, $self, @r)  = @_;
	my $sql = "SELECT * from ".$obj_type."_owner where name=?";
	my $sth = sql_exec($self->{dbh}, $sql, @r);

	my $ret =  $sth->fetchall_arrayref({});
	$sth->finish;
	return $ret;
}

sub KHARON_ACL_query_host_owner { return 1; }
sub query_host_owner {
	my $self = $_[0];
	my $r = query_owner_f('hosts', @_);
	return $r;
}

sub KHARON_ACL_query_acl_owner { return 1; }
sub query_acl_owner {
	my $self = $_[0];
	my $r = query_owner_f('acls', @_);
	return $r;
}

sub KHARON_ACL_list_commands { return 1; }
sub list_commands {
	return @Krb5Admin::KRB5_USER_COMMANDS;
}

sub principal_map_remove {
	my ($self, $account, $svc, $hostname) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	my $usage = "principal_map_remove <account> <service> <hostname>";

	require_scalar($usage, 1, $account);
	require_scalar($usage, 2, $svc);
	require_scalar($usage, 3, $hostname);

	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, "$svc/$hostname");
	die [500, "Malformed service or host name" ] if (@sprinc != 3);

	my $stmt = "DELETE FROM account_principal_map " .
	    "WHERE accountname=? AND realm=? AND servicename=? AND instance=?";

	sql_exec($dbh, $stmt, $account, @sprinc);
	return 1;
}

# add some principal mappings...
# long term this should include a better implementation of the
# access control policy than just punting to the SACLs
sub principal_map_add {
	my ($self, $account, $svc, $hostname) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	my $usage = "principal_map_add <account> <service> <hostname>";

	require_scalar($usage, 1, $account);
	require_scalar($usage, 2, $svc);
	require_scalar($usage, 3, $hostname);

	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, "$svc/$hostname");
	die [500, "Malformed service or host name" ] if (@sprinc != 3);

	my $stmt = "INSERT INTO account_principal_map " .
	    "(accountname, realm, servicename, instance) VALUES (?, ?, ?, ?)";

	sql_exec($dbh, $stmt, $account, @sprinc);
	return 1;
}

sub KHARON_ACL_principal_map_query { return 1;}

sub principal_map_query {
	my ($self, $account, $princ) = @_;
	my $dbh = $self->{dbh};
	my $usage = "principal_map_query <account> <service principal>";

	require_scalar($usage, 1, $account);
	require_scalar($usage, 2, $princ);

	my @sprinc = Krb5Admin::C::krb5_parse_name($self->{ctx}, $princ);

	my %query = (
		accountname => $account,
		servicename => $sprinc[1],
		instance    => $sprinc[2],
		realm	    => $sprinc[0]
	);

	return generic_query_union($dbh, \%field_desc,
				   'account_principal_map',
				   'external_account_principal_map',
				   [keys %query], %query);
}

1;

__END__

=head1 NAME

Krb5Admin::KerberosDB - locally manipulate a Kerberos DB

=head1 SYNOPSIS

	use Krb5Admin::KerberosDB;

	my $kmdb = Krb5Admin::KerberosDB->new();

=head1 DESCRIPTION

=head1 CONSTRUCTOR

=over 4

=item new(ARGS)

Creates a new "Krb5Admin::KerberosDB" object.  ARGS is a hash which
can contain

=over 4

=item acl_file

the path to the acl_file, defaults to /etc/krb5/krb5_admin.acl

=item dbname

broken.

=item sqlite

the path to the adjunct sqlite DB.

=item debug

if true, turns on debugging.

=item local

if true, sets the DB access mode to local which will circumvent ACL
checks and ignore client, add and hostname.

=item client

the Kerberos principal under whose authority actions will be taken.

=item addr

the address from which the client connected.

=item xrealm_bootstrap

the cross realm bootstrapping table.  Must be a hash reference.

=item win_xrealm_bootstarp

the Windows cross realm bootstrapping table.  Must be a hash reference.

=item prestash_xrealm

the prestashed cross realm authorisation table.  Must be a hash reference.

=back

=back

=head1 METHODS

All of the user-visible methods are inherited from Krb5Admin and are
documented there as well.

=head1 SEE ALSO

krb5_admin list_commands

L<Krb5Admin>
