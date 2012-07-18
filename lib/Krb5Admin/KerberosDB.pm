# 
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::KerberosDB;

use base qw/Krb5Admin/;

use DBI;
use Sys::Hostname;
use Sys::Syslog;

use Krb5Admin::Utils qw/reverse_the host_list/;
use Krb5Admin::C;
use Kharon::Entitlement::ACLFile;
use Kharon::Entitlement::Equals;

use Kharon::dbutils qw/sql_command generic_query/;

use Kharon::dbutils qw/sql_command generic_query/;

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

sub require_fqprinc {
	my ($ctx, $usage, $argnum, $princ) = @_;
	my @p;
	my $tmp;

	eval {
		@p = Krb5Admin::C::krb5_parse_name($ctx, $princ);
		$tmp = unparse_princ(\@p);
	};

	if ($@) {
		die [503, "Syntax error: arg $argnum must be a fully " .
		    "qualified principal: $@\nusage: $usage"];
	}

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

	if (@creds == 0) {
		die "Must provide a credential to set_creds";
	}

	if (@creds > 1) {
		die "Krb5Admin::KerberosDB does not support multiple " .
		    "credentials";
	}

	$self->{client} = $creds[0];
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
	my $acl = $self->{acl};

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

	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $subject);

	my @pprinc;
	if (defined($predicate[0])) {
		@pprinc = Krb5Admin::C::krb5_parse_name($ctx, $predicate[0]);
	}

	#
	# We allow host/foo@REALM to access <service>/foo@REALM for any
	# <service>.

	if (@pprinc != 3) {
		return "Keytab acls operate on 3 part principals.";
	}

	if ($pprinc[1] eq 'host') {

		#
		# If Krb5Admin::Utils::reverse_the is defined then we
		# will have $self->{hostname} and we'll use it to validate
		# that the request is coming from a properly mapped host.
		# Otherwise, we ignore it.

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

		$denied = "not an admin user";
		if (!$host_ok) {
			$denied  = "host does not match IP address";
			$denied .= " [" . $self->{hostname} . " not in " .

			$denied .= join(',', host_list($self->{hostname}));
			$denied .= "]";
		}
	} else {
		if (@sprinc != 3) {
			return 0;
		}

		$denied = 'realm'	if $sprinc[0] ne $pprinc[0];
		$denied = 'host'	if $sprinc[1] ne 'host';
		$denied = 'instance'	if $sprinc[2] ne $pprinc[2];
		$denied = 'no admin'	if $pprinc[2] eq 'admin';
		$denied = 'no root'	if $pprinc[2] eq 'root';
	}

	if (defined($denied)) {
		syslog('err', "%s", $subject . " failed ACL check for " .
		    $predicate[0] . "[$denied]");
		return "Permission denied [$denied] for $subject";
	}

	return 1;
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

	$dbname   = $args{dbname}	if defined($args{dbname});
	$sqlite   = $args{sqlite}	if defined($args{sqlite});

	# initialize our database handle
	my $dbh = DBI->connect("dbi:SQLite:$sqlite", "", "",
	    {RaiseError => 1, PrintError => 0, AutoCommit => 1});
	die "Could not open database " . DBI::errstr if !defined($dbh);
	$dbh->do("PRAGMA foreign_keys = ON");
	$dbh->do("PRAGMA journal_mode = WAL");
	$dbh->{AutoCommit} = 0;

	my $ctx = $self->{ctx};

	$self->{debug}	  = $args{debug};
	$self->{local}	  = $args{local};
	$self->{client}	  = $args{client};
	$self->{addr}	  = $args{addr};
	$self->{hostname} = reverse_the($args{addr});
	$self->{ctx}	  = $ctx;
	$self->{hndl}	  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, $dbname);
	$self->{acl}	  = $args{acl};
	$self->{dbh}	  = $dbh;

	$self->{local}	= 0			if !defined($self->{local});
	$self->{client}	= "LOCAL_MODIFICATION"	if          $self->{local};
	$self->{debug}	= 0			if !defined($self->{debug});

	$self->{allow_fetch}		= $args{allow_fetch};
	$self->{xrealm_bootstrap}	= $args{xrealm_bootstrap};
	$self->{win_xrealm_bootstrap}	= $args{win_xrealm_bootstrap};
	$self->{prestash_xrealm}	= $args{prestash_xrealm};

	if (!defined($self->{allow_fetch})) {
		$self->{allow_fetch} = 0;
		$self->{allow_fetch} = 1	if $self->{local};
	}

	bless($self, $class);
}

sub DESTROY {
	my ($self) = @_;

	if (defined($self->{dbh})) {
		$self->{dbh}->disconnect();
		undef($self->{dbh});
	}
	undef $self->{acl};
}

sub init_db {
	my ($self) = @_;
	my $dbh = $self->{dbh};

	Krb5Admin::C::init_kdb($self->{ctx}, $self->{hndl});

	$dbh->{AutoCommit} = 1;

	#
	# XXXrcd: the hosts structure should likely point to a list of
	#	  addresses or something more like that...

	$dbh->do(qq{
		CREATE TABLE hosts (
			name		VARCHAR NOT NULL PRIMARY KEY,
			realm		VARCHAR NOT NULL,
			ip_addr		VARCHAR,
			bootbinding	VARCHAR
		)
	});

	$dbh->do(qq{
		CREATE TABLE host_labels (
			host		VARCHAR NOT NULL,
			label		VARCHAR NOT NULL,

			PRIMARY KEY (host, label)
			FOREIGN KEY (host) REFERENCES hosts(name)
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
		CREATE TABLE prestashed (
			principal	VARCHAR NOT NULL,
			host		VARCHAR NOT NULL,

			PRIMARY KEY (principal, host)
			FOREIGN KEY (host) REFERENCES hosts(name)
		)
	});

	$dbh->{AutoCommit} = 0;

	return undef;
}

sub drop_db {
	my ($self) = @_;
	my ($dbh) = $self->{dbh};

	# XXXrcd: should we unlink(2) the Kerberos DB?  Maybe not.

	$dbh->{AutoCommit} = 1;
	$dbh->do('DROP TABLE IF EXISTS prestashed');
	$dbh->do('DROP TABLE IF EXISTS hostmap');
	$dbh->do('DROP TABLE IF EXISTS host_labels');
	$dbh->do('DROP TABLE IF EXISTS hosts');
	$dbh->{AutoCommit} = 0;
}

sub master { undef; }

#
# If generate_ecdh_key1() is provided with $operation and $name then it
# will perform ACL checks based on those.  Otherwise it will simply return
# a key.  The ACLs will be rechecked later by the method that actually
# performs the work---this check is merely a shorthand to catch ACL errors
# earlier in the process and as such it is not necessary to use it...

my @gek_operations = qw(change create create_bootstrap_id bootstrap_host_key);

sub KHARON_ACL_generate_ecdh_key1 {
	my ($self, $verb, $operation, $name, @args) = @_;

	if (defined($operation) || defined($name)) {
		if (!defined($operation) || !defined($name)) {
			die [503, "If arg1 or arg2 are defined then both " .
			    "must be defined."];
		}

		if ((grep { $operation eq $_ } @gek_operations) < 1) {
			die [503, "arg1 must be one of: " .
			    join(', ', @gek_operations)];
		}

		return $self->{acl}->check($operation, $name);
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
		Krb5Admin::C::krb5_createkey($ctx, $hndl, $name);
		syslog('info', "%s", $self->{client} . " created $name");
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
		Krb5Admin::C::krb5_createprinc($ctx, $hndl,
		    {principal => $name}, $args{enctypes}, $passwd);
	} else {
		Krb5Admin::C::krb5_setpass($ctx, $hndl, $name, $kvno,
		    $args{enctypes}, $passwd);
	}

	syslog('info', "%s", $self->{client} . " created $name");
	return undef;
}

sub create_user {
	my ($self, $name, $passwd) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("create_user <princ>", 1, $name);
	die "malformed name"	if $name =~ m,[^-A-Za-z0-9_/@.],;

	my $ret = Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $name,
			policy		=> 'default',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR |
					   REQUIRES_PWCHANGE,
		}, [], $passwd);
	syslog('info', "%s", $self->{client} . " created $name");
	$ret;
}

#
# We provide a default ACL for creating bootstrap ids.  As our code
# will by default use pkinit to WELLKNOWN/ANONYMOUS@REALM to create
# these ids, we limit the ACL to these anonymous principals.

sub KHARON_ACL_create_bootstrap_id {
	my ($self, %args) = @_;

	if ($self->{client} eq 'WELLKNOWN/ANONYMOUS@' . $args{realm}) {
		return 1;
	}

	return 0;
}

sub create_bootstrap_id {
	my ($self, %args) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};
	my $princ;
	my $realm;

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

	if (defined($args{realm}) && ref($args{realm}) eq '') {
		$realm = $args{realm};

		eval {
			Krb5Admin::C::krb5_query_princ($ctx, $hndl,
			    unparse_princ([$realm, "krbtgt", $realm]));
		};

		if ($@) {
			die [502, "KDC does not support realm $realm"];
		}
	}

	if (!defined($realm)) {
		die [503, "Must supply realm"];
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
	my $sth = sql_command($dbh, $stmt, $realm, $host, $subject);

	if ($sth->fetchrow_arrayref()->[0] != 1) {
		return "Permission denied: you are not bound to $host";
	}

	return 1;
}

sub bootstrap_host_key {
	my ($self, $princ, $kvno, %args) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};
	my $dbh  = $self->{dbh};
	my $stmt;
	my $sth;

	my $binding = $self->{client};

	# XXXrcd: sanity checks?

	require_fqprinc($ctx, "bootstrap_host_key <princ> <kvno> public=>key " .
	    "enctypes=>etypes", 1, $princ);
	require_scalar("bootstrap_host_key <princ> <kvno> public=>key " .
	    "enctypes=>etypes", 2, $kvno);

	my ($realm, $h, $host) = Krb5Admin::C::krb5_parse_name($ctx, $princ);

	#
	# XXXrcd: any more ACLs?  Fix how we determine the realm.

	$self->internal_create($princ, $kvno, %args);

	#
	# XXXrcd: and then delete the mapping from the host entry in the
	#         kmdb and if there are no more entries, then delete the
	#         bootstrap key from the Kerberos database.

	$stmt = "UPDATE hosts SET bootbinding = NULL WHERE name = ?";
	sql_command($dbh, $stmt, $host);
	$dbh->commit();

	#
	# We now check to see if the binding is no longer being used and
	# if it is not then we remove the krb5 principal.  XXXrcd: maybe
	# this will cause a race condition, though, as another principal
	# may very well get this binding after we delete the principal..
	# Will this cause a problem?  Yes, it's a problem.  We should
	# change the code for selecting a binding id to use an incrementing
	# counter instead of a random number, perhaps...

	$stmt = "SELECT COUNT(name) FROM hosts WHERE bootbinding = ?";
	$sth = sql_command($dbh, $stmt, $binding);

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
	my ($self, @args) = @_;

	if (!$self->{allow_fetch}) {
		return "Permission denied: fetch is administratively " .
		    "prohibited";
	}
	return $self->acl_keytab(@args);
}

sub fetch {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};
	my $tmp;
	my @ret;

	require_scalar("fetch <princ>", 1, $name);

	syslog('info', "%s", $self->{client} . " fetched $name");
	Krb5Admin::C::krb5_getkey($ctx, $hndl, $name);
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

sub change_passwd {
	my ($self, $name, $passwd, $opt) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("change_passwd <princ>", 1, $name);
	if (defined($passwd)) {
		require_scalar("change_passwd <princ>", 2, $passwd);
	}
	if (defined($opt)) {
		require_scalar("change_passwd <princ>", 3, $opt);
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

sub reset_passwd {
	my ($self, $name) = @_;
	my $ctx = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("reset_passwd <princ>", 1, $name);

	my $passwd = Krb5Admin::C::krb5_randpass($ctx, $hndl, $name, []);
	$self->internal_modify($name, {attributes => [ '+needchange' ]});

	return $passwd;
}

sub modify {
	my ($self, $name, $mods) = @_;

	require_scalar("modify <princ> {mods}", 1, $name);
	require_hashref("modify <princ> {mods}", 2, $mods);
	die [501, "Function not implemented"];

	$self->internal_modify($name, $mods);
}

sub internal_modify {
	my ($self, $name, $mods) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	# XXXrcd: MUST LOCK BEFORE DOING THESE OPERATIONS
	# XXXrcd: SANITY CHECK VALUES!

	my $tmp = Krb5Admin::C::krb5_query_princ($ctx, $hndl, $name);
	my $attrs = $tmp->{attributes};

	for my $i (@{$mods->{attributes}}) {
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
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

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

	my @tmp = Krb5Admin::C::krb5_getkey($ctx, $hndl, $name);

	$ret->{keys} = [ map {
		{ kvno => $_->{kvno}, enctype => $_->{enctype} }
	} @tmp ];

	$ret;
}

sub enable {
	my ($self, $princ) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("enable <princ>", 1, $princ);
	$self->internal_modify($princ, { attributes => ['+allow_tix'] });
}

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

sub remove {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("remove <princ>", 1, $name);
	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $name);
	return undef;
}

our %field_desc = (
	hosts		=> {
		pkey		=> 'name',
		uniq		=> [qw/name ip_addr bootbinding/],
		fields		=> [qw/name realm ip_addr bootbinding/],
		lists		=> [[qw/host_labels host label/]],
		wontgrow	=> 0,
	},
	hostmap		=> {
		pkey		=> undef,
		uniq		=> [],
		fields		=> [qw/logical physical/],
		wontgrow	=> 1,
	},
);

sub create_host {
	my ($self, $host, %args) = @_;
	my $dbh = $self->{dbh};

	require_scalar("create_host <host> [args]", 1, $host);

	my %fields = map { $_ => 1 } @{$field_desc{hosts}->{fields}};

	my @args = ('name');
	my @vals = ($host);
	delete $fields{name};
	for my $arg (keys %args) {
		next if defined($fields{$arg}) && !$fields{$arg};

		push(@args, $arg);
		push(@vals, $args{$arg});
		delete $fields{$arg};
	}

	my $stmt = "INSERT INTO hosts(" . join(',', @args) . ")" .
		   "VALUES (" . join(',', map {"?"} @args) . ")";

	sql_command($dbh, $stmt, @vals);
	$dbh->commit();
	return undef;
}

sub modify_host {
	my ($self, $host, %args) = @_;
	my $dbh = $self->{dbh};

	require_scalar("modify_host <host> [args]", 1, $host);

	internal_modify_host($self, $host, %args);
	$dbh->commit();

	return undef;
}

sub internal_modify_host {
	my ($self, $host, %args) = @_;
	my $dbh = $self->{dbh};

	#
	# XXXrcd: validate %args

	my @setv;
	my @bindv;

	my $set_label = 0;
	my @add_label;
	my @del_label;

	for my $arg (keys %args) {
		if ($arg eq 'label') {
			if (ref($args{$arg}) ne 'ARRAY') {
				die [503, "label takes an array ref"];
			}
			if (@add_label) {
				die [503, "Can't both set label and add label"];
			}
			$set_label = 1;
			push(@add_label, @{$args{$arg}});
			next;
		}

		if ($arg eq 'add_label') {
			if (ref($args{$arg}) ne 'ARRAY') {
				die [503, "add_label takes an array ref"];
			}
			push(@add_label, @{$args{$arg}});
			next;
		}

		if ($arg eq 'del_label') {
			if (ref($args{$arg}) ne 'ARRAY') {
				die [503, "del_label takes an array ref"];
			}
			push(@del_label, @{$args{$arg}});
			next;
		}

		if (!grep { $_ eq $arg } (@{$field_desc{hosts}->{fields}})) {
			die [503, "Unrecognised field: $arg"];
		}

		push(@setv, "$arg = ?");
		push(@bindv, $args{$arg});
	}

	if (@add_label || @del_label) {
		die [503, "Can't both add/del label and set label"];
	}

	if (@setv) {
		my $stmt = "UPDATE hosts SET " . join(',', @setv) .
		    " WHERE name = ?";
		sql_command($dbh, $stmt, @bindv, $host);
	}

	if ($set_label) {
		my $stmt = "DELETE FROM host_labels WHERE host = ?";
		sql_command($dbh, $stmt, $host);
	}

	for my $label (@add_label) {
		my $stmt = "INSERT INTO host_labels(host, label) VALUES (?, ?)";
		sql_command($dbh, $stmt, $host, $label);
	}

	if (@del_label) {
		my $stmt = qq{
				DELETE FROM host_labels
				WHERE host = ? AND ( } .
		    join(' OR ', map { "label = ?" } (@del_label)) . ")";
		sql_command($dbh, $stmt, $host, @del_label);
	}

	return undef;
}

sub KHARON_ACL_query_host { return 1; }

sub query_host {
	my ($self, %query) = @_;
	my $dbh = $self->{dbh};

	return generic_query($dbh, \%field_desc, 'hosts', [keys %query],
	    %query);
}

sub bind_host {
	my ($self, $host, $binding) = @_;
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	require_scalar("bind_host <host> <binding>", 1, $host);
	require_fqprinc($ctx, "bind_host <host> <binding>", 1, $binding);

	my $stmt = "UPDATE hosts SET bootbinding = ? WHERE name = ?";
	my $sth  = sql_command($dbh, $stmt, $binding, $host);

	if ($sth->rows != 1) {
		$dbh->rollback();
		die [500, "Host $host does not exist."];
	}

	$dbh->commit();

	# XXXrcd: we must check if we successfully bound the host.
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

		sql_command($dbh, "DELETE FROM hosts WHERE "
		    . join(' OR ', map {"name=?"} @curhosts), @curhosts);

		#
		# XXXrcd: error handling and all that.
	}

	$dbh->commit();

	return;
}

sub insert_hostmap {
	my ($self, @hosts) = @_;
	my $dbh = $self->{dbh};

	require_scalar("insert_hostmap <logical> <physical>", 1, $hosts[0]);
	require_scalar("insert_hostmap <logical> <physical>", 2, $hosts[1]);

	@hosts = map { lc($_) } @hosts;

	my $stmt = "INSERT INTO hostmap (logical, physical) VALUES (?, ?)";

	sql_command($dbh, $stmt, @hosts);

	$dbh->commit();

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

sub remove_hostmap {
	my ($self, @hosts) = @_;
	my $dbh = $self->{dbh};

	require_scalar("remove_hostmap <logical> <physical>", 1, $hosts[0]);
	require_scalar("remove_hostmap <logical> <physical>", 2, $hosts[1]);

	@hosts = map { lc($_) } @hosts;

	my $stmt = "DELETE FROM hostmap WHERE logical = ? AND physical = ?";

	sql_command($dbh, $stmt, @hosts);

	$dbh->commit();

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
	my $dbh = $self->{dbh};
	my $stmt = "SELECT realm FROM hosts WHERE name = ?";
	my $sth = eval { $dbh->prepare($stmt); };
	my $deny;

	if (!defined($sth)) {
		$dbh->rollback();
		die [510, "SQL ERROR: ".$dbh->errstr];
	}

	my $hrealm;
	$sth->bind_columns(\$hrealm);
	eval {
		for my $host (@hosts) {
			$sth->execute($host);
			if (! $sth->fetch) {
				_deny_nohost($host);
			}
			if (!grep($_ eq $hrealm, @$realms)) {
				_deny_xrealm($princ, $prealm, $host, $hrealm);
			}
		}
	};
	$deny = $@ if $@;
	$deny = [510, "SQL ERROR: ".$sth->errstr] if ($sth->err);

	if ($deny) {
		$dbh->rollback();
		die $deny;
	}
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

	for my $host (map {lc($_)} @hosts) {

		my $stmt = qq{
			INSERT INTO prestashed (principal, host) VALUES (?, ?)
		};

		my ($sth, $str) = sql_command($dbh, $stmt, $princ, $host);

#		if (!$sth || ($str =~ /unique/)) {
#			die [500, 'tickets already configured for prestash'];
#		}

		($sth, $str) = sql_command($dbh,
			"SELECT count(principal) FROM prestashed" .
			" WHERE host = ?", $host);

		my ($count) = $sth->fetchrow_array();
		die [500, 'limit exceeded: you can only prestash ' .
			  MAX_TIX_PER_HOST .
			  ' tickets on a single host or service address']
			if ($count > MAX_TIX_PER_HOST);
	}

	$dbh->commit();

	return undef;
}

sub KHARON_ACL_query_ticket { return 1; }

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

	my $sth = sql_command($dbh, $stmt, @bindv);

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
	my ($self, $cmd, @predicate) = @_;
	my $ctx = $self->{ctx};

	my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $self->{client});

	return 0	if $sprinc[1] ne 'host';
	return 0	if $sprinc[2] ne $predicate[0];

	# Now, we must also check to ensure that the client is
	# in the correct realm for the host that we have in our DB.

	my $host = $self->query_host(name=>$predicate[0]);
	if (!defined($host) || $host->{realm} ne $sprinc[0]) {
		return 0;
	}
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

	if (!defined($host)) {
		my @sprinc = Krb5Admin::C::krb5_parse_name($ctx,
		    $self->{client});

		if ($sprinc[1] eq 'host') {
			$host = $sprinc[2];
		}
	}

	my $tix = $self->query_ticket(host => $host, realm => $realm,
	    expand => 1);

	# XXXrcd: make configurable...
	return { map {
		$_ => Krb5Admin::C::mint_ticket($ctx, $hndl, $_, 7 * 3600 * 24,
		    0);
	} @$tix };
}

sub remove_ticket {
	my ($self, $princ, @hosts) = @_;
	my $usage = "remove_ticket <princ> <host> [<host> ...]";
	my $ctx = $self->{ctx};
	my $dbh = $self->{dbh};

	require_fqprinc($ctx, $usage, 1, $princ);
	require_scalar("remove_ticket <princ> <host> [<host> ...]", 2,
	    $hosts[0]);

	my $host;
	my $i = 3;
	for $host (@hosts) {
		require_scalar("remove_ticket <princ> <host> [<host> ...]",
		    $i++, $host);
	}

	while (@hosts) {
		my @curhosts = splice(@hosts, 0, 500);

		sql_command($dbh, qq{
			DELETE FROM prestashed WHERE principal = ? AND (
		    } . join(' OR ', map {"host=?"} @curhosts) . qq{
			)
		    }, $princ, @curhosts);

		#
		# XXXrcd: error handling and all that.
	}

	$dbh->commit();

	return undef;
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

L<Krb5Admin>
