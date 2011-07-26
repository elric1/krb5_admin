# 
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::KerberosDB;

use Sys::Syslog;

use Krb5Admin::Utils qw/reverse_the host_list/;
use Krb5Admin::C;
use Kharon::Entitlement::ACLFile;
use Kharon::Entitlement::Equals;

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
	ACL_FILE		=> '/etc/krb5/krb5_admin.acl',
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

sub require_hashref {
	my ($usage, $argnum, $arg) = @_;

	die [503, "Syntax error: arg $argnum undefined\nusage: $usage"]
	    if !defined($arg);
	die [503, "Syntax error: arg $argnum not a hashref\nusage: $usage"]
	    if ref($arg) ne 'HASH';
}

#
# check_acl is expected to throw an exception with a reason if the access
# is denied.  Otherwise it will simply return undef.  This function needs
# to be seriously abstracted but this will take some level of effort.

sub check_acl {
	my ($self, $verb, @predicate) = @_;
	my $subject = $self->{client};
	my $acl = $self->{acl};
	my $denied;

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
		die [502, "Modification of $predicate[0] prohibited."];
	}

	return if $self->{local};

	#
	# First we provide an Kharon file based entitlement system which
	# precedes all of the special processing...

	return if $acl->check($verb);

        #
        # We also need creds.  This is mainly for my use running this
        # by hand, but be that as it may...

        if (!defined($subject)) {
                die [502, "Permission denied: not an authenticated user"];
        }

	#
	# More interesting sitebased rules can go here.  Only put rules
	# here which would be difficult to encode using Kharon's entitlement
	# framework.

	my $ctx = $self->{ctx};
        my @sprinc = Krb5Admin::C::krb5_parse_name($ctx, $subject);
        my @pprinc = Krb5Admin::C::krb5_parse_name($ctx, $predicate[0]);

	#
	# The remaining logic is for krb5_keytab and is only to be used
	# for ``create'', ``fetch'', or ``change'':

	#
	# XXXrcd: right now check_acl:
	#
	#       1.  assumes that $predicate[0] is the object,
	#
	#       2.  doesn't differentiate between verbs,
	#
	#       3.  allows host/foo@REALM access to <service>/foo@REALM,

	if ($verb ne 'fetch' && $verb ne 'create' && $verb ne 'change') {
		die [502, "Permission denied"];
	}

	if (@sprinc != 3 || @pprinc != 3) {
		die [502, "Permission denied"];
	}

	if ($pprinc[1] eq 'host' && defined($self->{hostname})) {
		my @v;
		@v = grep { $_ eq $pprinc[2] } host_list($self->{hostname});

		return if @v == 1 && $sprinc[2] eq 'admin';

		$denied = "not an admin user" if $sprinc[2] ne 'admin';
		if ($#v != 0) {
			$denied  = "host does not match IP address";
			$denied .= " [" . $self->{hostname} . " not in " .

			$denied .= join(',', host_list($self->{hostname}));
			$denied .= "]";
		}
	} else {
		$denied = 'realm'       if $sprinc[0] ne $pprinc[0];
		$denied = 'host'        if $sprinc[1] ne 'host';
		$denied = 'instance'    if $sprinc[2] ne $pprinc[2];
		$denied = 'no admin'    if $pprinc[2] eq 'admin';
		$denied = 'no root'     if $pprinc[2] eq 'root';
	}

	if (defined($denied)) {
		syslog('err', "%s", $subject . " failed check_acl for " .
		    $predicate[0] . "[$denied]");
		die [502, "Permission denied [$denied] for $subject"];
	}
}

sub new {
	my ($isa, %args) = @_;
	my %self;

	#
	# set defaults:

	my $acl_file = ACL_FILE;
	my $dbname;

	$acl_file = $args{acl_file}	if defined($args{acl_file});
	$dbname = $args{dbname}		if defined($args{dbname});

	my $subacls = Kharon::Entitlement::Equals->new();
	my $acl = Kharon::Entitlement::ACLFile->new(filename => $acl_file,
	    subobject => $subacls);
	$acl->set_creds($args{client});

	my $ctx = Krb5Admin::C::krb5_init_context();

	$self{local}	= $args{local};
	$self{client}   = $args{client};
	$self{addr}     = $args{addr};
	$self{hostname} = reverse_the($args{addr});
	$self{ctx}      = $ctx;
	$self{hndl}     = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, $dbname);
	$self{acl}	= $acl;

	$self{local}	= 0			if !defined($self{local});
	$self{client}	= "LOCAL_MODIFICATION"	if $self{local};

	bless(\%self, $isa);
}

sub master { undef; }

sub create {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("create <princ>", 1, $name);
	$self->check_acl('create', $name);
	Krb5Admin::C::krb5_createkey($ctx, $hndl, $name);
	syslog('info', "%s", $self->{client} . " created $name");
	{ created => $name };
}

sub create_user {
	my ($self, $name, $passwd) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("create_user <princ>", 1, $name);
	die "malformed name"	if $name =~ m,[^-A-Za-z0-9_/@.],;

	$self->check_acl('create_user', $name);
	my $ret = Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $name,
			policy		=> 'strong_human',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR |
					   REQUIRES_PWCHANGE,
		}, $passwd);
	syslog('info', "%s", $self->{client} . " created $name");
	$ret;
}

sub listpols {
	my ($self, $exp) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	$self->check_acl('list', $exp);
	my $ret = Krb5Admin::C::krb5_list_pols($ctx, $hndl, $exp);
	@$ret;
}

sub list {
	my ($self, $exp) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	$self->check_acl('list', $exp);
	my $ret = Krb5Admin::C::krb5_list_princs($ctx, $hndl, $exp);
	@$ret;
}

sub fetch {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};
	my $tmp;
	my @ret;

	require_scalar("fetch <princ>", 1, $name);
	$self->check_acl('fetch', $name);
	syslog('info', "%s", $self->{client} . " fetched $name");
	Krb5Admin::C::krb5_getkey($ctx, $hndl, $name);
}

sub change {
	my ($self, $name, $kvno, $keys) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("change <princ>", 1, $name);
	$self->check_acl('change', $name);
	Krb5Admin::C::krb5_setkey($ctx, $hndl, $name, $kvno, $keys);
	{ setkey => $name };
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

	$self->check_acl('change_passwd', $name);

	if (defined($passwd)) {
		Krb5Admin::C::krb5_setpass($ctx, $hndl, $name, $passwd);
	} else {
		$passwd = Krb5Admin::C::krb5_randpass($ctx, $hndl, $name);
	}

	return $passwd if !defined($opt);

	if ($opt eq '+needchange') {
		$self->internal_modify($name, {attributes => [ $opt ]});
	}

	return $passwd;
}

sub modify {
	my ($self, $name, $mods) = @_;

	require_scalar("modify <princ> {mods}", 1, $name);
	require_hashref("modify <princ> {mods}", 2, $mods);
	$self->check_acl('modify', $name);
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

sub mquery {
	my ($self, @args) = @_;

	$self->check_acl('mquery', @args);

	@args = ('*')	if scalar(@args) == 0;	# empty args is a wildcard.

	my @ret;
	for my $i (map { $self->list($_) } (@args)) {
		# XXXrcd: we ignore errors under the presumption that
		#         the principal may have been deleted in the
		#         middle of the operation...

		eval { push(@ret, $self->query($i)); };
	}
	@ret;
}

sub query {
	my ($self, $name) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("query <princ>", 1, $name);
	$self->check_acl('query', $name);
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
	$self->check_acl('enable', $princ);
	$self->internal_modify($princ, { attributes => ['+allow_tix'] });
}

sub disable {
	my ($self, $princ) = @_;
	my $ctx  = $self->{ctx};
	my $hndl = $self->{hndl};

	require_scalar("disable <princ>", 1, $princ);
	$self->check_acl('disable', $princ);

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
	$self->check_acl('remove', $name);
	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $name);
	return undef;
}

1;
