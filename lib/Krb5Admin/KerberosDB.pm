# 
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::KerberosDB;

use DBI;
use Sys::Hostname;
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

	return if defined($self->{local}) && $self->{local};

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

	if ($verb eq 'fetch_tickets') {
		die [502, "Permission denied"]	if $sprinc[1] ne 'host';
		die [502, "Permission denied"]	if $sprinc[2] ne $predicate[0];

		# Now, we must also check to ensure that the client is
		# in the correct realm for the host that we have in our DB.

		my $host = $self->query_host(name=>$predicate[0]);
		if (!defined($host) || $host->{realm} ne $sprinc[0]) {
			die [502, "Permission denied"];
		}
		# The request is authorised.
		return;
        }

	my @pprinc;
	if (defined($predicate[0])) {
		@pprinc = Krb5Admin::C::krb5_parse_name($ctx, $predicate[0]);
	}

	#
	# The remaining logic is for krb5_keytab and is only to be used
	# for ``create'', ``fetch'', or ``change'':
	#
	# We allow host/foo@REALM to access <service>/foo@REALM for any
	# <service>.

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
		my @xbs = ();
		if (ref($self->{xrealm_bootstrap}) eq 'HASH' &&
		    ref($self->{xrealm_bootstrap}->{$sprinc[0]}) eq 'ARRAY') {
			@xbs = @{$self->{xrealm_bootstrap}->{$sprinc[0]}};
		}

		if ($sprinc[0] ne $pprinc[0] && ($pprinc[1] ne 'host' ||
		    !grep { $pprinc[0] eq $_ } @xbs)) {
			$denied = 'realm';
		}
		$denied = 'host'	if $sprinc[1] ne 'host';
		$denied = 'instance'	if $sprinc[2] ne $pprinc[2];
		$denied = 'no admin'	if $pprinc[2] eq 'admin';
		$denied = 'no root'	if $pprinc[2] eq 'root';
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
	my $sqlite   = SQL_DB_FILE;
	my $dbname;

	$acl_file = $args{acl_file}	if defined($args{acl_file});
	$dbname   = $args{dbname}	if defined($args{dbname});
	$sqlite   = $args{sqlite}	if defined($args{sqlite});

	# initialize our database handle
	my $dbh = DBI->connect("dbi:SQLite:$sqlite", "", "",
	    {RaiseError => 1, PrintError => 0, AutoCommit => 1});
	die "Could not open database " . DBI::errstr if !defined($dbh);
	$dbh->do("PRAGMA foreign_keys = ON");
	$dbh->do("PRAGMA journal_mode = WAL");
	$dbh->{AutoCommit} = 0;

	my $subacls = Kharon::Entitlement::Equals->new();
	my $acl = Kharon::Entitlement::ACLFile->new(filename => $acl_file,
	    subobject => $subacls);
	$acl->set_creds($args{client});

	my $ctx = Krb5Admin::C::krb5_init_context();

	$self{debug}	= $args{debug};
	$self{local}	= $args{local};
	$self{client}	= $args{client};
	$self{addr}	= $args{addr};
	$self{hostname} = reverse_the($args{addr});
	$self{ctx}	= $ctx;
	$self{hndl}	= Krb5Admin::C::krb5_get_kadm5_hndl($ctx, $dbname);
	$self{acl}	= $acl;
	$self{dbh}	= $dbh;

	$self{local}	= 0			if !defined($self{local});
	$self{client}	= "LOCAL_MODIFICATION"	if $self{local};
	$self{debug}	= 0			if !defined($self{debug});

	$self{xrealm_bootstrap} = $args{xrealm_bootstrap};

	bless(\%self, $isa);
}

sub DESTROY {
	my ($self) = @_;

	if (defined($self->{dbh})) {
		$self->{dbh}->disconnect();
		undef($self->{dbh});
	}
}

sub init_db {
	my ($self) = @_;
	my $dbh = $self->{dbh};

	$dbh->{AutoCommit} = 1;

	#
	# XXXrcd: the hosts structure should likely point to a list of
	#	  addresses or something more like that...

	$dbh->do(qq{
		CREATE TABLE hosts (
			name		VARCHAR NOT NULL PRIMARY KEY,
			realm		VARCHAR NOT NULL,
			ip_addr		VARCHAR
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

	$dbh->{AutoCommit} = 1;
	$dbh->do('DROP TABLE IF EXISTS prestashed');
	$dbh->do('DROP TABLE IF EXISTS hostmap');
	$dbh->do('DROP TABLE IF EXISTS hosts');
	$dbh->{AutoCommit} = 0;
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
			policy		=> 'default',
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
		Krb5Admin::C::krb5_setpass($ctx, $hndl, $name, [], $passwd);
	} else {
		$passwd = Krb5Admin::C::krb5_randpass($ctx, $hndl, $name, []);
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
		#	  the principal may have been deleted in the
		#	  middle of the operation...

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

sub _sql_command {
	my ($self, $stmt, @values) = @_;
	my $dbh = $self->{dbh};

	print STDERR "SQL: $stmt\n"	if $self->{debug};

	my $sth;
	eval {
		$sth = $dbh->prepare($stmt);

		if (!$sth) {
			die [510, "SQL ERROR: ".$dbh->errstr.", ".$dbh->err];
		}

		$sth->execute(@values);
	};

	if ($@) {
		print STDERR "Rollback...\n"	if $self->{debug};
		$dbh->rollback();
		die $@;
	}
	return $sth;
}
our %field_desc = (
	hosts		=> {
		pkey		=> 'name',
		uniq		=> [qw/name ip_addr/],
		fields		=> [qw/name realm ip_addr/],
		wontgrow	=> 0,
	},
	hostmap		=> {
		pkey		=> undef,
		uniq		=> [],
		fields		=> [qw/logical physical/],
		wontgrow	=> 1,
	},
);

sub generic_query {
	my ($self, $table, %query) = @_;

	#
	# XXXrcd: validation should be done.

	my @where;
	my @bindv;

	my $key_field = $field_desc{$table}->{fields}->[0];
	my %fields = map { $_ => 1 } @{$field_desc{$table}->{fields}};

	my %tmpquery = %query;
	for my $field (keys %fields) {
		next if !exists($query{$field});

		push(@where, "$field = ?");
		push(@bindv, $query{$field});
		delete $fields{$field};
		delete $tmpquery{$field};
	}

	if (scalar(keys %tmpquery) > 0) {
		die [500, "Fields: " . join(',', keys %tmpquery) .
		    " do not exit in $table table"];
	}

	my $where = join( ' AND ', @where );
	$where = "WHERE $where" if length($where) > 0;

	my $fields;
	if (scalar(keys %fields) > 0) {
		my %tmp_fields = %fields;

		$tmp_fields{$key_field} = 1;
		$fields = join(',', keys %tmp_fields);
	} else {
		$fields = "COUNT($key_field)";
	}

	my $stmt = "SELECT $fields FROM $table $where";

	my $sth = $self->_sql_command($stmt, @bindv);

	#
	# We now reformat the result to be comprised of the simplest
	# data structure we can imagine that represents the query
	# results:

	if (scalar(keys %fields) == 0) {
		return $sth->fetch()->[0];
	}

	my $results = $sth->fetchall_arrayref({});

	my $ret;
	if (scalar(keys %fields) == 1 && $field_desc{$table}->{wontgrow}) {
		$fields = join('', keys %fields);
		for my $result (@$results) {
			push(@$ret, $result->{$fields});
		}

		return $ret;
	}

	my $is_uniq = grep {$key_field eq $_} @{$field_desc{$table}->{uniq}};

	my $single_result = 0;
	if (scalar(keys %fields) == 2 && $field_desc{$table}->{wontgrow}) {
		$single_result = 1;
	}

	for my $result (@$results) {
		my $key = $result->{$key_field};

		delete $result->{$key_field};

		if ($single_result) {
			my $result_key = join('', keys %$result);
			$result = $result->{$result_key};
		}

		if ($is_uniq) {
			$ret->{$key} = $result;
		} else {
			push(@{$ret->{$key}}, $result);
		}
	}

	if ($is_uniq && grep {$key_field eq $_} (keys %query)) {
		#
		# this should mean that we get only a single
		# element in our resultant hashref.

		return $ret->{$query{$key_field}};
	}

	return $ret;
}

sub create_host {
	my ($self, $host, %args) = @_;

	require_scalar("create_host <host> [args]", 1, $host);

	# XXXrcd: more checking should be done.

	$self->check_acl('create_host', $host, %args);

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

	$self->_sql_command($stmt, @vals);
	$self->{dbh}->commit();
	return undef;
}

sub query_host {
	my ($self, %query) = @_;

	return $self->generic_query('hosts', %query);
}

sub remove_host {
	my ($self, @hosts) = @_;

	require_scalar("remove_host <host> [<host> ...]", 1, $hosts[0]);

	my $i = 2;
	for my $host (@hosts) {
		require_scalar("remove_host <princ> <host> [<host> ...]",
		    $i++, $host);
	}

	$self->check_acl('remove_host', @hosts);

	while (@hosts) {
		my @curhosts = splice(@hosts, 0, 500);

		$self->_sql_command("DELETE FROM hosts WHERE "
		    . join(' OR ', map {"name=?"} @curhosts), @curhosts);

		#
		# XXXrcd: error handling and all that.
	}

	$self->{dbh}->commit();

	return;
}

sub insert_hostmap {
	my ($self, @hosts) = @_;

	require_scalar("insert_hostmap <logical> <physical>", 1, $hosts[0]);
	require_scalar("insert_hostmap <logical> <physical>", 2, $hosts[1]);

	@hosts = map { lc($_) } @hosts;

	$self->check_acl('insert_hostmap', @hosts);

	my $stmt = "INSERT INTO hostmap (logical, physical) VALUES (?, ?)";

	$self->_sql_command($stmt, @hosts);

	$self->{dbh}->commit();

	return undef;
}

sub query_hostmap {
	my ($self, $host) = @_;

	$self->check_acl('query_hostmap', $host);

	if (defined($host)) {
		return $self->generic_query('hostmap', logical => $host);
	}

	return $self->generic_query('hostmap');
}

sub remove_hostmap {
	my ($self, @hosts) = @_;

	require_scalar("remove_hostmap <logical> <physical>", 1, $hosts[0]);
	require_scalar("remove_hostmap <logical> <physical>", 2, $hosts[1]);

	@hosts = map { lc($_) } @hosts;

	$self->check_acl('remove_hostmap', @hosts);

	my $stmt = "DELETE FROM hostmap WHERE logical = ? AND physical = ?";

	$self->_sql_command($stmt, @hosts);

	$self->{dbh}->commit();

	return;
}

sub insert_ticket {
	my ($self, $princ, @hosts) = @_;

	require_scalar("insert_ticket <princ> <host> [<host> ...]", 1, $princ);
	require_scalar("insert_ticket <princ> <host> [<host> ...]", 2,
	    $hosts[0]);

	my $host;
	my $i = 3;
	for $host (@hosts) {
		require_scalar("insert_ticket <princ> <host> [<host> ...]",
		    $i++, $host);
	}

	$self->check_acl('insert_ticket', $princ, @hosts);

	for $host (map {lc($_)} @hosts) {
		# XXXrcd: validate_hostname($host);

		my $stmt = qq{
			INSERT INTO prestashed (principal, host) VALUES (?, ?)
		};

		my ($sth, $str) = $self->_sql_command($stmt, $princ, $host);

#		if (!$sth || ($str =~ /unique/)) {
#			die [500, 'tickets already configured for prestash'];
#		}

		($sth, $str) = $self->_sql_command(
			"SELECT count(principal) FROM prestashed" .
			" WHERE host = ?", $host);

		my ($count) = $sth->fetchrow_array();
		die [500, 'limit exceeded: you can only prestash ' .
			  MAX_TIX_PER_HOST .
			  ' tickets on a single host or service address']
			if ($count > MAX_TIX_PER_HOST);
	}

	$self->{dbh}->commit();

	return undef;
}

sub query_ticket {
	my ($self, %query) = @_;

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

	my $sth = $self->_sql_command($stmt, @bindv);

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

sub fetch_tickets {
	my ($self, $host) = @_;
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

	$self->check_acl('fetch_tickets', $host);

	my $tix = $self->query_ticket(host => $host, expand => 1);

	# XXXrcd: make configurable...
	return { map {
		$_ => Krb5Admin::C::mint_ticket($ctx, $hndl, $_, 3600 * 24,
		    3600 * 24 * 7 )
	} @$tix };
}

sub remove_ticket {
	my ($self, $princ, @hosts) = @_;

	require_scalar("remove_ticket <princ> <host> [<host> ...]", 1, $princ);
	require_scalar("remove_ticket <princ> <host> [<host> ...]", 2,
	    $hosts[0]);

	my $host;
	my $i = 3;
	for $host (@hosts) {
		require_scalar("remove_ticket <princ> <host> [<host> ...]",
		    $i++, $host);
	}

	$self->check_acl('remove_ticket', $princ, @hosts);

	while (@hosts) {
		my @curhosts = splice(@hosts, 0, 500);

		$self->_sql_command(qq{
			DELETE FROM prestashed WHERE principal = ? AND (
		    } . join(' OR ', map {"host=?"} @curhosts) . qq{
			)
		    }, $princ, @curhosts);

		#
		# XXXrcd: error handling and all that.
	}

	$self->{dbh}->commit();

	return undef;
}

1;
