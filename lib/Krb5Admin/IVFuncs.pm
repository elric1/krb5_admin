package Krb5Admin::IVFuncs;
use Exporter;

@ISA = qw(Exporter);
@EXPORT = qw{	require_scalar require_scalars require_localrealm
		require_princ canonicalise_fqprinc require_fqprinc
		require_hostname require_hostnames require_hashref
		require_username require_usernames
		require_number
	    };

use Krb5Admin::C;
use Krb5Admin::Utils qw/unparse_princ/;

sub require_many {
	my ($f, $usage, $argnum, @args) = @_;

	my $i = $argnum;
	for my $arg (@args) {
		&$f($usage, $i++, $arg);
	}

	return;
}


sub require_scalars	{ require_many(\&require_scalar, @_) }
sub require_hostnames	{ require_many(\&require_hostname, @_) }
sub require_usernames	{ require_many(\&require_username, @_) }

sub require_scalar {
	my ($usage, $argnum, $arg) = @_;

	die [503, "Syntax error: arg $argnum undefined\nusage: $usage"]
	    if !defined($arg);
	die [503, "Syntax error: arg $argnum not a scalar\nusage: $usage"]
	    if ref($arg) ne '';
	return;
}

sub require_number {
	my ($usage, $argnum, $arg) = @_;

	require_scalar($usage, $argnum, $arg);
	die [503, "Syntax error: arg $argnum not a number\nusage: $usage"]
	    if $arg =~ /[^0-9]/o;
	return;
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
	return;
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
	return;
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
	return;
}

sub require_hostname {
	my ($usage, $argnum, $host) = @_;

	require_scalar(@_);
	if ($host !~
	    qr{^([a-z\d]((-?[a-z\d]+)*)\.)+([a-z\d]((-?[a-z\d]+)*))$}oi) {
		die [503, "Syntax error: arg $argnum (\"$host\") must be a " .
		    "valid hostname\nusage: $usage"];
	}

	return;
}

sub require_hashref {
	my ($usage, $argnum, $arg) = @_;

	die [503, "Syntax error: arg $argnum undefined\nusage: $usage"]
	    if !defined($arg);
	die [503, "Syntax error: arg $argnum not a hashref\nusage: $usage"]
	    if ref($arg) ne 'HASH';
	return;
}

sub require_username {
	my ($usage, $argnum, $user) = @_;

	require_scalar(@_);
	if ($user !~ m,^[a-z][a-z0-9]+$,) {
		die [503, "Invalid input: arg $argnum must be a valid " .
		    "username with only alphanumeric characters\n" .
		    "usage: $usage"];
	}
	return;
}

1;
