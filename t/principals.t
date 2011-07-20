#!/usr/pkg/bin/perl
#

#
# XXXrcd: these tests only really test the interfaces and to some degree
#         that the functions appears to be working in terms of the other
#         functions.  They _should_ also test that passwds actually work,
#         but they do not yet.  That would require firing up a KDC which
#         we'll eventually do.

use Test::More tests => 9;

use Krb5Admin::C;

use tests::utils qw{compare_array compare_hash compare};

use strict;
use warnings;

use constant {
	DISALLOW_POSTDATED      => 0x00000001,
	DISALLOW_FORWARDABLE    => 0x00000002,
	DISALLOW_TGT_BASED      => 0x00000004,
	DISALLOW_RENEWABLE      => 0x00000008,
	DISALLOW_PROXIABLE      => 0x00000010,
	DISALLOW_DUP_SKEY       => 0x00000020,
	DISALLOW_ALL_TIX        => 0x00000040,
	REQUIRES_PRE_AUTH       => 0x00000080,
	REQUIRES_HW_AUTH        => 0x00000100,
	REQUIRES_PWCHANGE       => 0x00000200,
	UNKNOWN_0x00000400      => 0x00000400,
	UNKNOWN_0x00000800      => 0x00000800,
	DISALLOW_SVR            => 0x00001000,
	PWCHANGE_SERVICE        => 0x00002000,
	SUPPORT_DESMD5          => 0x00004000,
	NEW_PRINC               => 0x00008000,
	ACL_FILE                => '/etc/krb5/krb5_admin.acl',
};

$ENV{KRB5_CONFIG} = 'FILE:./t/krb5.conf';

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, undef);

my $princ  = 'testprinc';
my $sprinc = 'testprinc/foodlebrotz.imrryr.org';

# make sure that the princs are not here:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ); };
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $sprinc); };

eval {
	Krb5Admin::C::krb5_createkey($ctx, $hndl, $sprinc);
	Krb5Admin::C::krb5_getkey($ctx, $hndl, $sprinc);
	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $sprinc);
};

ok(!$@, "Create, fetch, and delete a service principal") or diag($@);

# just make sure:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $sprinc); };

eval {
	Krb5Admin::C::krb5_createkey($ctx, $hndl, $sprinc);
	Krb5Admin::C::krb5_setkey($ctx, $hndl, $sprinc, 3,
	   [{enctype => 17, key => '0123456789abcdef'}]);

	my @keys = Krb5Admin::C::krb5_getkey($ctx, $hndl, $sprinc);

	@keys = grep { $_->{kvno} == 3 } @keys;

	if ($keys[0]->{enctype} != 1 || $keys[0]->{key} ne 'TheKey!!') {
		die "New key failed to match \"TheKey!!\"";
	}

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $sprinc);
};

ok(!$@, "Create, set, test, and delete a service principal") or diag($@);

# just make sure:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $sprinc); };

eval {
	Krb5Admin::C::krb5_createkey($ctx, $hndl, $sprinc);
	Krb5Admin::C::krb5_randkey($ctx, $hndl, $sprinc);

	my @keys = Krb5Admin::C::krb5_getkey($ctx, $hndl, $sprinc);

	@keys = grep { $_->{kvno} == 3 } @keys;

	if (@keys == 0) {
		die "Looks like the key didn't change...";
	}

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $sprinc);
};

ok(!$@, "Create, randkey, test, and delete a service principal") or diag($@);

# just make sure:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $sprinc); };

eval {
	my ($passwd, $q);

	$passwd = Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $princ,
			policy		=> 'default',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR,
		}, undef);

	$q = Krb5Admin::C::krb5_query_princ($ctx, $hndl, $princ);
	if ($q->{attributes} != (REQUIRES_PRE_AUTH | DISALLOW_SVR)) {
		die "Created princ's attrs not +requires_preauth,-allow_tix";
	}

	Krb5Admin::C::krb5_modprinc($ctx, $hndl, {
			principal	=> $princ,
			attributes	=> REQUIRES_PRE_AUTH,
		});

	$q = Krb5Admin::C::krb5_query_princ($ctx, $hndl, $princ);
	if ($q->{attributes} != REQUIRES_PRE_AUTH) {
		die "Created princ's attrs not +requires_preauth";
	}

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ);
};

ok(!$@, "Create, modify and delete a user principal") or diag($@);

# just make sure:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ); };

eval {
	my $passwd = "Ff1passThePolicy--%!";

	Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $princ,
			policy		=> 'default',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR,
		}, $passwd);

	#
	# XXXrcd: test the passwd was appropriately set!

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ);
};

ok(!$@, "Create with passwd, and delete a user principal") or diag($@);

# just make sure:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ); };

eval {
	my ($passwd);

	$passwd = Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $princ,
			policy		=> 'default',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR,
		}, undef);

	$passwd = 'Ff1passThePolicy--%!';
	$passwd = Krb5Admin::C::krb5_setpass($ctx, $hndl, $princ, $passwd);

	#
	# XXXrcd: test the passwd was appropriately set!

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ);
};

ok(!$@, "Create, setpass and delete a user principal") or diag($@);

# just make sure:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ); };

eval {
	my ($passwd);

	$passwd = Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $princ,
			policy		=> 'default',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR,
		}, undef);

	$passwd = Krb5Admin::C::krb5_randpass($ctx, $hndl, $princ);

	#
	# XXXrcd: test the passwd was appropriately set!

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ);
};

ok(!$@, "Create, randpass and delete a user principal") or diag($@);

# just make sure:
eval { Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ); };

my @princs = sort(map { $princ . $_ . '@IMRRYR.ORG' } (0..20));
my $results;
eval {
	my ($passwd, $q);

	for my $p (@princs) {
		$passwd = Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
			principal	=> $p,
			policy		=> 'default',
			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR,
			}, undef);
	}

	$results = Krb5Admin::C::krb5_list_princs($ctx, $hndl, $princ . "*");

	for my $p (@princs) {
		Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $p);
	}
};

ok(!$@, "Create 21 principals, list and delete them") or diag($@);
is_deeply([sort @$results], [sort @princs],
    "Create 21 principals, list and delete them");

eval {
	for my $p (@princs) {
		Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $p);
	}
};

exit (0);
