#!/usr/pkg/bin/perl
#

use Test::More tests => 16;

use Data::Dumper;

use CURVE25519_NWAY;

use Krb5Admin::C;

use strict;
use warnings;

#
# First test the CURVE25519_NWAY interface which deprecates the older
# interface [which is still tested] below:

for my $num (2,3,4,5,6,7,8,16,31,32,65,100,128,200,256) {
	eval { CURVE25519_NWAY::test_nway($num); };
	ok(!$@, "$@");
}

#
# For the time being, we continue to test the old curve25519 functions
# but we expect to transition the existing usage to CURVE25519_NWAY and
# so these tests will [eventually] disappear.

$ENV{KRB5_CONFIG} = './t/krb5.conf';

my ($ctx, $alice, $bob, $shared1, $shared2);

eval {
	$ctx = Krb5Admin::C::krb5_init_context();

	$alice = Krb5Admin::C::curve25519_pass1($ctx);
	$bob   = Krb5Admin::C::curve25519_pass1($ctx);

	$shared1 = Krb5Admin::C::curve25519_pass2($ctx, $alice->[0], $bob->[1]);
	$shared2 = Krb5Admin::C::curve25519_pass2($ctx, $bob->[0], $alice->[1]);
};

ok(!$@ && $shared1 eq $shared2, "curve25519 agrees on keys");

diag($@)			if $@;
diag("$shared1 ne $shared2")	if $shared1 ne $shared2;

exit(0);
