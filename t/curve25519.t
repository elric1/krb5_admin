#!/usr/pkg/bin/perl
#

use Test::More tests => 1;

use Data::Dumper;

use Krb5Admin::C;

use strict;
use warnings;

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
