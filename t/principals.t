#!/usr/pkg/bin/perl
#

use Test::More tests => 2;

use Krb5Admin::C;

use tests::utils qw{compare_array compare_hash compare};

use strict;
use warnings;

$ENV{KRB5_CONFIG} = 'FILE:./t/krb5.conf';

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, undef);

my $princ = 'testprinc/foodlebrotz';

eval {
	Krb5Admin::C::krb5_createkey($ctx, $hndl, $princ);
	Krb5Admin::C::krb5_getkey($ctx, $hndl, $princ);
	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ);
};

ok(!$@, "Create, fetch, and delete a service principal") or diag($@);

eval {
	Krb5Admin::C::krb5_createkey($ctx, $hndl, $princ);
	Krb5Admin::C::krb5_setkey($ctx, $hndl, $princ, 3,
	   [{enctype => 1, key => 'TheKey!!'}]);

	my @keys = Krb5Admin::C::krb5_getkey($ctx, $hndl, $princ);

	@keys = grep { $_->{kvno} == 3 } @keys;

	my $err;
	if ($keys[0]->{enctype} != 1 || $keys[0]->{key} ne 'TheKey!!') {
		$err = "New key failed to match \"TheKey!!\"";
	}

	Krb5Admin::C::krb5_deleteprinc($ctx, $hndl, $princ);

	die $err if defined($err);
};

ok(!$@, "Create, set, test, and delete a service principal") or diag($@);

exit (0);
