#!/usr/pkg/bin/perl
#

use Test::More tests => 2;

use Krb5Admin::C;

use strict;
use warnings;

sub mk_kte {
	my ($ctx, $realm, $kvno, $enctype) = @_;

	my $key = Krb5Admin::C::krb5_make_a_key($ctx, $enctype);

	$key->{princ} = 'elric/straasha.imrryr.org@IMRRYR.ORG';
	$key->{kvno}  = $kvno;

	return $key;
}

sub compare_keys {
	my ($lhs, $rhs) = @_;

	#
	# XXXrcd: as it turns out, the keytabs end up in the same order but
	#         we should not rely on that.  If this test fails, then we
	#         should first sort these lists into a stable order before
	#         calling compare().

	is_deeply($lhs, $rhs);
}

sub test_keytab {
	my ($ctx, $realm, $kt, $keys) = @_;

	unlink($kt);

	for my $key (@$keys) {
		Krb5Admin::C::write_kt($ctx, 'WRFILE:' . $kt, $key);
	}

	my @nkeys = Krb5Admin::C::read_kt($ctx, 'FILE:' . $kt);

	for my $key (@nkeys) {
		delete $key->{timestamp};
	}

	compare_keys($keys, \@nkeys);
	unlink($kt);
}

$ENV{KRB5_CONFIG} = 'FILE:./t/krb5.conf';

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, undef);
our $realm = Krb5Admin::C::krb5_get_realm($ctx);

my @keys;
my $kt = './test.foo.kt';

@keys = (mk_kte($ctx, $realm, 1, 17));

test_keytab($ctx, $realm, '/tmp/foo.kt', \@keys);

@keys = (
	mk_kte($ctx, $realm, 1, 17),
	mk_kte($ctx, $realm, 1, 18),
	mk_kte($ctx, $realm, 1, 23),
	mk_kte($ctx, $realm, 2, 17),
	mk_kte($ctx, $realm, 2, 18),
	mk_kte($ctx, $realm, 2, 23),
);

test_keytab($ctx, $realm, '/tmp/foo.kt', \@keys);

exit(0);
