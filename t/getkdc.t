#!/usr/pkg/bin/perl
#

use Test::More tests => 2;

use Sys::Hostname;

use Krb5Admin::C;

use strict;
use warnings;

sub compare_kdcs_to_expected {
	my %kdcs;

	for my $kdc (@_) {
		$kdcs{$kdc} = 1;
	}

	for (my $i = 1; $i < 10; $i++) {
		my $kdc = "kdc$i.test.realm";

		if (!exists($kdcs{$kdc})) {
			return 0;
		}

		delete $kdcs{$kdc};
	}

	if (keys %kdcs) {
		return 0;
	}

	return 1;
}

$ENV{KRB5_CONFIG} = './t/krb5.conf';

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $realm = Krb5Admin::C::krb5_get_realm($ctx);

my $expected = [sort (hostname(), map { "kdc$_.test.realm" } (1..9))];

my $kdcs;

$kdcs  = Krb5Admin::C::krb5_get_kdcs($ctx, '');
is_deeply([sort @$kdcs], $expected, "krb5_get_kdcs() without realm");

$kdcs  = Krb5Admin::C::krb5_get_kdcs($ctx, $realm);
is_deeply([sort @$kdcs], $expected, "krb5_get_kdcs() with realm");

exit 0;
