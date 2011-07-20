#!/usr/pkg/bin/perl
#

use Test::More;

use Krb5Admin::C;

use strict;
use warnings;

$ENV{KRB5_CONFIG} = 'FILE:./t/krb5.conf';

my $ret;
my $ctx = Krb5Admin::C::krb5_init_context();

my @tests = (
	['a@BAR.COM', [ 'BAR.COM', 'a' ]],
	['user@EXAMPLE.COM', [ 'EXAMPLE.COM', 'user' ]],
	['elric@IMRRYR.ORG', [ 'IMRRYR.ORG', 'elric' ]],
	['elric@imrryr.org', [ 'imrryr.org', 'elric' ]],
	['elric/root@IMRRYR.ORG', [ 'IMRRYR.ORG', 'elric', 'root' ]],
	['yyrkoon/admin@IMRRYR.ORG', [ 'IMRRYR.ORG', 'yyrkoon', 'admin' ]],
	['host/arioch.imrryr.org@IMRRYR.ORG',
	    [ 'IMRRYR.ORG', 'host', 'arioch.imrryr.org' ]],
	['HTTP/mournblade.imrryr.org@IMRRYR.ORG',
	    [ 'IMRRYR.ORG', 'HTTP', 'mournblade.imrryr.org' ]],
);

plan tests => scalar(@tests);

for my $test (@tests) {
	my $princ  = $test->[0];
	my $result = $test->[1];

	my $ret = [Krb5Admin::C::krb5_parse_name($ctx, $princ)];

	is_deeply($ret, $result, $princ);
}

exit(0);
