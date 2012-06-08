#!/usr/pkg/bin/perl
#

use Test::More;

use Krb5Admin::C;

use strict;
use warnings;

$ENV{KRB5_CONFIG} = './t/krb5.conf';

my $ret;
my $ctx = Krb5Admin::C::krb5_init_context();

my @tests = (
	['a@BAR.COM', [ 'BAR.COM', 'a' ]],
	['user@EXAMPLE.COM', [ 'EXAMPLE.COM', 'user' ]],
	['userA@TEST.REALM', [ 'TEST.REALM', 'userA' ]],
	['userA@test.realm', [ 'test.realm', 'userA' ]],
	['userA/root@TEST.REALM',  [ 'TEST.REALM', 'userA', 'root' ]],
	['userB/admin@TEST.REALM', [ 'TEST.REALM', 'userB', 'admin' ]],
	['host/host1.test.realm@TEST.REALM',
	    [ 'TEST.REALM', 'host', 'host1.test.realm' ]],
	['HTTP/host2.test.realm@TEST.REALM',
	    [ 'TEST.REALM', 'HTTP', 'host2.test.realm' ]],
);

plan tests => scalar(@tests);

for my $test (@tests) {
	my $princ  = $test->[0];
	my $result = $test->[1];

	my $ret = [Krb5Admin::C::krb5_parse_name($ctx, $princ)];

	is_deeply($ret, $result, $princ);
}

exit(0);
