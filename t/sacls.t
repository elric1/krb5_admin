#!/usr/pkg/bin/perl

use Test::More tests=> 4;

use Data::Dumper;

use Krb5Admin::ForkClient;

use strict;
use warnings;

my $kmdb;
$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

$kmdb = Krb5Admin::ForkClient->new({
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
}, CREDS => 'admin_user@TEST.REALM');

eval {
	$kmdb->add_acl('foo@TEST.REALM', 'krb5');
	$kmdb->add_acl('bar@TEST.REALM', 'krb5');
	$kmdb->add_acl('baz@TEST.REALM', 'krb5');

	$kmdb->sacls_add('create', 'foo@TEST.REALM');
	$kmdb->sacls_add('create', 'bar@TEST.REALM');
	$kmdb->sacls_add('create', 'baz@TEST.REALM');

	$kmdb->sacls_add('sacls_add', 'foo@TEST.REALM');
	$kmdb->sacls_add('sacls_del', 'bar@TEST.REALM');
};

ok(!$@, "Add initial sacls");

$kmdb = Krb5Admin::ForkClient->new({
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
}, CREDS => 'foo@TEST.REALM');

eval { $kmdb->sacls_del('create', 'foo@TEST.REALM'); };
ok(!$@, 'foo@TEST.REALM deleting its own create privs.');
diag(Dumper($@)) if $@;

$kmdb = Krb5Admin::ForkClient->new({
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
}, CREDS => 'bar@TEST.REALM');

eval { $kmdb->sacls_del('create', 'bar@TEST.REALM'); };
ok(!$@, 'bar@TEST.REALM deleting its own create privs.');
diag(Dumper($@)) if $@;

$kmdb = Krb5Admin::ForkClient->new({
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
}, CREDS => 'baz@TEST.REALM');

eval { $kmdb->sacls_del('create', 'baz@TEST.REALM'); };
ok($@, 'baz@TEST.REALM should not be able to relinquish privs...');

#done_testing();
