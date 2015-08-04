#!/usr/pkg/bin/perl

use Test::More tests => 4;

use Krb5Admin::KerberosDB;

use strict;
use warnings;

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

my $kmdb = Krb5Admin::KerberosDB->new(
    local	=> 1,
    client	=> 'root@TEST.REALM',
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
);

$kmdb->add_feature('BAR-Feature');
$kmdb->add_feature('BAZ-Feature');
ok($kmdb->has_feature('FOO-Feature') == 0, "FOO-Feature is present initially");
$kmdb->add_feature('FOO-Feature');
ok($kmdb->has_feature('FOO-Feature') == 1, "FOO-Feature not present!");
$kmdb->del_feature('FOO-Feature');
ok($kmdb->has_feature('FOO-Feature') == 0, "FOO-Feature IS present!");
$kmdb->add_feature('FOO-Feature');
ok($kmdb->has_feature('FOO-Feature') == 1, "FOO-Feature not present (2)!");
