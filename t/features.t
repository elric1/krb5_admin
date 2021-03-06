#!/usr/pkg/bin/perl

use Test::More tests => 4;

use Krb5Admin::Local;

use strict;
use warnings;

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

my $kmdb = Krb5Admin::Local->new({
    client	=> 'root@TEST.REALM',
    config	=> './t/krb5_admind.conf',
});

$kmdb->add_feature('BAR-Feature');
$kmdb->add_feature('BAZ-Feature');
ok($kmdb->has_feature('FOO-Feature') == 0, "FOO-Feature is present initially");
$kmdb->add_feature('FOO-Feature');
ok($kmdb->has_feature('FOO-Feature') == 1, "FOO-Feature not present!");
$kmdb->del_feature('FOO-Feature');
ok($kmdb->has_feature('FOO-Feature') == 0, "FOO-Feature IS present!");
$kmdb->add_feature('FOO-Feature');
ok($kmdb->has_feature('FOO-Feature') == 1, "FOO-Feature not present (2)!");
