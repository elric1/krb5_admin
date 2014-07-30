#!/usr/pkg/bin/perl
#

use Test::More tests => 1;

use Sys::Hostname;

use Kharon::Entitlement::SimpleSQL;

use Krb5Admin::C;
use Krb5Admin::KerberosDB;

use strict;
use warnings;

my $hostname = hostname();

#
# Create our custom krb5.conf:

system("sed s/__HOSTNAME__/$hostname/g < t/krb5.conf.in > t/krb5.conf");

$ENV{KRB5_CONFIG} = './t/krb5.conf';

chomp(my $me = qx{id -nu});
unlink('t/test-hdb.db');
unlink("t/keytabs/$me");
unlink("t/keytabs/root");

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, 'db:t/test-hdb', undef);
Krb5Admin::C::init_kdb($ctx, $hndl);
undef $hndl;

my $creds = 'admin_user@TEST.REALM';
my $creds_normal = 'normal_user@TEST.REALM';

my $kmdb;

my $sqlacl  = Kharon::Entitlement::SimpleSQL->new(
    table => 'krb5_admin_simple_acls');

$kmdb = Krb5Admin::KerberosDB->new(
    local	=> 1,
    client	=> $creds,
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
    sacls	=> $sqlacl,
);

$sqlacl->set_dbh($kmdb->get_dbh());

#
# XXXrcd: This is destructive!

$kmdb->drop_db();
$kmdb->init_db();

$kmdb->add_acl($creds, 'krb5');
$kmdb->add_acl($creds_normal, 'krb5');

$kmdb->sacls_add('sacls_add', $creds);
$kmdb->sacls_add('sacls_del', $creds);
$kmdb->sacls_add('add_acl', $creds);
# $kmdb->sacls_add('bind_host', $creds);
$kmdb->sacls_add('change', $creds);
$kmdb->sacls_add('change_passwd', $creds);
$kmdb->sacls_add('create', $creds);
$kmdb->sacls_add('create_appid', $creds);
$kmdb->sacls_add('create_host', $creds);
$kmdb->sacls_add('create_user', $creds);
$kmdb->sacls_add('del_acl', $creds);
$kmdb->sacls_add('disable', $creds);
$kmdb->sacls_add('enable', $creds);
$kmdb->sacls_add('fetch', $creds);
$kmdb->sacls_add('insert_aclgroup', $creds);
$kmdb->sacls_add('insert_hostmap', $creds);
$kmdb->sacls_add('insert_ticket', $creds);
$kmdb->sacls_add('modify', $creds);
$kmdb->sacls_add('remove', $creds);
$kmdb->sacls_add('remove_aclgroup', $creds);

$kmdb->sacls_add('remove_acl_owner', $creds);
$kmdb->sacls_add('remove_host_owner', $creds);
$kmdb->sacls_add('add_acl_owner', $creds);
$kmdb->sacls_add('add_host_owner', $creds);

$kmdb->sacls_add('query_host_owner', $creds);

$kmdb->sacls_add('principal_map_add', $creds);
$kmdb->sacls_add('principal_map_remove', $creds);

$kmdb->create('krbtgt/TEST.REALM@TEST.REALM');
$kmdb->create('WELLKNOWN/ANONYMOUS@TEST.REALM');
$kmdb->create('krb5_admin/' . $hostname . '@TEST.REALM');
$kmdb->create('default');

ok(1);

exit(0);
