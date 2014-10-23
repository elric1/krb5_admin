#!/usr/bin/perl

use Test::More tests => 7;

use Krb5Admin::ForkClient;

use Data::Dumper;

use Sys::Hostname;
use strict;
use warnings;

sub testObjC {
	my ($testname, $obj, $result, $method, @args) = @_;

	my @ret;
	eval {
		my $code = $obj->can($method) or die "no method $method.";
		@ret = &$code($obj, @args);
	};

	if ($@) {
		ok(0, $testname);
		diag(Dumper($@));
	} else {
		is_deeply(\@ret, $result, $testname) or diag(Dumper(\@ret));
	}
}

sub testMustDie {
	my ($testname, $obj, $method, @args) = @_;

	my @ret;
	my $code = $obj->can($method) or die "no method $method.";
	eval {
		@ret = &$code($obj, @args);
	};

	if ($@) {
		ok(1, $testname);
	} else {
		ok(0, $testname);
	}
}

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

my $creds  = 'admin_user@TEST.REALM';
my $sprinc = 'service/host1.test.realm@TEST.REALM';
my $sprinc2 = 'woodyard/host1.test.realm@TEST.REALM';
my $sprinc_host = 'host1.test.realm';
my $sprinc3 = 'woodyard/host2.test.realm@TEST.REALM';
my $uprinc = 'user@TEST.REALM';
my $anon   = 'WELLKNOWN/ANONYMOUS@TEST.REALM';
my $tgt    = 'krbtgt/TEST.REALM@TEST.REALM';
my $myhost = 'krb5_admin/' . hostname() . '@TEST.REALM';
my $def    = 'default@TEST.REALM';

sub host_kmdb {
	my $kmdb = Krb5Admin::ForkClient->new({
	    dbname	=> 'db:t/test-hdb',
	    sqlite	=> 't/sqlite.db',
	    allow_fetch => 1,
	}, CREDS => 'host/host1.test.realm@TEST.REALM');
	return $kmdb;
}

sub host2_kmdb {
	my $kmdb = Krb5Admin::ForkClient->new({
	    dbname	=> 'db:t/test-hdb',
	    sqlite	=> 't/sqlite.db',
	    allow_fetch => 1,
	}, CREDS => 'host/host2.test.realm@TEST.REALM');
	return $kmdb;
}

sub admin_kmdb {
	Krb5Admin::ForkClient->new({
	    dbname	=> 'db:t/test-hdb',
	    sqlite	=> 't/sqlite.db',
	    allow_fetch => 1,
	}, CREDS => $creds);
}

sub nonadmin_kmdb {
	Krb5Admin::ForkClient->new({
	    dbname	=> 'db:t/test-hdb',
	    sqlite	=> 't/sqlite.db',
	    allow_fetch => 1,
	}, CREDS => 'normal_user@TEST.REALM');
}

my $kmdb = admin_kmdb();
testObjC("Create Host", $kmdb, [undef], 'create_host', $sprinc_host ,
    realm=>"TEST.REALM");
$kmdb = host_kmdb();
testMustDie("Create: Not Allowed for non subdomain", $kmdb, 'create',
    $sprinc3, local_authz=>0);
#testObjC("Create: Allowed for username subdomain", $kmdb, [undef],
#    'create', $sprinc2);

testMustDie("Principal->Account Map: Create map to non-existant princ ",
    $kmdb, 'principal_map_add', 'root', $sprinc3);

$kmdb = admin_kmdb();
testObjC("Create a principal->account mapping", $kmdb, [1],
    'principal_map_add', 'testaccount' , "woodyard", $sprinc_host);
testObjC("Create a principal->account mapping", $kmdb, [1],
    'principal_map_add', 'testaccount2' , "woodyard", $sprinc_host);
testObjC("Create a principal->account mapping", $kmdb, [1],
    'principal_map_add', 'testaccount3' , "woodyard", $sprinc_host);

testMustDie("Create a principal->account mapping (bogus)", $kmdb,
    'principal_map_add', 'testaccount3' , $sprinc2."\@FADS#\$\@\$\!\@#\$",
    "foo");

#testObjC("Create Keys - Must Succeed(1)", $kmdb, [undef], 'create', $sprinc2,
#    local_authz=>0);
#testObjC("Change Keys - Must Succeed(2)", $kmdb, [undef], 'change', $sprinc2,
#    3, local_authz=>0,keys => [{enctype=>17, key=>'0123456789ABCDEF'}]);
#testMustDie("Change Keys - Must Fail", $kmdb, "change", $sprinc2, 4,
#    keys => [{enctype=>17, key=>'0123456789ABCDEF'}],
#    invoking_user=> 'notallowed', local_authz=>0 );

#testObjC("Change Keys - Must Fail", $kmdb, [undef], "change", $sprinc2, 4,
#    keys => [{enctype=>17, key=>'0123456789ABCDEF'}],
#    invoking_user=> 'notallowed' );

#testObjC("Change Keys - Must Succeed(3)", $kmdb, [undef], 'change',
#    $sprinc2, 4, keys => [{enctype=>17, key=>'0123456789ABCDEF'}],
#    local_authz=>0, invoking_user=>'testaccount3');

#testMustDie("Create Keys - Must Fail(a)", $kmdb, 'create', $sprinc3,
#    invoking_user=>"notallowed", local_authz=>0);
#testMustDie("Create Keys - Must Fail(b)", $kmdb, 'create', $sprinc3,
#    local_authz=>0 );
#$kmdb = undef;
#$kmdb = host2_kmdb();
# testMustDie("Create Keys - Must Fail", $kmdb, 'create', $sprinc3);
#testMustDie("Create Keys - Must Fail(c)", $kmdb, 'create', $sprinc3,
#    local_authz=>0, invoking_user=>"notallowed");
#testObjC("Create Keys - Must Succeed(4)", $kmdb, [undef],'create',
#    $sprinc3, local_authz=>0 );

#$kmdb = admin_kmdb();

#testObjC("Create a host", $kmdb, [undef], 'create_host', 'f1.test.realm',
#    ip_addr => '1.1.1.1', realm => 'TEST.REALM');
#testObjC("Create a host", $kmdb, [undef], 'create_host', 'f2.test.realm',
#    ip_addr => '1.1.1.1', realm => 'TEST.REALM');


#testObjC("Create Logical host", $kmdb, [undef], 'create_logical_host',
#    qw/f.test.realm/);
#testObjC("Add normal_user to hostmap owners", $kmdb, [1],"add_host_owner",
#    qw/f.test.realm normal_user@TEST.REALM/);


#$kmdb = nonadmin_kmdb();
#testMustDie("Create a principal->account mapping", $kmdb,
#    'principal_map_add', 'testaccount' , "HTTP","f.test.realm");
#testMustDie("Create a principal->account mapping", $kmdb,
#    'principal_map_add', 'testaccount' , "HTTP","f1.test.realm");
