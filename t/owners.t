#!/usr/bin/perl

use Test::More tests => 48;

use Sys::Hostname;

use Krb5Admin::KerberosDB;
use Krb5Admin::ForkClient;

use Data::Dumper;

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
		print $@;
		ok(0, $testname);
		diag(Dumper($@));
	} else {
		is_deeply(\@ret, $result, $testname) or diag(Dumper(\@ret));
	}
}

sub testMustNotDie {
	my ($testname, $obj, $method, @args) = @_;

	my @ret;
	eval {
		my $code = $obj->can($method) or die "no method $method.";
		@ret = &$code($obj, @args);
	};

	if ($@) {
		ok(0, $testname);
		diag(Dumper($@));
	} else { 
		ok(1, $testname);
	}
}

sub testMustDie {
	my ($testname, $obj, $method, @args) = @_;

	my @ret;
	eval {
		my $code = $obj->can($method) or die "no method $method.";
		@ret = &$code($obj, @args);
	};

	if ($@) {
		#diag(Dumper($@));
		ok(1, $testname);
	} else { 
		ok(0, $testname);
	}

}

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

sub admin_user_connect {
	my $kmdb = Krb5Admin::ForkClient->new({
	    dbname	=> 'db:t/test-hdb',
	    sqlite	=> 't/sqlite.db',
	}, CREDS => 'admin_user@TEST.REALM');
	return $kmdb;
}
my $kmdb = admin_user_connect();

testMustNotDie("normal_user create", $kmdb, 
	'create_user', 'normal_user@TEST.REALM') ;

my @physical_hosts = ("a","b","c","d","e");

foreach my $h (@physical_hosts) {
	testMustNotDie("Create a physical host $h", $kmdb, 'create_host',
	    "$h.test.realm", 'ip_addr'=> '6.6.6.6', 'realm'=>'TEST.REALM');
	testObjC("Query the logical host $h", $kmdb,
	    [{ip_addr => '6.6.6.6', realm => 'TEST.REALM',
	    bootbinding => undef, is_logical => undef, label => [],
	    owner=>[]}], 'query_host', "$h.test.realm");
}

my $h = 'cname1';
testMustNotDie("Create a host $h", $kmdb, 'create_host', "$h.test.realm", 
		 'ip_addr'=> '6.6.6.6', 'realm'=>'TEST.REALM');

testObjC("Query the logical host $h", $kmdb,
    [{ip_addr => '6.6.6.6', realm => 'TEST.REALM', bootbinding => undef,
    is_logical=>undef, label => [], owner => []}], 'query_host',
    "$h.test.realm");

testMustDie("Can't steal a physical host to be a cluster name", $kmdb,
    "insert_hostmap", qw/cname1.test.realm b.test.realm/);

testMustDie("Can't steal a physical host to be a cluster name", $kmdb,
    "insert_hostmap", qw/cname.test.realm b.test.realm/);
	    
$h = 'cname';
testMustNotDie("Create a host $h", $kmdb, 'create_logical_host',
    "$h.test.realm", 'ip_addr'=> '6.6.6.6', 'realm'=>'TEST.REALM');
testObjC("Create logical host map", $kmdb, [undef], 'insert_hostmap',
    qw/cname.test.realm a.test.realm/);
testObjC("Create logical host map", $kmdb, [undef], 'insert_hostmap',
    qw/cname.test.realm b.test.realm/);

sub create_normal_user_connect {
	my $kmdb_user = Krb5Admin::ForkClient->new({
			dbname	=> 'db:t/test-hdb',
			sqlite	=> 't/sqlite.db',
			}, CREDS => 'normal_user@TEST.REALM');
	return $kmdb_user;
}

my @x = [
	   [
#	      {
#		'owner' => 'admin_user@TEST.REALM',
#		'name' => 'logical.test.realm'
#	      },
	     {
	       'owner' => 'admin_user@TEST.REALM',
	       'name' => 'cname.test.realm'
	     },
	    {
	       'owner' => 'normal_user@TEST.REALM',
	       'name' => 'cname.test.realm'
	     },
	   ]
	 ];


testMustDie("Add user to non existant hostmap", $kmdb, "add_host_owner",
    qw/a1111.test.realm normal_user@TEST.REALM/);

my $kmdb_user = create_normal_user_connect();
testMustDie("Normal User Attempts to add", $kmdb_user, "insert_hostmap",
    qw/cname.test.realm c.test.realm/);
undef $kmdb_user;

testObjC("Add normal_user to hostmap owners", $kmdb, [1],"add_host_owner", 
    qw/cname.test.realm normal_user@TEST.REALM/);

testObjC("Query host owner must show correct", $kmdb, @x,"query_host_owner", 
    qw/cname.test.realm/);
undef $kmdb;

$kmdb_user = create_normal_user_connect();
testMustNotDie("normal_user should be able to add hostmap now", $kmdb_user,
    "insert_hostmap", qw/cname.test.realm c.test.realm/);

undef $kmdb_user;

$kmdb = admin_user_connect();

testMustNotDie("add a group", $kmdb, "add_acl", qw/test_group1 group/);
testMustNotDie("add a group", $kmdb, "add_acl", qw/test_group2 group/);
testMustNotDie("add a group", $kmdb, "add_acl", qw/test_group3 group/);
testMustNotDie("add a group with odd different", $kmdb, "add_acl",
    qw/test_group4 group/, owner=>'normal_user@TEST.REALM');

testObjC("acl_owner", $kmdb, [[{owner=>'normal_user@TEST.REALM',
    name=>'test_group4'}]],"query_acl_owner", qw/test_group4/);

testObjC("create logical for someone else", $kmdb,
    [[{owner=>'normal_user@TEST.REALM', name=>'test_group4'}]],
    "query_acl_owner", qw/test_group4/);

$kmdb_user = create_normal_user_connect();

testMustDie("Can't create a logical for someone else", $kmdb_user,
    "create_logical_host", "cname10.test.realm",
    owner=>'admin_user@TEST.REALM');

testMustNotDie("normal_user should be able to create logicals", $kmdb_user,
    "create_logical_host", qw/cname102.test.realm/);

undef $kmdb_user;

$kmdb = admin_user_connect();

# XXX - this was moved to 00prepare.t
# testMustNotDie("add a group", $kmdb, "add_acl",
#     qw/normal_user@TEST.REALM krb5/);

$kmdb_user = create_normal_user_connect();

testMustDie("normal user should not modify aclgroup", 
	$kmdb_user, "insert_aclgroup",
	qw/test_group1 normal_user@TEST.REALM/);
undef $kmdb_user;

testMustNotDie("add owner of test_group1", $kmdb, "add_acl_owner",
	qw/test_group3 normal_user@TEST.REALM/);

$kmdb_user = create_normal_user_connect();
testMustNotDie("add a group", $kmdb_user, "insert_aclgroup",
    qw/test_group3 normal_user@TEST.REALM/);
undef $kmdb_user;

testMustNotDie("add a owner", $kmdb, "add_acl_owner",
    qw/test_group3 normal_user@TEST.REALM/);
testMustDie("delete self owner", $kmdb, "remove_acl_owner",
    qw/test_group3 admin_user@TEST.REALM/);
testMustNotDie("delete self owner", $kmdb, "remove_acl_owner",
    qw/test_group3 normal_user@TEST.REALM/);

testMustNotDie("add a host", $kmdb, "create_host", "a.testfqdn.com",
    realm => 'TEST.REALM');    
testMustDie("add a host", $kmdb, "create_host", "a.testfqdn.com",
    realm => 'TEST.REALM');    
testMustNotDie("add a host", $kmdb, "create_host", "b.testfqdn.com",
    realm => 'TEST.REALM');    

$kmdb_user = create_normal_user_connect();
testMustNotDie("remove hostmap", $kmdb_user, "remove_hostmap", 
    qw/cname.test.realm c.test.realm/);

testMustNotDie("logical multi owner", $kmdb_user, "create_logical_host",
    "cluster1.testfqdn.com", owner => ['normal_user@TEST.REALM',
    'admin_user@TEST.REALM']);

testMustNotDie("modify owner host", $kmdb_user, "modify_host",
	"cluster1.testfqdn.com", del_owner => ['admin_user@TEST.REALM']);

testMustDie("modify owner host del self must fail", $kmdb_user, "modify_host",
	"cluster1.testfqdn.com", del_owner => ['normal_user@TEST.REALM']);

testMustNotDie('attach group owner', $kmdb_user, "modify_host",
	'cluster1.testfqdn.com', add_owner =>['test_group3']);

testMustNotDie('remove non group owner', $kmdb_user, "modify_host",
	'cluster1.testfqdn.com', del_owner =>['normal_user@TEST.REALM']);

testMustDie('dont allow invalid action', $kmdb_user, "modify_host",
	'cluster1.testfqdn.com', name =>'cluster2.testfqdn.com');

testMustNotDie("normal_user should still be able to add hostmap now",
    $kmdb_user, "insert_hostmap", qw/cluster1.testfqdn.com c.test.realm/);

undef $kmdb_user;
undef $kmdb;

__END__

#
# XXXrcd: is this really the end?

$kmdb = Krb5Admin::ForkClient->new({
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
}, CREDS => 'admin_user@TEST.REALM');

testMustNotDie("normal_user create", $kmdb, 
	'create_user', 'normal_user@TEST.REALM') ;	# repeat?

my @physical_hosts = ("a","b","c","d","e");

foreach my $h (@physical_hosts) {
	testMustNotDie("Create a logical host $h", $kmdb, 'create_host',
	    "$h.test.realm", 'ip_addr'=> '6.6.6.6', 'realm'=>'TEST.REALM');
	testObjC("Query the logical host $h", $kmdb,
	    [{ip_addr => '6.6.6.6', realm => 'TEST.REALM',
	    bootbinding => undef, label => []}], 'query_host',
	    "$h.test.realm");
}
my $h = 'cname';
testMustNotDie("Create a logical host $h", $kmdb, 'create_host',
    "$h.test.realm", 'ip_addr'=> '6.6.6.6', 'realm'=>'TEST.REALM');
testObjC("Query the logical host $h", $kmdb,
    [{ip_addr => '6.6.6.6', realm => 'TEST.REALM', bootbinding => undef,
    label => []}], 'query_host', "$h.test.realm");

testObjC("Create logical host map", $kmdb, [undef], 'insert_hostmap',
    qw/cname.test.realm a.test.realm/);
testObjC("Create logical host map", $kmdb, [undef], 'insert_hostmap',
    qw/cname.test.realm b.test.realm/);

sub create_normal_user_connect {
	my $kmdb_user = Krb5Admin::ForkClient->new({
			dbname	=> 'db:t/test-hdb',
			sqlite	=> 't/sqlite.db',
			}, CREDS => 'normal_user@TEST.REALM');
	return $kmdb_user;
}

my @x = [
	   [
	     {
	       'owner' => 'admin_user@TEST.REALM',
	       'name' => 'logical.test.realm'
	     },
	     {
	       'owner' => 'admin_user@TEST.REALM',
	       'name' => 'cname.test.realm'
	     },
	     {
	       'owner' => 'normal_user@TEST.REALM',
	       'name' => 'cname.test.realm'
	     }
	   ]
	 ];

testMustDie("Add user to non existant hostmap", $kmdb, "add_hostmap_owner",
		qw/a.test.realm normal_user@TEST.REALM/);
my $kmdb_user = create_normal_user_connect();
testMustDie("Normal User Attempts to add", $kmdb_user, "insert_hostmap",
		qw/cname.test.realm c.test.realm/);
testObjC("Add normal_user to hostmap owners", $kmdb, [1],"add_hostmap_owner",
	qw/cname.test.realm normal_user@TEST.REALM/);

testObjC("Query hostmap must show correct", $kmdb, @x,"query_hostmap_owner",
	qw/cname.test.realm normal_user@TEST.REALM/);

$kmdb_user = create_normal_user_connect();
testMustNotDie("normal_user should be able to add hostmap now", $kmdb_user,
    "insert_hostmap", qw/cname.test.realm c.test.realm/);

testMustNotDie("add a group", $kmdb, "add_acl", qw/test_group1 group/);
testMustNotDie("add a group", $kmdb, "add_acl", qw/test_group2 group/);
testMustNotDie("add a group", $kmdb, "add_acl", qw/test_group3 group/);
testMustNotDie("add a group", $kmdb, "add_acl",
    qw/normal_user@TEST.REALM krb5/);

testMustDie("normal user should not modify aclgroup", 
	$kmdb_user, "insert_aclgroup",
	qw/test_group1 normal_user@TEST.REALM/);

testMustNotDie("add owner of test_group1", $kmdb, "add_acl_owner",
	qw/test_group3 normal_user@TEST.REALM/);

$kmdb_user = create_normal_user_connect();
testMustNotDie("add a group", $kmdb_user, "insert_aclgroup",
    qw/test_group3 normal_user@TEST.REALM/);

done_testing();
