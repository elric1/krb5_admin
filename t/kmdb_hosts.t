#!/usr/pkg/bin/perl

use Test::More tests => 18;

use Krb5Admin::KerberosDB;

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
		ok(0, $testname);
		diag(Dumper($@));
	} else {
		is_deeply(\@ret, $result, $testname);
	}
}

my $kmdb;

$kmdb = Krb5Admin::KerberosDB->new(
    local	=> 1,
    client	=> 'host/arioch.imrryr.org@IMRRYR.ORG',
    acl_file	=> 't/krb5_admin.acl',
);

#
# XXXrcd: This is destructive!

$kmdb->drop_db();
$kmdb->init_db();

#
# First, we create three hosts.

testObjC("Create a host", $kmdb, [undef], 'create_host', 'foo.imrryr.org',
	ip_addr => '1.1.1.1');
testObjC("Query the host", $kmdb, [['foo.imrryr.org', '1.1.1.1']],
	'query_host', name => 'foo.imrryr.org');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'bar.imrryr.org',
	ip_addr => '2.2.2.2');
testObjC("Query the host", $kmdb, [['bar.imrryr.org', '2.2.2.2']],
	'query_host', name => 'bar.imrryr.org');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'baz.imrryr.org',
	ip_addr => '3.3.3.3');
testObjC("Query the host", $kmdb, [['baz.imrryr.org', '3.3.3.3']],
	'query_host', name => 'baz.imrryr.org');

#
# Now we create a ``logical host''.  This is basically the same as a
# regular host but we'll use it differently below.

testObjC("Create a host", $kmdb, [undef], 'create_host', 'logical.imrryr.org',
	ip_addr => '3.3.3.3');
testObjC("Query the logical host", $kmdb, [[qw{logical.imrryr.org 3.3.3.3}]],
	'query_host', name => 'logical.imrryr.org');

#
# Now, we will map the logical host onto ba{r,z}.

testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.imrryr.org bar.imrryr.org/);
testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.imrryr.org baz.imrryr.org/);
testObjC("Query the hostmap", $kmdb,
	[[[qw/logical.imrryr.org bar.imrryr.org/],
	    [qw/logical.imrryr.org baz.imrryr.org/]]],
	'query_hostmap', 'logical.imrryr.org');

#
# And finally, the prestashed tickets:

testObjC("Insert a ticket", $kmdb, [], qw/insert_ticket proid1 foo.imrryr.org/);
testObjC("Insert a ticket", $kmdb, [], qw/insert_ticket proid2 bar.imrryr.org/);
testObjC("Insert a ticket", $kmdb, [], qw/insert_ticket proid3 baz.imrryr.org/);
testObjC("Insert a ticket", $kmdb, [], qw/insert_ticket proid4
	logical.imrryr.org/);

testObjC("Query all tickets", $kmdb,
	[{ proid1=>['foo.imrryr.org'],
	   proid2=>['bar.imrryr.org'],
	   proid3=>['baz.imrryr.org'],
	   proid4=>['logical.imrryr.org'],
	}], "query_ticket");

testObjC("Query all tickets (with expand)", $kmdb,
	[{ proid1=>['foo.imrryr.org'],
	   proid2=>['bar.imrryr.org'],
	   proid3=>['baz.imrryr.org'],
	   proid4=>['bar.imrryr.org', 'baz.imrryr.org'],
	}], "query_ticket", "expand", 1);

testObjC("Query all tickets (with verbose)", $kmdb,
	[{ proid1=>[['foo.imrryr.org']],
	   proid2=>[['bar.imrryr.org']],
	   proid3=>[['baz.imrryr.org']],
	   proid4=>[['logical.imrryr.org', 'bar.imrryr.org'],
		    ['logical.imrryr.org', 'baz.imrryr.org']],
	}], "query_ticket", "verbose", 1);


exit(0);
