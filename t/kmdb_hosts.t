#!/usr/pkg/bin/perl

use Test::More tests => 36;

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
    dbname	=> 'db:t/test-hdb',
    acl_file	=> 't/krb5_admin.acl',
    sqlite	=> 't/sqlite.db',
);

#
# XXXrcd: This is destructive!

$kmdb->drop_db();
$kmdb->init_db();

my $proid1 = 'proid1@IMRRYR.ORG';
my $proid2 = 'proid2@IMRRYR.ORG';
my $proid3 = 'proid3@IMRRYR.ORG';
my $proid4 = 'proid4@IMRRYR.ORG';

#
# First, we create three hosts.

testObjC("Create a host", $kmdb, [undef], 'create_host', 'foo.imrryr.org',
	ip_addr => '1.1.1.1', realm => 'IMRRYR.ORG');
testObjC("Query the host", $kmdb,
	[{realm => 'IMRRYR.ORG', ip_addr => '1.1.1.1'}],
	'query_host', name => 'foo.imrryr.org');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'bar.imrryr.org',
	ip_addr => '2.2.2.2', realm => 'IMRRYR.ORG');
testObjC("Query the host", $kmdb,
	[{ip_addr => '2.2.2.2', realm => 'IMRRYR.ORG'}],
	'query_host', name => 'bar.imrryr.org');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'baz.imrryr.org',
	ip_addr => '3.3.3.3', realm => 'IMRRYR.ORG');
testObjC("Query the host", $kmdb,
	[{realm => 'IMRRYR.ORG', ip_addr => '3.3.3.3'}],
	'query_host', name => 'baz.imrryr.org');

#
# Now we create a ``logical host''.  This is basically the same as a
# regular host but we'll use it differently below.

testObjC("Create a host", $kmdb, [undef], 'create_host', 'logical.imrryr.org',
	ip_addr => '3.3.3.3', realm => 'IMRRYR.ORG');
testObjC("Query the logical host", $kmdb,
	[{ip_addr => '3.3.3.3', realm => 'IMRRYR.ORG'}],
	'query_host', name => 'logical.imrryr.org');

#
# Now, we will map the logical host onto ba{r,z}.

testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.imrryr.org bar.imrryr.org/);
testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.imrryr.org baz.imrryr.org/);
testObjC("Query the hostmap", $kmdb,
	[[qw/bar.imrryr.org baz.imrryr.org/]],
	'query_hostmap', 'logical.imrryr.org');

#
# And finally, the prestashed tickets.  First, we insert a reasonable list
# of prestashed tickets:

testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid1,
	'foo.imrryr.org');
testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid2,
	'bar.imrryr.org');
testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid3,
	'baz.imrryr.org');
testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid4,
	'logical.imrryr.org');

#
# Then we query the resulting state in various ways to ensure that everything
# appears to be correct:

testObjC("Query all tickets", $kmdb,
	[{ $proid1=>['foo.imrryr.org'],
	   $proid2=>['bar.imrryr.org'],
	   $proid3=>['baz.imrryr.org'],
	   $proid4=>['logical.imrryr.org'],
	}], "query_ticket");

testObjC("Query all tickets (with expand)", $kmdb,
	[{ $proid1=>['foo.imrryr.org'],
	   $proid2=>['bar.imrryr.org'],
	   $proid3=>['baz.imrryr.org'],
	   $proid4=>['bar.imrryr.org', 'baz.imrryr.org'],
	}], "query_ticket", "expand", 1);

testObjC("Query all tickets (with verbose)", $kmdb,
	[{ $proid1=>[['foo.imrryr.org']],
	   $proid2=>[['bar.imrryr.org']],
	   $proid3=>[['baz.imrryr.org']],
	   $proid4=>[['logical.imrryr.org', 'bar.imrryr.org'],
		     ['logical.imrryr.org', 'baz.imrryr.org']],
	}], "query_ticket", "verbose", 1);

#
# We then query by proid:

testObjC("Query ${proid1}'s tickets", $kmdb, [['foo.imrryr.org']],
	"query_ticket", principal => $proid1);

testObjC("Query ${proid1}'s tickets (expand)", $kmdb, [['foo.imrryr.org']],
	"query_ticket", principal => $proid1, expand => 1);

testObjC("Query ${proid1}'s tickets (verbose)", $kmdb,
	[{$proid1 => [['foo.imrryr.org']]}],
	"query_ticket", principal => $proid1, verbose => 1);

testObjC("Query ${proid4}'s tickets", $kmdb, [['logical.imrryr.org']],
	"query_ticket", principal => $proid4);

testObjC("Query ${proid4}'s tickets (expand)", $kmdb,
	[['bar.imrryr.org', 'baz.imrryr.org']],
	"query_ticket", principal => $proid4, expand => 1);

testObjC("Query ${proid4}'s tickets (verbose)", $kmdb,
	[{$proid4 => [['logical.imrryr.org', 'bar.imrryr.org'],
		      ['logical.imrryr.org', 'baz.imrryr.org']]}],
	"query_ticket", principal => $proid4, verbose => 1);

#
# And we query by host:

testObjC("Query foo.imrryr.org's tickets", $kmdb, [[$proid1]],
	"query_ticket", host => 'foo.imrryr.org');

testObjC("Query foo.imrryr.org's tickets (expand)", $kmdb, [[$proid1]],
	"query_ticket", host => 'foo.imrryr.org', expand => 1);

testObjC("Query foo.imrryr.org's tickets (verbose)", $kmdb,
	[{$proid1 => [['foo.imrryr.org']]}],
	"query_ticket", host => 'foo.imrryr.org', verbose => 1);

testObjC("Query bar.imrryr.org's tickets", $kmdb, [[$proid2]],
	"query_ticket", host => 'bar.imrryr.org');

testObjC("Query bar.imrryr.org's tickets (expand)", $kmdb,
	[[$proid4, $proid2]],
	"query_ticket", host => 'bar.imrryr.org', expand => 1);

testObjC("Query bar.imrryr.org's tickets (verbose)", $kmdb,
	[{$proid2 => [['bar.imrryr.org']],
	  $proid4 => [['logical.imrryr.org','bar.imrryr.org']]}],
	"query_ticket", host => 'bar.imrryr.org', verbose => 1);

testObjC("Query baz.imrryr.org's tickets", $kmdb, [[$proid3]],
	"query_ticket", host => 'baz.imrryr.org');

testObjC("Query baz.imrryr.org's tickets (expand)", $kmdb,
	[[$proid3, $proid4]],
	"query_ticket", host => 'baz.imrryr.org', expand => 1);

testObjC("Query baz.imrryr.org's tickets (verbose)", $kmdb,
	[{$proid3 => [['baz.imrryr.org']],
	  $proid4 => [['logical.imrryr.org','baz.imrryr.org']]}],
	"query_ticket", host => 'baz.imrryr.org', verbose => 1);

testObjC("Query logical.imrryr.org's tickets", $kmdb, [[$proid4]],
	"query_ticket", host => 'logical.imrryr.org');

testObjC("Query logical.imrryr.org's tickets", $kmdb, [[$proid4]],
	"query_ticket", host => 'logical.imrryr.org', expand => 1);

testObjC("Query logical.imrryr.org's tickets", $kmdb,
	[{$proid4 => [['logical.imrryr.org','bar.imrryr.org'],
		      ['logical.imrryr.org','baz.imrryr.org']]}],
	"query_ticket", host => 'logical.imrryr.org', verbose => 1);



exit(0);
