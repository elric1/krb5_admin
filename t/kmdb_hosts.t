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
		is_deeply(\@ret, $result, $testname) or diag(Dumper(\@ret));
	}
}

my $kmdb;

$kmdb = Krb5Admin::KerberosDB->new(
    local	=> 1,
    client	=> 'host/host1.test.realm@TEST.REALM',
    dbname	=> 'db:t/test-hdb',
    acl_file	=> 't/krb5_admin.acl',
    sqlite	=> 't/sqlite.db',
);

#
# XXXrcd: This is destructive!

$kmdb->drop_db();
$kmdb->init_db();

my $proid1 = 'proid1@TEST.REALM';
my $proid2 = 'proid2@TEST.REALM';
my $proid3 = 'proid3@TEST.REALM';
my $proid4 = 'proid4@TEST.REALM';

#
# First, we create three hosts.

testObjC("Create a host", $kmdb, [undef], 'create_host', 'foo.test.realm',
	ip_addr => '1.1.1.1', realm => 'TEST.REALM');
testObjC("Query the host", $kmdb,
	[{realm => 'TEST.REALM', ip_addr => '1.1.1.1', bootbinding => undef,
	label => []}], 'query_host', name => 'foo.test.realm');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'bar.test.realm',
	ip_addr => '2.2.2.2', realm => 'TEST.REALM');
testObjC("Query the host", $kmdb,
	[{ip_addr => '2.2.2.2', realm => 'TEST.REALM', bootbinding => undef,
	label => []}], 'query_host', name => 'bar.test.realm');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'baz.test.realm',
	ip_addr => '3.3.3.3', realm => 'TEST.REALM');
testObjC("Query the host", $kmdb, [{realm => 'TEST.REALM',
	ip_addr => '3.3.3.3', bootbinding => undef, label => []}],
	'query_host', name => 'baz.test.realm');

#
# Now we create a ``logical host''.  This is basically the same as a
# regular host but we'll use it differently below.

testObjC("Create a host", $kmdb, [undef], 'create_host', 'logical.test.realm',
	ip_addr => '3.3.3.3', realm => 'TEST.REALM');
testObjC("Query the logical host", $kmdb,
	[{ip_addr => '3.3.3.3', realm => 'TEST.REALM', bootbinding => undef,
	label => []}], 'query_host', name => 'logical.test.realm');

#
# Now, we will map the logical host onto ba{r,z}.

testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.test.realm bar.test.realm/);
testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.test.realm baz.test.realm/);
testObjC("Query the hostmap", $kmdb,
	[[qw/bar.test.realm baz.test.realm/]],
	'query_hostmap', 'logical.test.realm');

#
# And finally, the prestashed tickets.  First, we insert a reasonable list
# of prestashed tickets:

testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid1,
	'foo.test.realm');
testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid2,
	'bar.test.realm');
testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid3,
	'baz.test.realm');
testObjC("Insert a ticket", $kmdb, [undef], 'insert_ticket', $proid4,
	'logical.test.realm');

#
# Then we query the resulting state in various ways to ensure that everything
# appears to be correct:

testObjC("Query all tickets", $kmdb,
	[{ $proid1=>['foo.test.realm'],
	   $proid2=>['bar.test.realm'],
	   $proid3=>['baz.test.realm'],
	   $proid4=>['logical.test.realm'],
	}], "query_ticket");

testObjC("Query all tickets (with expand)", $kmdb,
	[{ $proid1=>['foo.test.realm'],
	   $proid2=>['bar.test.realm'],
	   $proid3=>['baz.test.realm'],
	   $proid4=>['bar.test.realm', 'baz.test.realm'],
	}], "query_ticket", "expand", 1);

testObjC("Query all tickets (with verbose)", $kmdb,
	[{ $proid1=>[['foo.test.realm']],
	   $proid2=>[['bar.test.realm']],
	   $proid3=>[['baz.test.realm']],
	   $proid4=>[['logical.test.realm', 'bar.test.realm'],
		     ['logical.test.realm', 'baz.test.realm']],
	}], "query_ticket", "verbose", 1);

#
# We then query by proid:

testObjC("Query ${proid1}'s tickets", $kmdb, [['foo.test.realm']],
	"query_ticket", principal => $proid1);

testObjC("Query ${proid1}'s tickets (expand)", $kmdb, [['foo.test.realm']],
	"query_ticket", principal => $proid1, expand => 1);

testObjC("Query ${proid1}'s tickets (verbose)", $kmdb,
	[{$proid1 => [['foo.test.realm']]}],
	"query_ticket", principal => $proid1, verbose => 1);

testObjC("Query ${proid4}'s tickets", $kmdb, [['logical.test.realm']],
	"query_ticket", principal => $proid4);

testObjC("Query ${proid4}'s tickets (expand)", $kmdb,
	[['baz.test.realm', 'bar.test.realm']],
	"query_ticket", principal => $proid4, expand => 1);

testObjC("Query ${proid4}'s tickets (verbose)", $kmdb,
	[{$proid4 => [['logical.test.realm', 'bar.test.realm'],
		      ['logical.test.realm', 'baz.test.realm']]}],
	"query_ticket", principal => $proid4, verbose => 1);

#
# And we query by host:

testObjC("Query foo.test.realm's tickets", $kmdb, [[$proid1]],
	"query_ticket", host => 'foo.test.realm');

testObjC("Query foo.test.realm's tickets (expand)", $kmdb, [[$proid1]],
	"query_ticket", host => 'foo.test.realm', expand => 1);

testObjC("Query foo.test.realm's tickets (verbose)", $kmdb,
	[{$proid1 => [['foo.test.realm']]}],
	"query_ticket", host => 'foo.test.realm', verbose => 1);

testObjC("Query bar.test.realm's tickets", $kmdb, [[$proid2]],
	"query_ticket", host => 'bar.test.realm');

testObjC("Query bar.test.realm's tickets (expand)", $kmdb,
	[[$proid4, $proid2]],
	"query_ticket", host => 'bar.test.realm', expand => 1);

testObjC("Query bar.test.realm's tickets (verbose)", $kmdb,
	[{$proid2 => [['bar.test.realm']],
	  $proid4 => [['logical.test.realm','bar.test.realm']]}],
	"query_ticket", host => 'bar.test.realm', verbose => 1);

testObjC("Query baz.test.realm's tickets", $kmdb, [[$proid3]],
	"query_ticket", host => 'baz.test.realm');

testObjC("Query baz.test.realm's tickets (expand)", $kmdb,
	[[$proid4, $proid3]],
	"query_ticket", host => 'baz.test.realm', expand => 1);

testObjC("Query baz.test.realm's tickets (verbose)", $kmdb,
	[{$proid3 => [['baz.test.realm']],
	  $proid4 => [['logical.test.realm','baz.test.realm']]}],
	"query_ticket", host => 'baz.test.realm', verbose => 1);

testObjC("Query logical.test.realm's tickets", $kmdb, [[$proid4]],
	"query_ticket", host => 'logical.test.realm');

testObjC("Query logical.test.realm's tickets", $kmdb, [[$proid4]],
	"query_ticket", host => 'logical.test.realm', expand => 1);

testObjC("Query logical.test.realm's tickets", $kmdb,
	[{$proid4 => [['logical.test.realm','bar.test.realm'],
		      ['logical.test.realm','baz.test.realm']]}],
	"query_ticket", host => 'logical.test.realm', verbose => 1);



exit(0);
