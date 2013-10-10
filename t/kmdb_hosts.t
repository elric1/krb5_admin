#!/usr/pkg/bin/perl

use Test::More tests => 39;

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
		ok(0, $testname);
		diag(Dumper($@));
	} else {
		is_deeply(\@ret, $result, $testname) or diag(Dumper(\@ret));
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

my $kmdb;

$kmdb = Krb5Admin::ForkClient->new({
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
}, CREDS => 'admin_user@TEST.REALM');

my $proid1 = 'proid1@TEST.REALM';
my $proid2 = 'proid2@TEST.REALM';
my $proid3 = 'proid3@TEST.REALM';
my $proid4 = 'proid4@TEST.REALM';

for my $p ($proid1, $proid2, $proid3, $proid4) {
	$kmdb->create_appid($p);
}

#
# First, we create three hosts.

testObjC("Create a host", $kmdb, [undef], 'create_host', 'foo.test.realm',
	ip_addr => '1.1.1.1', realm => 'TEST.REALM');
testObjC("Query the host", $kmdb,
	[{realm => 'TEST.REALM', ip_addr => '1.1.1.1', bootbinding => undef,
	is_logical=>undef, label => [], owner => []}], 'query_host', 'foo.test.realm');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'bar.test.realm',
	ip_addr => '2.2.2.2', realm => 'TEST.REALM');
testObjC("Query the host", $kmdb,
	[{ip_addr => '2.2.2.2', realm => 'TEST.REALM', bootbinding => undef,
	is_logical=>undef, label => [], owner => []}], 'query_host', 'bar.test.realm');
testObjC("Create a host", $kmdb, [undef], 'create_host', 'baz.test.realm',
	ip_addr => '3.3.3.3', realm => 'TEST.REALM');
testObjC("Query the host", $kmdb, [{realm => 'TEST.REALM',
	is_logical=>undef, ip_addr => '3.3.3.3', bootbinding => undef, label => [], owner => []}],
	'query_host', 'baz.test.realm');

testObjC("Query the hostmap", $kmdb,
	[undef],
	'query_hostmap', 'logical.test.realm');
#
# Now, we will map the logical host onto ba{r,z}.

testObjC("Create Logical host", $kmdb, [undef], 'create_logical_host',
	qw/logical.test.realm/);
	

testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.test.realm bar.test.realm/);
testObjC("Create a mapping", $kmdb, [undef], 'insert_hostmap',
	qw/logical.test.realm baz.test.realm/);

testObjC("Query the hostmap", $kmdb,
	[[qw/bar.test.realm baz.test.realm/]],
	'query_hostmap', 'logical.test.realm');

testMustDie("Create a mapping to a bogus physical host", $kmdb, 'insert_hostmap',
	qw/logical.test.realm bdfdfda.est.realm/);

testMustDie("Don't create a physical host named the same as a logical host", $kmdb, 
    'create_host', 'logical.test.realm',
    ip_addr => '3.3.3.3', realm => 'TEST.REALM');

testObjC("Query the logical host", $kmdb,
	[{ip_addr => undef, realm => 'TEST.REALM', bootbinding => undef,
	is_logical=>1, label => [], owner => ['admin_user@TEST.REALM']}], 'query_host', 'logical.test.realm');


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

for my $p ($proid1, $proid2, $proid3, $proid4) {
	$kmdb->remove($p);
}

exit(0);
