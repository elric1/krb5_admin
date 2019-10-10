#!/usr/pkg/bin/perl

use Test::More tests => 82;

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
		is_deeply(\@ret, $result, $testname);
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

sub mk_kmdb {
	Krb5Admin::ForkClient->new({config => './t/krb5_admind.conf'}, @_);
}

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

my $kmdb = mk_kmdb(CREDS => 'admin_user@TEST.REALM');

#
# First, we create a few ACLs.  They must be created before the appids
# because appids will always reference at least one ACL.

my @owner_grp = (owner => ['admin_user@TEST.REALM']);
my @owner_user = (owner => []);
my @members = (member => []);
our $acls = {
	'admin_user@TEST.REALM'	=> { type => 'krb5', @owner_user, @members},
	'normal_user@TEST.REALM'=> { type => 'krb5', @owner_user, @members},
	'elric@IMRRYR.ORG'	=> { type => 'krb5', @owner_user, @members},
	'yyrkoon@IMRRYR.ORG'	=> { type => 'krb5', @owner_user, @members},
	'cymoril@IMRRYR.ORG'	=> { type => 'krb5', @owner_user, @members},
	'sadric@IMRRYR.ORG'	=> { type => 'krb5', @owner_user, @members},
	'group1'		=> { type => 'group', @owner_grp, @members},
	'group2'		=> { type => 'group', @owner_grp, @members},
	'group3'		=> { type => 'group', @owner_grp, @members},
	'group4'		=> { type => 'group', @owner_grp, @members},
	'group5'		=> { type => 'group', @owner_grp, @members},
	'group6'		=> { type => 'group', @owner_grp, @members},
	'group7'		=> { type => 'group', @owner_grp, @members},
	'group8'		=> { type => 'group', @owner_grp, @members},
	'group9'		=> { type => 'group', @owner_grp, @members},
	'group10'		=> { type => 'group', @owner_grp, @members},
	'group11'		=> { type => 'group', @owner_grp, @members},
	'group12'		=> { type => 'group', @owner_grp, @members},
	'group13'		=> { type => 'group', @owner_grp, @members},
	'group14'		=> { type => 'group', @owner_grp, @members},
	'group15'		=> { type => 'group', @owner_grp, @members},
	'group16'		=> { type => 'group', @owner_grp, @members},
	'group17'		=> { type => 'group', @owner_grp, @members},
	'master_group'		=> { type => 'group', @owner_grp, @members},
    };

my $i;
for $i (keys %$acls) {
	next if $i eq 'admin_user@TEST.REALM';	# now create in 00prepare.t.
	next if $i eq 'normal_user@TEST.REALM';	# now create in 00prepare.t.

	testObjC("Create ACL: $i", $kmdb, [], 'create_subject', $i,
	    %{$acls->{$i}});
}

testObjC("Query ACLs", $kmdb, [$acls], 'query_acl');

#
# We then create a few appids and query them.

for $i (0..3) {
	testObjC("Create appid$i", $kmdb, [undef], 'create_appid', "appid$i");

	my $ret;
	eval { $ret = $kmdb->query("appid$i"); };

	ok(!$@, "query of appid$i");

	ok($ret->{principal}	eq "appid$i\@TEST.REALM", "appid$i princ true");
	is_deeply($ret->{owner}, ['admin_user@TEST.REALM'],
	    "appid$i owned correctly");
	ok(!defined($ret->{desc}), "appid$i desc is undef");
	is_deeply($ret->{cstraint}, [], "appid$i cstraint is empty");
}

#
# And let's populate the groups with some users and groups.

our $groups = {
	'group1'	=> [ 'elric@IMRRYR.ORG', 'yyrkoon@IMRRYR.ORG' ],
	'group2'	=> [ 'cymoril@IMRRYR.ORG', 'sadric@IMRRYR.ORG' ],
	'group3'	=> [ 'group1', 'group2' ],
	'group4'	=> [ 'group3' ],
	'group5'	=> [ 'group4' ],
	'group6'	=> [ 'group5' ],
	'group7'	=> [ 'group6' ],
	'group8'	=> [ 'group7' ],
	'group9'	=> [ 'group8' ],
	'group10'	=> [ 'group9' ],
	'group11'	=> [ 'group10' ],
	'group12'	=> [ 'group11' ],
	'group13'	=> [ 'group12' ],
	'group14'	=> [ 'group13' ],
	'group15'	=> [ 'group14' ],
	'group16'	=> [ 'group15' ],
	'group17'	=> [ 'group16' ],
	'master_group'	=> [ 'group17' ],
    };

for $i (keys %$groups) {
	for my $j (@{$groups->{$i}}) {
		testObjC("add members to a group", $kmdb, [], 'modify_group',
		    $i, add_member => [$j]);
	}
}

testObjC("Query ACL groups", $kmdb, [$groups], 'query_aclgroup');

#
# And finally, we assign ACLs to our appids and test them in various ways.
# XXXrcd: in these tests, the owner array is not necessary sorted in the
#         order that we have here.  It's an implementation detail and so
#         these tests may eventually fail with a working implementation.

testObjC("Assign ACL: assign owner", $kmdb, [undef], 'modify',
    'appid0', owner => ['elric@IMRRYR.ORG']);
#testObjC("Query appid0", $kmdb, [{owner=>['elric@IMRRYR.ORG'], desc=>undef,
#    cstraint=>[]}], 'query', 'appid0');

testObjC("Assign ACL: add_owner", $kmdb, [undef], 'modify',
    'appid0', add_owner => ['yyrkoon@IMRRYR.ORG']);
#testObjC("Query appid0", $kmdb,
#    [{owner=>['elric@IMRRYR.ORG','yyrkoon@IMRRYR.ORG'], desc=>undef,
#      cstraint=>[]}], 'query', 'appid0');

testObjC("Assign ACL: del_owner", $kmdb, [undef], 'modify',
    'appid0', del_owner => ['elric@IMRRYR.ORG']);
#testObjC("Query appid0", $kmdb,
#    [{owner=>['yyrkoon@IMRRYR.ORG'], desc=>undef, cstraint=>[]}],
#    'query', 'appid0');

testObjC("Assign Group ACL", $kmdb, [undef], 'modify',
    'appid1', add_owner => ['group1']);
testObjC("Assign Group ACL", $kmdb, [undef], 'modify',
    'appid2', owner => ['group2']);
testObjC("Assign Group ACL", $kmdb, [undef], 'modify',
    'appid3', add_owner => ['master_group']);

testObjC("Is owner #0?", $kmdb, [0], 'is_appid_owner', 'elric@IMRRYR.ORG',
    'appid0');
testObjC("Is owner #1?", $kmdb, [1], 'is_appid_owner', 'yyrkoon@IMRRYR.ORG',
    'appid0');
testObjC("Is owner #2?", $kmdb, [1], 'is_appid_owner', 'elric@IMRRYR.ORG',
    'appid1');
testObjC("Is owner #3?", $kmdb, [0], 'is_appid_owner', 'sadric@IMRRYR.ORG',
    'appid1');
testObjC("Is owner #4?", $kmdb, [0], 'is_appid_owner', 'elric@IMRRYR.ORG',
    'appid2');
testObjC("Is owner #5?", $kmdb, [1], 'is_appid_owner', 'sadric@IMRRYR.ORG',
    'appid2');
#testObjC("Is owner #6?", $kmdb, [1], 'is_appid_owner', 'elric@IMRRYR.ORG',
#    'appid3');
#testObjC("Is owner #7?", $kmdb, [1], 'is_appid_owner', 'sadric@IMRRYR.ORG',
#    'appid3');

$kmdb = mk_kmdb(CREDS => 'yyrkoon@IMRRYR.ORG');

testMustDie("Assign ACL: assign owner", $kmdb, 'modify',
    'appid0', owner => ['admin_user@TEST.REALM']);

undef $kmdb;

$kmdb = mk_kmdb(CREDS => 'admin_user@TEST.REALM');

for $i (0..3) {
	$kmdb->remove("appid$i");
}

undef $kmdb;

exit(0);
