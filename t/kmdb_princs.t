#!/usr/pkg/bin/perl

use Test::More tests => 39;

use Krb5Admin::KerberosDB;

use Data::Dumper;

use strict;
use warnings;

sub compare_keys {
	my ($princ, $keys, $testname) = @_;
	my %lhs;
	my %rhs;

	for my $k (@{$princ->{keys}}) {
		if (exists($k->{key})) {
			$lhs{$k->{enctype} . ":" . $k->{kvno}} = $k->{key};
		} else {
			$lhs{$k->{enctype} . ":" . $k->{kvno}} = 1;
		}
	}

	for my $k (@{$keys}) {
		if (exists($k->{key})) {
			$rhs{$k->{enctype} . ":" . $k->{kvno}} = $k->{key};
		} else {
			$rhs{$k->{enctype} . ":" . $k->{kvno}} = 1;
		}
	}

	is_deeply(\%lhs, \%rhs, $testname);
}

sub compare_princ_to_attrs {
	my ($princ, $attrs, $testname) = @_;

	is_deeply([sort @{$princ->{attributes}}], [sort @{$attrs}], $testname);
}

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

$ENV{'KRB5_CONFIG'} = 't/krb5.conf';

my $sprinc = 'service@TEST.REALM';
my $uprinc = 'user@TEST.REALM';

my $kmdb;

$kmdb = Krb5Admin::KerberosDB->new(
    local	=> 1,
    client	=> 'host/hostA.test.realm@TEST.REALM',
    dbname	=> 'db:t/test-hdb',
    acl_file	=> 't/krb5_admin.acl',
    sqlite	=> 't/sqlite.db',
);

#
# XXXrcd: This is destructive!

$kmdb->drop_db();
$kmdb->init_db();

my $p = "Aa1thisisapasswd!!!!";

#
# Let's just go through the basics.  We dropped the DB and our creation
# routines leave a completely empty DB.  We are starting with kvno = 1,
# which is slightly different than the MIT default but we're only really
# testing on Heimdal at the moment and our stuff works a tad differently,
# anyway.

testObjC("create", $kmdb, [undef], 'create', $sprinc);
testObjC("create_user", $kmdb, [$p], 'create_user', $uprinc, $p);

#
# Now, we test to ensure that the princs are what we expect them to be.

testObjC("list", $kmdb, [$uprinc, $sprinc], 'list');

my $result;

$result = $kmdb->query('user');

ok($result->{policy} eq 'default', qq{user policy is ``default''});
ok($result->{principal} eq $uprinc, qq{query returned correct princ});
compare_princ_to_attrs($result, [qw/+requires_preauth -allow_svr +needchange/],
    "user has correct attributes 1");
compare_keys($result, [
		{enctype=>18,kvno=>1},
		{enctype=>16,kvno=>1},
		{enctype=>23,kvno=>1}
	], "user has correct key types 1");

$result = $kmdb->query('service');

ok($result->{policy} eq 'default', qq{service policy is ``default''});
ok($result->{principal} eq $sprinc, qq{query returned correct princ});
compare_princ_to_attrs($result, [], "service has correct attributes");
compare_keys($result, [
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 1");

#
# MODIFY AND TEST...

testObjC("change", $kmdb, [undef], 'change', $sprinc, 3, [{enctype=>17,
    key=>'0123456789abcdef'}]);
$result = $kmdb->query('service');
compare_keys($result, [
		{enctype=>17,kvno=>3},
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 2");

testObjC("change", $kmdb, [undef], 'change', $sprinc, 4, keys => [{enctype=>17,
    key=>'0123456789ABCDEF'}]);
$result = $kmdb->query('service');
compare_keys($result, [
		{enctype=>17,kvno=>4},
		{enctype=>17,kvno=>3},
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 3");

testObjC("change_passwd", $kmdb, ["${p}1"], 'change_passwd', $uprinc, "${p}1");
$result = $kmdb->query('user');
compare_keys($result, [
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "user has correct key types 2");
compare_princ_to_attrs($result, [qw/+requires_preauth -allow_svr/],
    "user has correct attributes 2");

#
# Test enable, disable:

testObjC("disable", $kmdb, [undef], 'disable', 'user');
$result = $kmdb->query('user');
compare_princ_to_attrs($result, [qw/-allow_tix +requires_preauth -allow_svr/],
    "user has correct attributes 2");

testObjC("enable", $kmdb, [undef], 'enable', 'user');
$result = $kmdb->query('user');
compare_princ_to_attrs($result, [qw/+requires_preauth -allow_svr/],
    "user has correct attributes 2");

#
# Test mquery and remove.

my @results;
eval {
	@results = $kmdb->mquery();
};

ok(!$@, "mquery works") or diag($@);

if (!$@) {
	my %allprincs;

	for my $princ (@results) {
		$allprincs{$princ->{principal}} = $princ;
	}

	compare_keys($allprincs{$uprinc}, [
			{enctype=>18,kvno=>2},
			{enctype=>16,kvno=>2},
			{enctype=>23,kvno=>2}
		], "user has correct key types in mquery");
	compare_princ_to_attrs($allprincs{$uprinc},
	    [qw/+requires_preauth -allow_svr/],
	    "user has correct attributes in mquery");
	delete $allprincs{$uprinc};

	compare_keys($allprincs{$sprinc}, [
			{enctype=>17,kvno=>4},
			{enctype=>17,kvno=>3},
			{enctype=>18,kvno=>2},
			{enctype=>16,kvno=>2},
			{enctype=>23,kvno=>2}
		], "service has correct key types in mquery");
	compare_princ_to_attrs($allprincs{$sprinc}, [],
	    "service has correct attributes in mquery");
	delete $allprincs{$sprinc};

	ok(keys %allprincs == 0, "mquery returned no extra results");
}

testObjC("remove user", $kmdb, [undef], 'remove', 'user');
testObjC("remove service", $kmdb, [undef], 'remove', 'service');

#
# Let's try to test the new ECDH key negotiation for create.

my $gend;
eval {
	my @etypes = (16, 17, 18, 23);

	$gend = $kmdb->genkeys('ecdh', 1, @etypes);

	$kmdb->create('ecdh', public => $gend->{public}, enctypes => \@etypes);
};

ok(!$@, "genkeys/create did not toss an exception") or diag(Dumper($@));

$result->{keys} = [$kmdb->fetch('ecdh')];
compare_keys($result, $gend->{keys}, "ecdh after create keys are the same");

#
# And ECDH for change...

eval {
	my @etypes = (17, 18);

	$gend = $kmdb->genkeys('ecdh', 2, @etypes);

	$kmdb->change('ecdh', 2, public => $gend->{public},
	    enctypes => \@etypes);
};
ok(!$@, "genkeys/change did not toss an exception") or diag($@);

$result->{keys} = [$kmdb->fetch('ecdh')];
compare_keys($result, $gend->{keys}, "ecdh after change keys are the same");

#
# Now we should try to create a bootstrap id:

my $binding;
eval {
	$gend = $kmdb->genkeys('bootstrap', 1, 18);
	$binding = $kmdb->create_bootstrap_id(public => $gend->{public},
	    enctypes => [18]);
	$gend = $kmdb->regenkeys($binding, $gend);
};
ok(!$@, "genkeys/create_bootstrap_id did not toss an exception") or diag($@);

$result->{keys} = [$kmdb->fetch($binding)];
compare_keys($result, $gend->{keys}, "$binding\'s keys after " .
    "create_bootstrap_id are the same");

my $host = 'boundhost.test.realm';
eval {
	$kmdb->create_host($host, realm => 'TEST.REALM');
	$kmdb->bind_host($host, $binding);
};
ok(!$@, "bind_host did not toss an exception") or diag($@);

my $hostprinc = "host/$host\@TEST.REALM";
eval {
	my $kmdb = Krb5Admin::KerberosDB->new(
	    client	=> $binding,
	    dbname	=> 'db:t/test-hdb',
	    acl_file	=> 't/krb5_admin.acl',
	    sqlite	=> 't/sqlite.db',
	);

	$gend = $kmdb->genkeys("host/$host\@TEST.REALM", 1, 17, 18);
	$kmdb->bootstrap_host_key($host, public => $gend->{public},
	    enctypes => [17, 18]);
};
ok(!$@, "genkeys/bootstrap_host_key did not toss an exception")
    or diag(Dumper($@));

$result->{keys} = [$kmdb->fetch($hostprinc)];
compare_keys($result, $gend->{keys}, "$hostprinc\'s keys after " .
    "bootstrap_host_key() are the same");

exit(0);
