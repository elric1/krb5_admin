#!/usr/pkg/bin/perl

use Test::More tests => 47;

use Sys::Hostname;

use Kharon::Entitlement::Object;
use Kharon::Entitlement::SimpleSQL;

use Krb5Admin::C;
use Krb5Admin::ForkClient;

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

sub mk_kmdb {
	Krb5Admin::ForkClient->new({
	    allow_fetch	=> 1,
	    config	=> './t/krb5_admind.conf'
	}, @_);
}

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

my $creds  = 'admin_user@TEST.REALM';
my $sprinc = 'service/host1.test.realm@TEST.REALM';
my $uprinc = 'user@TEST.REALM';
my $anon   = 'WELLKNOWN/ANONYMOUS@TEST.REALM';
my $tgt    = 'krbtgt/TEST.REALM@TEST.REALM';
my $myhost = 'krb5_admin/' . hostname() . '@TEST.REALM';
my $def    = 'default@TEST.REALM';

my $p = "Aa1thisisapasswd!!!!";

#
# Let's just go through the basics.  We dropped the DB and our creation
# routines leave a completely empty DB.  We are starting with kvno = 1,
# which is slightly different than the MIT default but we're only really
# testing on Heimdal at the moment and our stuff works a tad differently,
# anyway.  We create a new Krb5Admin::ForkClient because we want to test
# the ACLs and the protocol.

my $kmdb = mk_kmdb(CREDS => $creds);

testObjC("create", $kmdb, [undef], 'create', $sprinc);
testObjC("create_user", $kmdb, [$p], 'create_user', $uprinc, $p);

#
# Now, we test to ensure that the princs are what we expect them to be.
#
# XXX: order of "list" results depends on HDB storage format, this
# will break if Heimdal's encoding of principals or the underlying
# database engine change.

my @princs;
eval { @princs = $kmdb->list(); };
if ($@) {
	ok(0, "list");
	diag(Dumper($@));
} else {
	is_deeply([sort @princs],
	    [sort ($uprinc, $anon, $sprinc, , $tgt, $def, $myhost)],
	    "list");
}

my $result;

$result = $kmdb->query($uprinc);

ok($result->{policy} eq 'default', qq{user policy is ``default''});
ok($result->{principal} eq $uprinc, qq{query returned correct princ});
compare_princ_to_attrs($result, [qw/+requires_preauth -allow_svr +needchange/],
    "user has correct attributes 1");
compare_keys($result, [
		{enctype=>18,kvno=>1},
		{enctype=>16,kvno=>1},
		{enctype=>23,kvno=>1}
	], "user has correct key types 1");

$result = $kmdb->query($sprinc);

ok($result->{policy} eq 'default', qq{service policy is ``default''});
ok($result->{principal} eq $sprinc, qq{query returned correct princ});
compare_princ_to_attrs($result, [], "service has correct attributes");
compare_keys($result, [
		{enctype=>17,kvno=>2},
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 1");

#
# Change some attributes:

my $result0;
my $result1;
my $result2;
eval {
		$kmdb->modify($uprinc, del_attributes => ['needchange']);
		$result0 = $kmdb->query($uprinc);

		$kmdb->modify($uprinc, del_attributes => ['allow_tix']);
		$result1 = $kmdb->query($uprinc);

		$kmdb->modify($uprinc, add_attributes => ['allow_tix']);
		$result2 = $kmdb->query($uprinc);
};
if ($@) {
	ok(0, "Exception: " . Dumper($@));
	ok(1, "user has correct attributes after modification #0");
	ok(1, "user has correct attributes after modification #1");
	ok(1, "user has correct attributes after modification #2");
} else {
	ok(1, "Exception: ");
	compare_princ_to_attrs($result0,
	    [qw/+requires_preauth -allow_svr/],
	    "user has correct attributes after modification #0");
	compare_princ_to_attrs($result1,
	    [qw/+requires_preauth -allow_svr -allow_tix/],
	    "user has correct attributes after modification #1");
	compare_princ_to_attrs($result2,
	    [qw/+requires_preauth -allow_svr/],
	    "user has correct attributes after modification #2");
}

#
# MODIFY AND TEST...

testObjC("change", $kmdb, [undef], 'change', $sprinc, 3, [{enctype=>17,
    key=>'0123456789abcdef'}]);
$result = $kmdb->query($sprinc);
compare_keys($result, [
		{enctype=>17,kvno=>3},
		{enctype=>17,kvno=>2},
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 2");

testObjC("change", $kmdb, [undef], 'change', $sprinc, 4, keys => [{enctype=>17,
    key=>'0123456789ABCDEF'}]);
$result = $kmdb->query($sprinc);
compare_keys($result, [
		{enctype=>17,kvno=>4},
		{enctype=>17,kvno=>3},
		{enctype=>17,kvno=>2},
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 3");

testObjC("change_passwd", $kmdb, ["${p}1"], 'change_passwd', $uprinc, "${p}1");
$result = $kmdb->query($uprinc);
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
$result = $kmdb->query($uprinc);
compare_princ_to_attrs($result, [qw/-allow_tix +requires_preauth -allow_svr/],
    "user has correct attributes 2");

testObjC("enable", $kmdb, [undef], 'enable', 'user');
$result = $kmdb->query($uprinc);
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
			{enctype=>17,kvno=>2},
			{enctype=>18,kvno=>2},
			{enctype=>16,kvno=>2},
			{enctype=>23,kvno=>2}
		], "service has correct key types in mquery");
	compare_princ_to_attrs($allprincs{$sprinc}, [],
	    "service has correct attributes in mquery");
	delete $allprincs{$sprinc};

	delete $allprincs{$anon};
	delete $allprincs{$myhost};
	delete $allprincs{$tgt};
	delete $allprincs{$def};

	ok(keys %allprincs == 0, "mquery returned no extra results");
}

testObjC("remove user", $kmdb, [undef], 'remove', $uprinc);
testObjC("remove service", $kmdb, [undef], 'remove', $sprinc);


# ----------------------------------------------------------------------
#		BEGIN DEPRECATED TEST FUNCTIONALITY
#
#  Below this point, we are testing deprecated functionality which has
#  not made it into an official release and hence may be removed at a
#  moment's notice...  We'll continue to support it for the time being
#  by merely refusing to modify it in the slightest...
#
#
#  NOTE: Well, honestly, this isn't deprecated quite yet, but it is on
#        its way...
# ----------------------------------------------------------------------

my $gend;
eval {
	my @etypes = (16, 17, 18, 23);

	$gend = $kmdb->genkeys('create', 'ecdh', 1, @etypes);

	$kmdb->create('ecdh', public => $gend->{public}, enctypes => \@etypes);
};

ok(!$@, "genkeys/create did not toss an exception") or diag(Dumper($@));

$result = {};
eval {
	$result->{keys} = [$kmdb->fetch('ecdh')];
};

ok(!$@, "able to fetch ecdh keys") or diag(Dumper($@));

compare_keys($result, $gend->{keys}, "ecdh after create keys are the same");

#
# And ECDH for change...

eval {
	my @etypes = (17, 18);

	$gend = $kmdb->genkeys('change', 'ecdh', 2, @etypes);

	$kmdb->change('ecdh', 2, public => $gend->{public},
	    enctypes => \@etypes);
};
ok(!$@, "genkeys/change did not toss an exception") or diag($@);

$result = {};
eval {
	$result->{keys} = [$kmdb->fetch('ecdh')];
};
ok(!$@, "able to fetch ecdh keys") or diag(Dumper($@));
compare_keys($result, $gend->{keys}, "ecdh after change keys are the same");

#
# Now we should try to create a bootstrap id:

$kmdb->sacls_add('bind_host', $creds);
my $binding;
eval {
	$kmdb = mk_kmdb(CREDS => $anon);

	$gend = $kmdb->genkeys('create_bootstrap_id', 'bootstrap', 1, 18);
	$binding = $kmdb->create_bootstrap_id(public => $gend->{public},
	    enctypes => [18], realm => 'TEST.REALM');
	$gend = $kmdb->regenkeys($gend, $binding);
};
ok(!$@, "genkeys/create_bootstrap_id did not toss an exception")
    or diag(Dumper($@));

$kmdb = mk_kmdb(CREDS => $creds);

$result = {};
eval {
	$result->{keys} = [$kmdb->fetch($binding)];
};
ok(!$@, "able to fetch binding keys") or diag(Dumper($@));
compare_keys($result, $gend->{keys}, "$binding\'s keys after " .
    "create_bootstrap_id are the same");

my $host = 'boundhost.test.realm';
eval {
	$kmdb->create_host($host, realm => 'TEST.REALM');
	$kmdb->bind_host($host, $binding);
};
ok(!$@, "bind_host did not toss an exception") or diag(Dumper($@));

my $hostprinc = "host/$host\@TEST.REALM";
eval {
	$kmdb = mk_kmdb(CREDS => $binding);

	$gend = $kmdb->genkeys('bootstrap_host_key', $hostprinc,
	    1, 17, 18);
	$kmdb->bootstrap_host_key($hostprinc, 1,
	    public => $gend->{public}, enctypes => [17, 18]);
};
ok(!$@, "genkeys/bootstrap_host_key did not toss an exception")
    or diag(Dumper($@));

$kmdb = mk_kmdb(CREDS => $creds);

$result = {};
eval {
	$result->{keys} = [$kmdb->fetch($hostprinc)];
};
ok(!$@, "able to fetch host keys") or diag(Dumper($@));
compare_keys($result, $gend->{keys}, "$hostprinc\'s keys after " .
    "bootstrap_host_key() are the same");

exit(0);
