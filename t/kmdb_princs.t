#!/usr/pkg/bin/perl

use Test::More tests => 16;

use Krb5Admin::KerberosDB;

use Data::Dumper;

use strict;
use warnings;

sub compare_keytypes {
	my ($princ, $keys, $testname) = @_;
	my %lhs;
	my %rhs;

	for my $k (@{$princ->{keys}}) {
		$lhs{$k->{enctype} . ":" . $k->{kvno}} = 1;
	}

	for my $k (@{$keys}) {
		$rhs{$k->{enctype} . ":" . $k->{kvno}} = 1;
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

my $p = "Aa1thisisapasswd!!!!";

#
# Let's just go through the basics.  We dropped the DB and our creation
# routines leave a completely empty DB.  We are starting with kvno = 1,
# which is slightly different than the MIT default but we're only really
# testing on Heimdal at the moment and our stuff works a tad differently,
# anyway.

testObjC("create", $kmdb, [undef], 'create', 'service');
testObjC("create_user", $kmdb, [$p], 'create_user', 'user', $p);

#
# Now, we test to ensure that the princs are what we expect them to be.

testObjC("list", $kmdb, [ map { "$_\@IMRRYR.ORG" } (qw/user service/)], 'list');

my $result;

$result = $kmdb->query('user');

ok($result->{policy} eq 'default', qq{user policy is ``default''});
ok($result->{principal} eq 'user@IMRRYR.ORG', qq{query returned correct princ});
compare_princ_to_attrs($result, [qw/+requires_preauth -allow_svr +needchange/],
    "user has correct attributes 1");
compare_keytypes($result, [
		{enctype=>18,kvno=>1},
		{enctype=>16,kvno=>1},
		{enctype=>23,kvno=>1}
	], "user has correct key types 1");

$result = $kmdb->query('service');

ok($result->{policy} eq 'default', qq{user policy is ``default''});
ok($result->{principal} eq 'service@IMRRYR.ORG',
    qq{query returned correct princ});
compare_princ_to_attrs($result, [], "user has correct attributes");
compare_keytypes($result, [
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 1");

#
# MODIFY AND TEST...

testObjC("change", $kmdb, [undef], 'change', 'service', 3, [{enctype=>17,
    key=>'0123456789abcdef'}]);
$result = $kmdb->query('service');
compare_keytypes($result, [
		{enctype=>17,kvno=>3},
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "service has correct key types 2");

testObjC("change_passwd", $kmdb, ["${p}1"], 'change_passwd', 'user', "${p}1");
$result = $kmdb->query('user');
compare_keytypes($result, [
		{enctype=>18,kvno=>2},
		{enctype=>16,kvno=>2},
		{enctype=>23,kvno=>2}
	], "user has correct key types 2");
compare_princ_to_attrs($result, [qw/+requires_preauth -allow_svr/],
    "user has correct attributes 2");

#
# Test mquery, enable, disable and remove.


exit(0);
