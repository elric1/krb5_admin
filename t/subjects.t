#!/usr/bin/perl

use Test::More;

use Sys::Hostname;

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

sub create_normal_user_connect {
	my $kmdb_user = Krb5Admin::ForkClient->new({
			dbname	=> 'db:t/test-hdb',
			sqlite	=> 't/sqlite.db',
			}, CREDS => 'normal_user@TEST.REALM');
	return $kmdb_user;
}

testMustNotDie("create_subject", $kmdb, "create_subject", 'subject_test1',
    type=>'group');
testMustNotDie("create_group", $kmdb, "create_group", 'subject_test2');
testMustNotDie("create_subject", $kmdb, "create_group", 'subject_test3');
testMustNotDie("create_subject with odd different", $kmdb,
    "create_subject", 'test_subject4', type=> 'group',
    owner=> ['normal_user@TEST.REALM']);

testObjC("query_subject", $kmdb,
    [{ member => [], owner => ['admin_user@TEST.REALM'], type => 'group' }],
    "query_subject", "subject_test1");

testObjC("query_subject", $kmdb,
    [{ member => [], owner => ['normal_user@TEST.REALM'], type => 'group' }],
    "query_subject", "test_subject4");

done_testing();
