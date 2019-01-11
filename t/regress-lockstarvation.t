#!/usr/pkg/bin/perl
#

use Data::Dumper;
use Test::More tests => 4;

use Krb5Admin::ForkClient;

use strict;
use warnings;

$ENV{KRB5_CONFIG} = './t/krb5.conf';

sub mk_kmdb {
        Krb5Admin::ForkClient->new({config => './t/krb5_admind.conf'},
	    CREDS => 'admin_user@TEST.REALM');
}

my $kmdb1;
my $kmdb3;
eval {
	$kmdb1 = mk_kmdb();
	$kmdb3 = mk_kmdb();
};

ok(!$@, "creating connexions: ". Dumper($@));

eval {
	$kmdb1->create_host("test1.test.realm", realm => 'TEST.REALM',
	    is_logical => 1, owner => ['admin_user@TEST.REALM']);
	$kmdb1->create_host("test2.test.realm", realm => 'TEST.REALM');
	$kmdb1->create('test/test1.test.realm@TEST.REALM');
};
ok(!$@, "creating DB objects: ". Dumper($@));

eval {
	$kmdb1->lock_hostprinc('test/test1.test.realm@TEST.REALM');
};
ok(!$@, "lock_hostprinc: ". Dumper($@));

my $kid = fork();

if ($kid == 0) {
	# I am the child

	local $SIG{ALRM} = sub { die "FOO!\n" };
	alarm(30);
	eval {
		my $kmdb2 = mk_kmdb();
		$kmdb2->modify_host("test1.test.realm",
		    add_member => ['test2.test.realm']);
	};

	exit(0);
}

#
# Time this!

eval {
	local $SIG{ALRM} = sub { die "Lock contention!!!\n" };
	sleep(3);
	alarm(10);
	$kmdb3->create_host("test3.test.realm", realm => 'TEST.REALM');
};

ok(!$@, "query: $@");

eval { $kmdb1->unlock_hostprinc('test/test1.test.realm@TEST.REALM'); };
eval {
	$kmdb1->modify_host("test1.test.realm",
	   del_member => ['test2.test.realm']);
};
eval { $kmdb1->remove_host("test1.test.realm"); };
eval { $kmdb1->remove_host("test2.test.realm"); };
eval { $kmdb1->remove_host("test3.test.realm"); };
eval { $kmdb1->remove('test/test1.test.realm@TEST.REALM'); };

exit(0);
