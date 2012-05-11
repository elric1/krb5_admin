#!/usr/pkg/bin/perl
#

#
# XXXrcd: these tests only really test the interfaces and to some degree
#         that the functions appears to be working in terms of the other
#         functions.  They _should_ also test that passwds actually work,
#         but they do not yet.  That would require firing up a KDC which
#         we'll eventually do.

use Test::More tests => 1;

use Data::Dumper;

use Krb5Admin::C;

use strict;
use warnings;

use constant {
	DISALLOW_POSTDATED      => 0x00000001,
	DISALLOW_FORWARDABLE    => 0x00000002,
	DISALLOW_TGT_BASED      => 0x00000004,
	DISALLOW_RENEWABLE      => 0x00000008,
	DISALLOW_PROXIABLE      => 0x00000010,
	DISALLOW_DUP_SKEY       => 0x00000020,
	DISALLOW_ALL_TIX        => 0x00000040,
	REQUIRES_PRE_AUTH       => 0x00000080,
	REQUIRES_HW_AUTH        => 0x00000100,
	REQUIRES_PWCHANGE       => 0x00000200,
	UNKNOWN_0x00000400      => 0x00000400,
	UNKNOWN_0x00000800      => 0x00000800,
	DISALLOW_SVR            => 0x00001000,
	PWCHANGE_SERVICE        => 0x00002000,
	SUPPORT_DESMD5          => 0x00004000,
	NEW_PRINC               => 0x00008000,
	ACL_FILE                => '/etc/krb5/krb5_admin.acl',
};

#
# We fork a number of kids who are expected to create principals.  We are
# really testing the concurrency of Kerberos DB access, here.  The principals
# are of the form: concurrency.$kid_number.$loop_counter.  We will then check
# to ensure that we have created all of the correct principals.

sub kid_logic {
	my ($prefix, $max) = @_;

	my  $ctx   = Krb5Admin::C::krb5_init_context();
	our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, 'db:t/test-hdb');

	for my $i (1..$max) {
diag("create $prefix.$i\n");
		Krb5Admin::C::krb5_createkey($ctx, $hndl, "$prefix.$i");
#		Krb5Admin::C::krb5_createprinc($ctx, $hndl, {
#			principal	=> "$prefix.$i",
#			policy 		=> 'default',
#			attributes	=> REQUIRES_PRE_AUTH | DISALLOW_SVR,
#		}, [], undef);
	}
}

sub start_kid {
	my ($func, @args) = @_;
	my $kid;

	$kid = fork();

	if (!defined($kid)) {
		die "Cannot fork: $!";
	}

	if ($kid > 0) {
		return $kid;
	}

	&$func(@args);
	exit 0;
}

$ENV{KRB5_CONFIG} = 'FILE:./t/krb5.conf';

my $ctx   = Krb5Admin::C::krb5_init_context();
my $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, 'db:t/test-hdb');

Krb5Admin::C::init_kdb($ctx, $hndl);

undef $ctx;
undef $hndl;

my %kids;

for my $i (1..20) {
	my $kid = start_kid(\&kid_logic, "concurrency.$i", 100);

	$kids{$kid} = 1;
}

while (keys %kids > 0) {
	my $pid = wait();

diag("$pid exited, remaining kids = " . (keys %kids));

	delete $kids{$pid};
}

#
# Now, we expect to have created concurrency.(0..20).(0..5000), so let's find
# out...

$ctx   = Krb5Admin::C::krb5_init_context();
$hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, 'db:t/test-hdb');

my $results = Krb5Admin::C::krb5_list_princs($ctx, $hndl, "concurrency." . "*");

diag(Dumper($results));
diag("list has " . @$results . "\n");

ok(1);

exit(0);
