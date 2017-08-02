#!/usr/pkg/bin/perl
#

use Test::More tests => 1;

use Krb5Admin::ForkClient;

use strict;
use warnings;

sub kid_logic {
	my ($postfix, $max) = @_;

	my $kmdb = Krb5Admin::ForkClient->new({
	    dbname	=> 'db:t/test-hdb',
	    sqlite	=> 't/sqlite.db',
	}, CREDS => 'admin_user@TEST.REALM');

	for my $i (1..$max) {
		$kmdb->create_host("a-$i.$postfix", realm => 'TEST.REALM');
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

my $nprocs = 20;
my $nprincs = 50;

$ENV{KRB5_CONFIG} = './t/krb5.conf';

my %kids;

for my $i (1..$nprocs) {
	my $kid = start_kid(\&kid_logic, "concurrency.$i", $nprincs);

	$kids{$kid} = 1;
}

my %failures;
while (keys %kids > 0) {
	my $pid = wait();
	$failures{$pid} = 1 if $? != 0;
	delete $kids{$pid};
}

ok(keys %failures == 0, (keys %failures) . " had locking failures");

exit(0);
