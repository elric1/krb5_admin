#!/usr/pkg/bin/perl

use Test::More tests => 2;

use Krb5Admin::Krb5Host::Local;

use Data::Dumper;

use strict;
use warnings;

our $KRB5_KEYTAB_CONFIG = './t/krb5_keytab.conf';

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

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

#
# As a first step, we start a kdc using our local configuration.  This
# will respond to requests made to TEST.REALM against our test database:

my $pid = fork();
exit(1) if $pid == -1;
if ($pid == 0) {
	exec {'/usr/sbin/kdc'} qw/kdc/;
	exit(1);
}
ok(1);
diag("Started kdc for testing\n");
sleep(2);

#
# These variables are expected to be set in the configuration file:

our $verbose = 0;
our %user2service = ();
our @allowed_enctypes = ();
our @admin_users = ();
our %krb5_libs = ();
our %krb5_lib_quirks = ();
our $default_krb5_lib = ();
our %user_libs = ();
our $use_fetch = 0;

#
# Done: config file.

sub get_kt {

	return Krb5Admin::Krb5Host::Local->new(
		local			=> 1,
		invoking_user		=> 'root',
		user2service            => \%user2service,
		allowed_enctypes        => \@allowed_enctypes,
		admin_users             => \@admin_users,
		krb5_libs               => \%krb5_libs,
		krb5_lib_quirks         => \%krb5_lib_quirks,
		default_krb5_lib        =>  $default_krb5_lib,
		user_libs               => \%user_libs,
		use_fetch               =>  $use_fetch,
		ktdir			=>  './t/keytabs',
		lockdir			=>  './t/krb5host.lock',
		testing			=> 1,
		@_,
	);
}

do $KRB5_KEYTAB_CONFIG if -f $KRB5_KEYTAB_CONFIG;
diag $@ if $@;

my $kt = get_kt();

eval { $kt->install_keytab('root', undef, 'bootstrap/RANDOM'); };

ok(!$@, Dumper($@));

diag("Killing kdc.\n");
kill(15, $pid);
exit(0);
