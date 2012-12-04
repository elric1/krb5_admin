#!/usr/pkg/bin/perl

use Test::More tests => 4;

use Sys::Hostname;

use Krb5Admin::KerberosDB;
use Krb5Admin::Krb5Host::Local;

use Data::Dumper;

use strict;
use warnings;

our $KRB5_KEYTAB_CONFIG = './t/krb5_keytab.conf';

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

#
# XXXrcd: THIS MASKS A BUG THAT WE NEED TO FIND!:
unlink('t/keytabs/root');

#
# As a first step, we start a kdc using our local configuration.  This
# will respond to requests made to TEST.REALM against our test database.
# We need to be able to respond to anonymous PKINIT requests, so we set
# up the certs first.

unlink('t/ca.pem');
unlink('t/kdc.pem');

no warnings;

system(qw{hxtool issue-certificate --self-signed --issue-ca
    --generate-key=rsa --subject=CN=CA,DC=test,DC=realm
    --lifetime=1hour --certificate=FILE:t/ca.pem});

system(qw{hxtool issue-certificate --ca-certificate=FILE:t/ca.pem
    --generate-key=rsa --type=pkinit-kdc
    --pk-init-principal=krbtgt/TEST.REALM@TEST.REALM
    --subject=uid=kdc,DC=test,DC=realm
    --certificate=FILE:t/kdc.pem});

use warnings;

my $kdc_pid = fork();
exit(1) if $kdc_pid == -1;
if ($kdc_pid == 0) {
	exec {'/usr/sbin/kdc'} qw/kdc/;
	exit(1);
}
ok(1);
diag("Started kdc for testing\n");

my $krb5_admind_pid = fork();
exit(1) if $krb5_admind_pid == -1;
if ($krb5_admind_pid == 0) {
	$ENV{'KRB5_KTNAME'} = 'FILE:t/keytabs/root';
	exec {'knc'} qw{knc -l krb5_admin /usr/pkg/bin/perl
			-Iblib/lib -Iblib/arch ./scripts/krb5_admind -M
			-S t/sqlite.db
		};
	exit(1);
}
ok(1);
diag("Started krb5_admind for testing\n");
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
		verbose			=>  $verbose,
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

my $kmdb = Krb5Admin::KerberosDB->new(
    local	=> 1,
    client	=> 'root@TEST.REALM',
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
);

do $KRB5_KEYTAB_CONFIG if -f $KRB5_KEYTAB_CONFIG;
diag $@ if $@;

my $kt;

$kt = get_kt(local => 1);
$kt->install_keytab('root', undef, 'krb5_admin/' . hostname() . '@TEST.REALM');
undef($kt);

#
# XXXrcd: in order to do this properly, we're going to have to stop
#         running everything locally and fire up a krb5_admind on the
#         host to chat with.  Or perhaps, we should use ForkClient
#         to get something a little more under our control for our
#         test environment.  Otherwise, much of the test functionality
#         will not actually be properly tested...

$kt = get_kt();

my $binding;
eval {
	($binding) = $kt->install_keytab('root', undef, 'bootstrap/RANDOM');
};
ok(!$@, Dumper($@));

$kmdb->create_host(hostname(), realm => 'TEST.REALM');
$kmdb->bind_host(hostname(), $binding);

eval { $kt->install_keytab('root', undef, 'host'); };
ok(!$@, Dumper($@));

diag("Killing kdc.\n");
kill(15, $kdc_pid);
kill(15, $krb5_admind_pid);
exit(0);
