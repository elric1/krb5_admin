#!/usr/pkg/bin/perl

use Test::More tests => 30;

use Sys::Hostname;

use Krb5Admin::KerberosDB;
use Krb5Admin::Krb5Host::Local;

use Data::Dumper;

use strict;
use warnings;

our $KRB5_KEYTAB_CONFIG = './t/krb5_keytab.conf';
my $hostname = hostname();

# Find Kerberos binaries
#
my $KRB5TYPE = "heimdal";	# Heimdal by default!
$KRB5TYPE = $ENV{KRB5TYPE}	if defined($ENV{KRB5TYPE});
my $KRB5DIR;
$KRB5DIR = $ENV{KRB5DIR}	if defined($ENV{KRB5DIR});
for my $dir (qw{/usr /usr/local /usr/pkg /opt/heimdal}) {
	last	if defined($KRB5DIR);

	if ($KRB5TYPE eq "mit" && -f "$dir/lib/libgssapi_krb5.so") {
		$KRB5DIR = $dir;
	}

	if ($KRB5TYPE eq "heimdal" && -f "$dir/lib/libgssapi.so") {
		$KRB5DIR = $dir;
	}
}
if (!defined($KRB5DIR)) {
	die "Can't find the Kerberos libraries.\n";
}
if ($KRB5TYPE != 'heimdal' && $KRB5TYPE != 'mit') {
	die "Unrecognised Kerberos type: " . $KRB5TYPE .
	    ".  Must be mit or heimdal.\n";
}
$ENV{'PATH'} = "$KRB5DIR/bin:$KRB5DIR/sbin:".$ENV{PATH};

$ENV{'KRB5_CONFIG'} = './t/krb5.conf';

#
# XXXrcd: THIS MASKS A BUG THAT WE NEED TO FIND!:
unlink('t/keytabs/root');
unlink('t/keytabs/elric');

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
	exec { "$KRB5DIR/libexec/kdc" } qw/kdc/;
	exit(1);
}
ok(1);

my $krb5_admind_pid = fork();
exit(1) if $krb5_admind_pid == -1;
if ($krb5_admind_pid == 0) {
	$ENV{'KRB5_KTNAME'} = 'FILE:t/keytabs/root';
	exec {'knc'} qw{knc -l krb5_admin -- /usr/bin/perl
			-Iblib/lib -Iblib/arch ./scripts/krb5_admind -M
			-S t/sqlite.db
		};
	exit(1);
}
ok(1);
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

sub mk_kte {
	my ($ctx, $princ, $kvno, $enctype) = @_;

	my $key = Krb5Admin::C::krb5_make_a_key($ctx, $enctype);
 
	$key->{princ} = $princ;
	$key->{kvno}  = $kvno;
 
	return $key;
}

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

my $ctx = Krb5Admin::C::krb5_init_context();

my $kmdb = Krb5Admin::KerberosDB->new(
    local	=> 1,
    client	=> 'root@TEST.REALM',
    dbname	=> 'db:t/test-hdb',
    sqlite	=> 't/sqlite.db',
);

do $KRB5_KEYTAB_CONFIG if -f $KRB5_KEYTAB_CONFIG;
diag $@ if $@;

my $kt;

$kt = get_kt(local => 1, kmdb => $kmdb);
eval {
	$kt->install_keytab('root', undef,
	    'krb5_admin/' . $hostname . '@TEST.REALM');
};
ok(!$@, Dumper($@));
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

eval {
	$kmdb->create_host($hostname, realm => 'TEST.REALM');
	$kmdb->bind_host($hostname, $binding);
};
ok(!$@, Dumper($@));

eval { $kt->install_keytab('root', undef, 'host'); };
ok(!$@, Dumper($@));

#
# Okay, now we have a host key and so we can try to install some service
# keys...

my $me = `id -un`;
chomp($me);

eval { $kt->install_keytab('root', undef, 'nfs'); };
ok(!$@, Dumper($@));
eval { $kt->install_keytab($me, undef, $me); };
ok(!$@, Dumper($@));

#
# We should be able to ``install'' them again which should result
# in no action being taken:

eval { $kt->install_keytab('root', undef, 'nfs'); };
ok(!$@, Dumper($@));
eval { $kt->install_keytab($me, undef, $me); };
ok(!$@, Dumper($@));

#
# Now, how about if we mess up the keys?  We specifically add AES
# keys and will use mitkrb5/1.3 to see if they are left in place.

for my $etype (16, 17, 18, 23) {
	eval {
		Krb5Admin::C::write_kt($ctx, "WRFILE:t/keytabs/$me",
		    mk_kte($ctx, "$me/$hostname", 2, $etype));
	};
	ok(!$@, Dumper($@));
}

for my $etype (16, 17, 18, 23) {
	eval {
		my $key = mk_kte($ctx, "$me/$hostname", 3, $etype);
		Krb5Admin::C::write_kt($ctx, "WRFILE:t/keytabs/$me", $key);
	};
	ok(!$@, Dumper($@));
}

#
# We should be able to ``install'' them again which should result
# in new keys being generated with kvno == 3.

eval { $kt->install_keytab($me, 'mitkrb5/1.3', $me); };
ok(!$@, Dumper($@));

my @keys;
eval { @keys = Krb5Admin::C::read_kt($ctx, "t/keytabs/$me"); };
ok(!$@, Dumper($@));
ok((grep { $_->{kvno} == 3 } @keys) > 0, "install replaced faulty keys");

#
# We also installed a bunch of incorrect keys of kvno == 3 to muddy
# the waters.  Let's make sure that they are gone...

ok(!(grep { $_->{kvno} == 3 && $_->{enctype} == 17 } @keys), "bad etype: 17");
ok(!(grep { $_->{kvno} == 3 && $_->{enctype} == 18 } @keys), "bad etype: 18");

#
# And let's see if we can rotate the keys:

eval { $kt->change_keytab('root', 'mitkrb5/1.3', 'host'); };
ok(!$@, Dumper($@));

eval { $kt->change_keytab('root', 'mitkrb5/1.3', 'host'); };
ok(!$@, Dumper($@));

eval { $kt->change_keytab('root', 'mitkrb5/1.4', 'host'); };
ok(!$@, Dumper($@));

eval { $kt->change_keytab('root', 'mitkrb5/1.3', 'nfs'); };
ok(!$@, Dumper($@));

eval { $kt->change_keytab($me, 'mitkrb5/1.3', $me); };
ok(!$@, Dumper($@));

#
# And, now, fetch some things and see if we get what we expect...

my $ret;
eval { $ret = $kt->query_keytab($me); };
ok(!$@, Dumper($@));
is_deeply($ret, {
	$me . '/' . $hostname . '@TEST.REALM' => [['mitkrb5/1.4', 0],
						   ['mitkrb5/1.3', 1]],
});

kill(15, $kdc_pid);
kill(15, $krb5_admind_pid);
exit(0);
