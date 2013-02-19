#

package CURVE25519_NWAY::Kerberos;

use base qw/CURVE25519_NWAY/;

use Krb5Admin::C;

use strict;
use warnings;

#
# And we define a few lookup tables:

our %enctypes = (
	0x12	=> 'aes256-cts',
	0x11	=> 'aes128-cts',
	0x17	=> 'rc4-hmac',
	0x10	=> 'des3-cbc-sha1',
	0x01	=> 'des-cbc-crc',
	0x03	=> 'des-cbc-md5',
);
our %revenctypes;
for my $i (keys %enctypes) {
	$revenctypes{$enctypes{$i}} = $i;
}
our $bootetype_name = "aes256-cts";
our $bootetype_code = $revenctypes{$bootetype_name};

our %enctypesize = (
	'aes256-cts'	=> 32,
	'aes128-cts'	=> 16,
	'rc4-hmac'	=> 16,
	'des3-cbc-sha1'	=> 24,
	'des-cbc-crc'	=> 8,
	'des-cbc-md5'	=> 8,
);
our %revenctypesize;
for my $i (keys %enctypesize) {
	$revenctypesize{$revenctypes{$i}} = $enctypesize{$i};
}

#
# We override the methods in CURVE25519_NWAY to calculate the appropriate
# Kerberos keys.  These functions are passed $priv which is expected to be
# a list reference containing:
#
#	$op	the operation to perform: install, change, bootstrap.
#		In the case of Krb5Admin::Krb5Host::Local, this is
#		ignored.
#
#	$lib	the Kerberos library to which things are expected to
#		conform [ignored in the KDC].
#
#	$name	the principal on which to operate.
#
#	$kvno	the key version number to be created.
#
#	%args	the remaining arguments:
#
#		enctypes	a list ref of enctypes.
#
# The return a list ref of Kerberos keys.
#
# This method is then expected to be overridden by the module which is a
# party to the negotiation which will then write the keys to the appropriate
# place.

sub curve25519_final {
	my ($self, $priv, $hnum, $nonces, $pub) = @_;
	my $ctx = $self->{ctx};

	my $prk = $self->SUPER::curve25519_final($priv, $hnum, $nonces, $pub);

	my ($op, $user, $name, $lib, $kvno, %args) = @$priv;

	# XXXrcd: sanity check args and %args!

	my $counter = 0;
	my @keys;
	for my $enctype (@{$args{enctypes}}) {
		# Make sure we've got a numeric enctype... XXXrcd ???
		my $etype = $revenctypes{$enctype};
		$etype = $enctype if !defined($etype);
		
		my $size = $revenctypesize{$etype};
		my $info = "$counter|$etype|$size|$name";
		my $key  = Krb5Admin::C::hkdf_expand($prk, $info, $size);

		push(@keys, {
			princ	=> $name,
			kvno	=> $kvno,
			enctype	=> $etype,
			key	=> $key,
		});
		$counter++;
	}

	return \@keys;
}

1;
