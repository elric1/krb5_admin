#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>
#
# XXXrcd: must rename this library but not today, not today.

package CURVE25519_NWAY;

use Krb5Admin::C;

use strict;
use warnings;

#
# This constructor is not intended to be used for anything except testing.

sub new {
	my ($isa, %args) = @_;
	my %self;

	$self{ctx} = Krb5Admin::C::krb5_init_context();

	bless(\%self, $isa);
}

sub curve25519_start {
	my ($self, $priv, $hnum, $pub) = @_;
	my $ctx = $self->{ctx};

	#
	# To start our process, we first generate a nonce that we will
	# be using to derive the final key.  Each node in the communication
	# will generate its own nonce and they will all be used to derive
	# the resulting key.  We use an AES key generated from the krb5
	# libs as it is the right sort of length and we can rely on the
	# Kerberos lib's PRNG to be cryptographically sound:

	my $nonce = Krb5Admin::C::krb5_make_a_key($ctx, 17);
	$nonce = $nonce->{key};
	$self->{CURVE25519_NWAY_nonce} = $nonce;

	#
	# We then fire up the curve25519 dynamics:

	my ($secret, $public) = @{Krb5Admin::C::curve25519_pass1($ctx)};
	$self->{CURVE25519_NWAY_secret} = $secret;

	#
	# And we save the host number provided to us so that we can validate
	# it on each following step:

	$self->{CURVE25519_NWAY_hnum} = $hnum;

	return [$nonce, $public] if !defined($pub);
	return [$nonce, Krb5Admin::C::curve25519_pass2($ctx, $secret, $pub)];
}

sub curve25519_step {
	my ($self, $hnum, $pub) = @_;
	my $ctx = $self->{ctx};
	my $secret = $self->{CURVE25519_NWAY_secret};

	#
	# Sanity:

	die "HNUM doesn't match.\n"  if $hnum != $self->{CURVE25519_NWAY_hnum};

	return Krb5Admin::C::curve25519_pass2($ctx, $secret, $pub);
}

sub curve25519_final {
	my ($self, $priv, $hnum, $nonces, $pub) = @_;
	my $ctx = $self->{ctx};
	my $secret = $self->{CURVE25519_NWAY_secret};

	#
	# Sanity:

	die "HNUM doesn't match.\n"  if $hnum != $self->{CURVE25519_NWAY_hnum};
	die "nonce doesn't match"    if $nonces->[$hnum] ne
					$self->{CURVE25519_NWAY_nonce};

	my $prk = Krb5Admin::C::hkdf_extract(join(' ', @$nonces),
	    Krb5Admin::C::curve25519_pass2($ctx, $secret, $pub));

	if (defined($priv) && ref($priv) eq '' && $priv eq 'testing') {
		$self->{CURVE25519_NWAY_prk} = $prk;
	}

	return $prk;
}

sub curve25519_abort {

	return;
}

use integer;

sub recurse {
	my ($hosts, $host_start, $host_end, $pub) = @_;
	my $host_mid = ($host_start + $host_end) / 2;

	return ($pub) if $host_start == $host_end;

	my $i;

	my $pub1 = $pub;
	for ($i=$host_start; $i <= $host_mid; $i++) {
		$pub1 = $hosts->[$i]->curve25519_step($i, $pub1);
	}

	my $pub2 = $pub;
	for ($i=$host_mid+1; $i <= $host_end; $i++) {
		$pub2 = $hosts->[$i]->curve25519_step($i, $pub2);
	}

	return ( recurse($hosts, $host_start, $host_mid, $pub2),
		 recurse($hosts, $host_mid + 1, $host_end, $pub1) );
}

#
# do_nway is a divide and conquer implementation of N party ECDH key
# exchange using curve25519.  It takes as arguments $priv which is
# implementation defined data passed to all of the counterparties in
# the final step.  This will contain things like principal name, kvno,
# and encryption types in the Kerberos key implementation.
#
# The divide and conquer strategy is implemented recursively via two
# very similar functions: do_nway and recurse.  The main reason that
# we chose not to implement this as a single function is we felt that
# putting all of the conditionals in to either pass or fail to pass
# the nonces, etc, in a single function would obsfucate the code.
#
# The strategy is as follows:
#
#	1.  we are passed a list of hosts in $hosts.  We need to
#	    build both a list of nonces and a list of public keys
#	    for each host which has been operated on by every host
#	    except for itself.  That is one that looks roughly like
#	    this:
#
#		$pubs[i] = $hosts->[0]->curve25519_step(0,
#			       $hosts->[1]->curve25519_step(1,
#			       $hosts->[2]->curve25519_step(2,
#			       ...
#			       $hosts->[i-1]->curve25519_step(i-1,
#			       $hosts->[i+1]->curve25519_step(i+1,
#			       ...
#			       $hosts->[$hnum]->curve25519_start($hnum, undef)
#			       ))...)));
#
#	2.  we note that as far as curve25519 is concerned,
#	    curve25519_start() and curve25519_step() do the
#	    same thing,
#
#	3.  we also note that our operations are commutative and
#	    associative, thus we can reorder any operations and we
#	    do not have to worry about grouping,
#
#	4.  So, all our algorithm needs to ensure is that the generated
#	    public key that we pass to each host in the last step has been
#	    operated on by every host.
#
#	5.  We therefore use a divide and conquer algorithm recursively.
#	    At each step we are passed a list of hosts and a public key.
#	    We divide that list into two (not necessarily equal parts)
#	    and on each part we compute the initial public key passed to
#	    us operated on by each host in the list.  Now, we have two
#	    public keys $pub1, $pub2.  $pub1 has been operated on by all
#	    of the members of the first list.  $pub2 has been operated on
#	    by all of the members of the second list.  We then use the same
#	    strategy on the first list passing in the second list's public
#	    key $pub2 and vice versa (calling the function recurse).
#
#	6.  It can be seen that on every call to recurse, the public key
#	    passed in has been operated on by all of the hosts which are
#	    not within the range ($host_start, $host_end).  And so, when
#	    we get down to calling recurse on a single host, we have the
#	    pubkey that we desire.
#
# After calculated these semi-final keys, we pass them to
# curve25519_final() along with $priv which generates the shared
# secret.  This method is expected to be overloaded by the child
# class which will consume the shared secret and do something with
# it other than return it.

sub do_nway {
	my ($priv, $hosts) = @_;
	my $host_end = scalar(@$hosts) -1;
	my @nonces;
	my $i;
	my $ret;

	#
	# XXXrcd: ORDERING!  Both of these operations should occur in
	#         a particular order as curve25519_start() will lock
	#         and curve25519_final() will instantiate and unlock.
	#         We should likely do one backwards and the other forwards,
	#         as well as ensuring that the lists are sorted into a
	#         deterministic order...  For krb5, we would like to
	#         ensure that we contact the KDC first as it is the most
	#         likely to deny us.

	my ($pub1, $pub2);

	$ret = $hosts->[0]->curve25519_start($priv, 0, undef);

	$nonces[0] = $ret->[0];
	$pub1      = $ret->[1];

	for ($i=1; $i <= $host_end - 1; $i++) {
		$ret = $hosts->[$i]->curve25519_start($priv, $i, $pub2);

		$nonces[$i] = $ret->[0];
		$pub1       = $ret->[1];
	}

	my @pubs = (recurse($hosts, 1, $host_end, $pub2), $pub1);

	#
	# XXXrcd: we should also deal with transactions that abort by
	#         calling curve25519_abort() on all nodes on which
	#         curve25519_final() has been called.  In practice,
	#         this should not be too much of an issue as the various
	#         curve25519_start()s should do all of the ACL checking
	#         and be the most likely time to fail.

	for ($i=$host_end; $i >= 0; $i--) {
		$hosts->[$i]->curve25519_final($priv, $i, \@nonces, $pubs[$i]);
	}

	return;
}

#
# test_nway() is just a test to ensure that the algorithm is working
# correctly.  It takes a single argument which is the number of objects
# to construct to perform the negotiation.

sub test_nway {
	my ($num_hosts) = @_;

	my $i;
	my @hosts;

	for ($i=0; $i < $num_hosts; $i++) {
		push(@hosts, CURVE25519_NWAY->new());
	}

	do_nway('testing', \@hosts);

	my $val;
	my $oldval;

	for ($i=0; $i < $num_hosts; $i++) {
		$val = $hosts[$i]->{CURVE25519_NWAY_prk};

		die "Failed test" if defined($oldval) && $oldval ne $val;
	}
}

1;

#
# This is the old O(n^2) algorithm:
#
#package NWAY;
#
#use Data::Dumper;
#
#use Krb5Admin::C;
#
#use strict;
#use warnings;
#
#sub new {
#	my ($isa, %args) = @_;
#	my %self;
#
#	$self{ctx} = Krb5Admin::C::krb5_init_context();
#
#	bless(\%self, $isa);
#}
#
#sub ecdh_pass1 {
#	my ($self, $hnum, $pubs) = @_;
#	my $memo = $self->{memo};
#	my $ctx = $self->{ctx};
#	my $ret = [];
#
#	# XXXrcd: sanity, $hnum < length(@$pubs) or something like that.
#
#	my $secret = $self->{secret};
#	my $public;
#
#	if (!defined($secret)) {
#		($secret, $public) = @{Krb5Admin::C::curve25519_pass1($ctx)};
#		$self->{secret} = $secret;
#	}
#
#	my $hits = 0;
#	for (my $i=0; $i < @$pubs; $i++) {
#		$ret->[$i] = $pubs->[$i];
#		next if $i == $hnum;
#
#		if (!defined($pubs->[$i])) {
#			$ret->[$i] = $public;
#			$pubs->[$i] = $public;
#			next;
#		}
#
#		if (exists($memo->{$pubs->[$i]})) {
#			$hits++;
#			$ret->[$i] = $memo->{$pubs->[$i]};
#			next;
#		}
#
#		$ret->[$i] = Krb5Admin::C::curve25519_pass2($ctx, $secret,
#		    $pubs->[$i]);
#		$memo->{$pubs->[$i]} = $ret->[$i];
#	}
#
#	return $ret;
#}
#
#sub ecdh_pass2 {
#	my ($self, $hnum, $pub) = @_;
#	my $ctx = $self->{ctx};
#
#	#
#	# ecdh_pass1 do pretty much all of the work.  Now, well, we don't
#	# have much left to do at all...
#
#	Krb5Admin::C::curve25519_pass2($ctx, $self->{secret}, $pub);
#}

1;

__END__

=head1 NAME

CURVE25519_NWAY - perform n-way curve25519 ECDH

=head1 SYNOPSIS

	use CURVE25519_NWAY;

	use base qw/... CURVE25519_NWAY/;

=head1 DESCRIPTION

CURVE25519_NWAY expects to be inherited by a class that will use
its methods.  This class is expected to be a hashref and provide
an element ctx which is a Kerberos context.  It will set state
variables in the hashref of the form CURVE25519_NWAY_*.

It also expects that the class that inherits it will be using an
OO RPC framework such as Kharon and that the methods curve25519_start()
and curve25519_step() are exported by the derived objects.  This
means that many of the calls to curve25519_start()/curve25519_step()
will in fact be network communications rather than be processed
locally.  This object should also override curve25519_final() to
provide a method which takes shared secret which is returned and
use it in whatever fashion is desired.  This function will look
roughy like this:

=over 4

	sub curve25519_start {
		my ($self, $priv, @rest) = @_;

		my $key = $self->SUPER::curve25519_start($priv, @rest);

		... do something with the key


		return;		# do not return the key.
	}

=back

To negotiate a key between N objects, the class method
CURVE25519_NWAY::do_nway must be called to get all of the state
setup.  It must then be followed by $obj->curve25519_final for each
object.  The results of curve25519_final() must not be transmitted over
the wire as it is the shared key.

=head1 CONSTRUCTOR

There are no constructors which are not intended solely for testing.

=head1 CLASS METHODS

=over 4

=item CURVE25519_NWAY::do_nway(HOSTS)

performs N-way CURVE25519 ECDH.  HOSTS is an array ref containing
objects that implement CURVE25519_NWAY.

=back

=head1 METHODS

=over 4

=item $ecdh->curve25519_final(HNUM, NONCES, PUBLICKEY)

returns the shared secret in exchange for host number (HNUM), the
array reference of NONCES and the public key (PUBLICKEY) derived
by using curve25519 with all of the other hosts secrets.  Or more
simply, one must pass in HNUM which is the position of the object
in the hosts list provided to do_nway(), NONCES which is the array
reference of nonces returned by each curve25519_start(), and
PUBLICKEY which is the associated public key also returned by
do_nway().

This function should never be directly exported on the wire as it
returns the shared secret.  This would invalidate the purpose of
using ECDH.  It is expected that that the class that inherits will
override this function, consume its output, and act on it.

=back
