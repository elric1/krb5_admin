# 
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin;

use strict;
use warnings;

sub new {
	my ($isa, %args) = @_;
	my %self;

	bless(\%self, $isa);
}

1;

__END__

=head1 NAME

Krb5Admin - manipulate a Kerberos DB

=head1 SYNOPSIS

	use Krb5Admin;

	my $kmdb = Krb5Admin::KerberosDB->new();

=head1 DESCRIPTION

=head1 CONSTRUCTOR

This is a base class with a basic constructor.  It is not intended to
be used for much except as a base class for Krb5Admin::KerberosDB and
Krb5Admin::Client.

=over 4

=item new(ARGS)

Creates a new "Krb5Admin::KerberosDB" object.  ARGS is a hash which
is simply ignored.

=back

=head1 METHODS

=over 4

=item $kmdb->master()

Will ensure that the master DB is being modified.

=item $kmdb->create(PRINCIPAL)

Creates a principal suitable for use as a service principal.  The
principal will be assigned a random key rather than a password and
no attributes will be set.

=item $kmdb->create_user(PRINCIPAL[, PASSWD])

Creates principal suitable for use as a user.  This means that it
will be assigned a password, a password policy and attributes
suitable for use as a user REQUIRES_PRE_AUTH, REQUIRES_PWCHANGE
and DISALLOW_SVR.  The PASSWD argument is optional and if it is
not specified a random password will be selected.  The password
will in either case be returned from the method call.

=item $kmdb->list([GLOB])

Lists the principals in the Kerberos DB.  If supplied, the GLOB will
be applied before the list is returned.  The return will be an array
reference.

=item $kmdb->fetch(PRINCIPAL)

Will fetch the keys associated with PRINCIPAL.  The return value is
a list of hash references containing the following keys: enctype,
timestamp, princ, key, kvno.

=item $kmdb->change(PRINCIPAL, KVNO, KEYS)

TBD.

=item $kmdb->change_passwd(PRINCIPAL, PASSWD, OPT)

Will change the password of PRINCIPAL.  If PASSWD is defined then
it will be used as the new password, otherwise a password will be
randomly selected.  OPT is a hash references of options to the
command.  The only option that is currently defined is '+needchange'
which will cause the REQUIRES_PWCHANGE flag to be set on the
principal upon completion.

=item $kmdb->modify(PRINCIPAL, MODS)

TDB.

=item $kmdb->mquery([GLOB, ...])

Will return a set of principals matching the supplied GLOBs.  The return
value will be equivalent to:

	map { $kmdb->query($_) } ($kmdb->list(GLOB))

The function is provided mostly for Krb5Admin::Client's use to reduce the
number of network round trips.

=item $kmdb->query(PRINCIPAL)

Will return a hash reference containing various attributes about
the named principal.  The keys will include: principal, keys,
last_pwd_change, policy, mod_date, pw_expiration, max_life, mod_name,
princ_expire_time, mkvno, kvno, max_renewable_life and attributes.
All of these values will be scalars with the exception of keys and
attributes.  keys is an array reference of hash references containing
keys: enctype, kvno.  It is important to note that keys does not
actually contain the keys---to obtain the keys, the fetch method
must be used.  attributes is an array reference containing the list
of attributes that are set of the principal, e.g. +needchange.

=item $kmdb->enable(PRINCIPAL)

Will remove the -allow_tix flag from PRINCIPAL.

=item $kmdb->disable(PRINCIPAL)

Will set the -allow_tix flag from PRINCIPAL.

=item $kmdb->remove(PRINCIPAL)

Will remove PRINCIPAL.

=back
