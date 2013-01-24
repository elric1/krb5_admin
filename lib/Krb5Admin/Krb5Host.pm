#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Krb5Host;

use Krb5Admin::C;

use strict;
use warnings;

our @KHARON_RW_SC_EXPORT = qw/	change_keytab
				fetch_tickets
				install_keytab
				install_ticket
			     /;

our @KHARON_RO_SC_EXPORT = qw/	query_keytab
				list_keytab
				generate_keytab
				test_keytab
				show_krb5_conf
			     /;

1;

__END__

=head1 NAME

Krb5Admin::Krb5Host - manipulate Kerberos settings and credentials on a host

=head1 SYNOPSIS

	use Krb5Admin::Krb5Host;

	my $kmdb = Krb5Admin::Krb5Host::Local->new();

=head1 DESCRIPTION

Krb5Admin::Krb5Host manipulates Kerberos settings and credentials
on a host.  Currently, the modules support keytab management, the
installation of prestashed tickets, and various administrative
testing functions designed to ensure that the host is correctly
configured and the aforementioned credentials are working.

=head1 CONSTRUCTOR

This is a base class.  It is not intended to be used directly and
hence has no constructor.  To use the functionality provided either
Krb5Admin::Krb5Host::Local or Krb5Admin::Krb5Host::Client must be
used.

=head1 METHODS

=over 4

=item $krbhst->show_krb5_conf()

Returns the contents of /etc/krb5.conf as an array ref of the
lines of the file.  Newlines are stripped.

=item $krbhst->list_keytab(USER)

Returns the contents of USER's keytab as a hash ref containing two
values, ktname and keys.  keys is an array ref of hash refs with
entries kvno, princ, and enctype.

=item $krbhst->query_keytab(USER)

Returns a high level description of the contents of USER's keytab.
The return is a hashref of principals (string) to a list of supported
libs which are represented as an array ref of [string, boolean]
where the string is the library name and the boolean undicates if
the library is considered to be deprecated.

=item $krbhst->generate_keytab(USER, IGNORED, @PRINCS)

Returns two array references.  The first is a list of errors.  The
second is a list of commands used to generate the @PRINCS in USER's
keytab.  If @PRINCS is not supplied then the returned list will be
for all of the keys in the keytab.

=item $krbhst->test_keytab(USER, LIB, @PRINCS)

Tests if @PRINCS are compatible with LIB in USER's keytab.  Will
throw exceptions on errors and return nothing on success.

=item $krbhst->change_keytab(USER, LIB, @PRINCS)

Change USER's keys.  If LIB is specified then the new keys will be
compatible with LIB.  If @PRINCS are specified then only the keys
so specified are changed, otherwise the default set of keys will
be changed.

=item $krbhst->install_keytab(USER, LIB, @PRINCS)

Validate and/or install keys.  If LIB is specified then the new
keys will be compatible with LIB.  If @PRINCS are specified then
only the keys so specified are validated and/or installed, otherwise
the default set of keys will be validated and/or installed.

=item $krbhst->install_ticket(PRINC, TICKET)

Will install a ticket for user PRINC.  No return value.  Exceptions are
thrown on error.

=item $krbhst->fetch_tickets(@REALMS)

Fetch and install the configured prestashed tickets for the host.
@REALMS, if specified, will cause the KDCs for each Realm to be
contacted.

=back
