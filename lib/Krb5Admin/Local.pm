#
#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Local;

use base qw(Kharon::Class::Local);

use Kharon::InputValidation::Object;

use Krb5Admin::KerberosDB;
use Krb5Admin::Utils qw/mk_kmdb_with_config/;

use strict;
use warnings;

sub new {
	my ($proto, $config, $args) = @_;
	my $class = ref($proto) || $proto;

	$args->{local} = 1;
	my $kmdb = mk_kmdb_with_config($config, $args);

	my $iv = Kharon::InputValidation::Object->new(subobject => $kmdb);
	my $self = $class->SUPER::new(obj => $kmdb, iv => $iv);

	return bless($self, $class);
}

1;

__END__

=head1 NAME

Krb5Admin::Local - locally manipulate a Kerberos DB

=head1 SYNOPSIS

	use Krb5Admin::Local;

	my $kmdb = Krb5Admin::Client->new();

=head1 DESCRIPTION

=head1 CONSTRUCTOR

=over 4

=item new(%ARGS)

Creates a new "Krb5Admin::Local" object.  The %ARGS are passed
directly to Krb5Admin::KerberosDB without modification.

=back

=head1 METHODS

All of the user-visible methods are inherited from Krb5Admin and are
documented there as well.

=head1 SEE ALSO

L<Krb5Admin>
