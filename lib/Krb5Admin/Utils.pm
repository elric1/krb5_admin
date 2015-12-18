#
#
# This is where the ugly code goes.  If I hide it---maybe no one will
# actually SEE it!

package Krb5Admin::Utils;
use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw/reverse_the host_list force_symlink/;

#
# Host list will, given an IP/Hostname return a list of all of the valid
# host principals which we would expect that host to contain in their
# entirety.  We strive to make the code less ugly than in.dstd:

sub host_list {
	my ($hostname) = @_;

	return ($hostname);
}

sub reverse_the {
	my ($addr) = @_;

#	my $iaddr = inet_aton($addr);
#	$name  = gethostbyaddr($iaddr, AF_INET);
#
#	$name;
	return undef;	# unimplemented.
}

sub force_symlink {
	my ($to, $from) = @_;

	my $l = readlink($from);
	if (!defined($l) || $l ne $to) {
		symlink($to, "$from.$$");
		rename("$from.$$", $from) or
		    die "$0: Can't create $from as a link to $to: $!\n";
	}
}

1;
