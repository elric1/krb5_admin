#

package tests::utils;

use base qw(Exporter);
@EXPORT_OK = qw{ compare_array compare_hash compare };

use Carp;

use strict;
use warnings;

sub compare_array {
	my ($lhs, $rhs) = @_;

	if (@$lhs != @$rhs) {
		confess "ARRAY: arrays are of different length ". (@$lhs) .
		    " " . @$rhs;
	}

	for (my $i=0; $i < @$lhs; $i++) {
		compare($lhs->[$i], $rhs->[$i]);
	}
}

sub compare_hash {
	my ($lhs, $rhs) = @_;

	$rhs = \%{$rhs};
	for my $i (keys %$lhs) {
		confess "$i exists in lhs but not rhs" if !exists($rhs->{$i});

		compare($lhs->{$i}, $rhs->{$i});
		delete $rhs->{$i};
	}

	if (keys %$rhs) {
		confess join(', ', keys %$rhs) . " exist in rhs but not lhs";
	}
}

sub compare {
	my ($lhs, $rhs) = @_;

	if (ref($lhs) ne ref($rhs)) {
		confess ("REFS: '" . ref($lhs) . "' ne '" . ref($rhs) . "'!" );
	}

	return if !defined($lhs) && !defined($rhs);

	if (ref($lhs) eq '') {
		if ($lhs ne $rhs) {
			confess "SCALAR: $lhs ne $rhs!";
		}
		return;
	}

	return compare_array($lhs, $rhs) if ref($lhs) eq 'ARRAY';
	return compare_hash($lhs, $rhs)  if ref($lhs) eq 'HASH';

	confess "REFS: can't interpret " . ref($lhs);
}

1;
