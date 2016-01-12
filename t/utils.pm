package t::utils;

use Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw/normalise/;

use strict;
use warnings;

sub mysort {
	my ($a, $b) = @_;

	return  0		if !defined($a) && !defined($b);
	return  1		if  defined($a) && !defined($b);
	return -1		if !defined($a) &&  defined($b);
	return $a cmp $b;
}

sub normalise {
	my ($in) = @_;

	if (ref($in) eq 'HASH') {
		return [ map { [$_, normalise($in->{$_})] } sort keys %$in ];
	}

	return $in				if ref($in) ne 'ARRAY';
	return []				if !@$in;
	return [ sort { mysort($a, $b) } @$in ]	if !ref($in->[0]);
	return [ map { normalise($_) } @$in ];
}
