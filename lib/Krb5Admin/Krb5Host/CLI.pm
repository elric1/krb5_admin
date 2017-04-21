#
# Blame "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Krb5Host::CLI;

use base qw(Kharon::Class::CLI);

use Data::Dumper;
use IO::File;
use POSIX;

use strict;
use warnings;

sub CMD_help {
	my ($self) = @_;
	my $out = $self->{out};

	$self->print( <<EOM );

	list_keytab	lists a user's keytab
	query_keytab	less information about a user's keytab
	query_ticket	information about the prestashed tickets
	show_krb5_conf	outputs /etc/krb5.conf and other configs

For a more complete description of commands with usage and examples,
please refer to the manual page which can be accessed via:

	\$ man krb5_host
EOM

	return 0;
}

sub FORMAT_list_keytab {
	my ($self, $cmd, $args, $ret) = @_;

	$self->print("Keytab name: " . $ret->{ktname} . "\n");
	$self->print("KVNO Principal\n");
	$self->print("---- ");
	for (my $i=0; $i < 74; $i++) {
		$self->print("-");
	}
	$self->print("\n");

	for my $key (@{$ret->{keys}}) {
		$self->printf("% 4d %s (%s)\n", $key->{kvno}, $key->{princ},
		    $key->{enctype});
	}

	return 0;
}

sub mknum {
	my ($num) = @_;

	return sprintf("%3.1f", $num);
}

sub mkreadable {
	my ($num) = @_;

	return $num				if $num < 1_000;
	return mknum($num / 1000) . "K"		if $num < 1_000_000;
	return mknum($num / 1000000) . "M"	if $num < 1_000_000_000;
	return mknum($num / 1000000000) . "G";
}

my $qt_fmt = "%-15.15s %-15.15s %6s %s\n";
sub FORMAT_query_ticket {
	my ($self, $cmd, $args, $ret) = @_;

	$self->printf($qt_fmt, 'USER', 'REALM', 'SIZE', '');
	$self->printf($qt_fmt, "----", '-----', '----', '');

	for my $u (sort (keys %{$ret})) {
		my $user = $ret->{$u};
		my $ustr = $u;

		for my $r (sort (keys %$user)) {
			my $urealm = $user->{$r};
			$r = 'default' if $r eq '.';
			my $size = mkreadable($urealm->{size});

			$self->printf($qt_fmt, $ustr, $r, $size, "created " .
			    strftime("%c", localtime($urealm->{ctime})));
			$ustr = '';
			$r = '';
			$size = '';

			if ($urealm->{username} ne $u) {
				$self->printf($qt_fmt, $ustr, $r, $size,
				    "WARNING: file isn't owned by $u");
			}

			if ($urealm->{mode} & 040) {
				$self->printf($qt_fmt, $ustr, $r, $size,
				    "WARNING: file is group readable");
			}

			if ($urealm->{mode} & 020) {
				$self->printf($qt_fmt, $ustr, $r, $size,
				    "WARNING: file is group writable");
			}

			if ($urealm->{mode} & 04) {
				$self->printf($qt_fmt, $ustr, $r, $size,
				    "WARNING: file is other readable");
			}

			if ($urealm->{mode} & 02) {
				$self->printf($qt_fmt, $ustr, $r, $size,
				    "WARNING: file is other writable");
			}

			if ($urealm->{nlink} != 1) {
				$self->printf($qt_fmt, $ustr, $r, $size,
				    "WARNING: nlink != 1");
			}

		}
	}
}

my $dashes = "------------------------------------------------------------\n";
sub FORMAT_show_krb5_conf {
	my ($self, $cmd, $args, $ret) = @_;

	for my $f (keys %$ret) {
		next if !defined($ret->{$f}->{error});

		$self->print("ERROR: $f: " . $ret->{$f}->{error} . "\n");
		delete $ret->{$f};
	}

	for my $fn (keys %$ret) {
		my $f = $ret->{$fn};

		$self->print($dashes);
		$self->printf("%s%s%s\n", $fn, defined($f->{path})?" -> ":"",
		    $f->{path} // "");
		$self->print($dashes);
		$self->print($f->{contents});
	}
	$self->print($dashes);
}

1;
