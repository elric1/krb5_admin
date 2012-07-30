#
# Blame "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::CLI;

use base qw(Kharon::Class::CLI);

use IO::File;

use strict;
use warnings;

our %enctypes = (
	0x12    => 'aes256-cts',
	0x11    => 'aes128-cts',
	0x17    => 'rc4-hmac',
	0x10    => 'des3-cbc-sha1',
	0x01    => 'des-cbc-crc',
);


sub CMD_help {
	my ($self) = @_;
	my $out = $self->{out};

	$self->print( <<EOM );

Commands that operate on principals:

	list [wildcard]		lists principals that match the wildcard
	query princ		displays the principal
	remove princ		removes a principal
	enable princ		enables a principal
	disable	princ		disables a principal

Commands that operate on users:

	create_user user	creates a new user account
	desdeco user		upgrades the user to the strong_human policy

Commands that operate on service principals:

none, yet.

Commands that operate on policies:

	listpols [wildcard]	lists the policies that match the wildcard

General commands:

	master			reconnects to the master KDC

* unimplemented
EOM

	return 0;
}

sub FORMAT_create_user {
	my ($self, $cmd, $args, $ret) = @_;

	$self->print("Created user with passwd '$ret'\n");
	return 0;
}

sub FORMAT_reset_passwd  { FORMAT_change_passwd(@_) }
sub FORMAT_change_passwd {
	my ($self, $cmd, $args, $ret) = @_;

	$self->print("Changed passwd to '$ret'\n");
	return 0;
}

sub FORMAT_query_host {
	my ($self, $cmd, $args, @rets) = @_;
	for my $r (@rets) {
		while (my ($h, $hinfo) = each %$r) {
			$self->printf("%s:\t%s\n", "name", $h);
			while (my ($a, $v) = each %$hinfo) {
				next if ! defined($v);
				if (! ref($v)) {
					$self->printf("%s:\t%s\n", $a, $v);
					next;
				}
				for my $e (@$v) {
					$self->printf("%s:\t%s\n", $a, $e);
				}
			}
		}
		$self->print("\n");
	}

	return 0;
}

sub FORMAT_mquery {
	my ($self, $cmd, $args, @rets) = @_;

	for my $i (@rets) {
		$self->FORMAT_query($i);
	}

	return 0;
}

our $QUERY_FMT = "%- 25.25s ";
sub FORMAT_query {
	my ($self, $cmd, $args, $ret) = @_;

	# First fix up some fields:

	if (grep { $_ eq '+needchange' } @{$ret->{attributes}}) {
		# not zero but quite small:
		$ret->{pw_expiration} = 1;
	}

	$ret->{policy} = "none" if !defined($ret->{policy});
	$ret->{keys}   = []	if !exists($ret->{keys});

	# Now print it all out:

	$self->qout("Principal:", $ret->{principal});
	$self->qout("Policy:", $ret->{policy});
	$self->qout("Last modified by:", $ret->{mod_name});
	$self->qout("Last modified on:", $self->fmtdate($ret->{mod_date}));
	$self->qout("Last password change:",
	    $self->fmtdate($ret->{last_pwd_change}));
	$self->qout("Password expiration:",
	    $self->fmtexpi($ret->{pw_expiration}));
	$self->qout("Maximum ticket life:", $self->fmtintv($ret->{max_life}));
	$self->qout("Maximum renewable life:",
	    $self->fmtintv($ret->{max_renewable_life}));
	$self->qout("Current kvno:", $ret->{kvno});
	$self->printf("$QUERY_FMT ", "Attributes:");
	if (@{$ret->{attributes}} > 0) {
		$self->printvar(undef, $ret->{attributes});
	} else {
		$self->print("\n");
	}

	$self->print("Number of keys: " . scalar(@{$ret->{keys}}) . "\n");
	for my $k (sort { $a->{kvno} <=> $b->{kvno} } @{$ret->{keys}}) {
		my $enctype = $k->{enctype};

		$enctype = $enctypes{$enctype} if exists($enctypes{$enctype});
		$self->printf("Key: kvno % 5d, %s\n", $k->{kvno}, $enctype);
	}

	return 0;
}

1;

__END__

#
# Extra code looking for a home...

our %KHARON_COMMAND_ALIASES = (
	desdeco	=> 'upgrade_to_strong_human',
);

sub proid_passwd {
	my ($kmdb, $proid, $file) = @_;

	if (!defined($proid) || !defined($file)) {
		die "Syntax error: not enough args\nusage: proid_passwd " .
		    "<proid> <file>";
	}

	my $fh = IO::File->new($file, O_CREAT|O_EXCL|O_WRONLY, 0600);
	die "Can't open $file: $!" if !defined($fh);

	#
	# XXXrcd: check to see if the file is PTS protected.
	#         This is a weak check but designed only to
	#         encourage correct user behaviour...
	#         We allow local files, but don't check if
	#         it is in NFS...

	my $fsout = qx{fs la "$file" 2>/dev/null};
	if ($fsout =~ /system:anyuser/) {
		unlink($file);
		die "Permission denied: will not write a proid's to an AFS ".
		    "location which permits system:anyuser access";
	}

	my $pass;
	eval { $pass = $kmdb->proid_passwd($proid); };
	if ($@) {
		unlink($file) and die formaterr($@) . " and unlink failed: $!";
		die $@;
	}
	print $fh "$pass\n";
}
