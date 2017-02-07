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

our %host_hmap = (
	realm		=> undef,
	ip_addr		=> undef,
	is_logical	=> undef,
	bootbinding	=> undef,
	label		=> [],
	owner		=> [],
	member		=> [],
);

our %princ_hmap = (
	# Associated HDB attributes
	# XXX: It would be nice if the API supported time
	#      suffixes (1d, 2w, ...)
	princ_expire_time	=> undef,
	pw_expiration		=> undef,
	max_life		=> 'duration',
	max_renewable_life	=> 'duration',
	attributes		=> [],
);

our %appid_hmap = (
	desc		=> undef,
	owner		=> [],
	cstraint	=> [],
);

our %subject_hmap = (
	type		=> undef,
	owner		=> [],
	member		=> [],
);

our %acl_hmap = (
	owner	=> []
);

our %logical_host_hmap = (
	owner	=> [],
	member	=> [],
);

our %sacls_query_hmap = (
	subject	=> undef,
	verb	=> undef,
);

sub KHARON_HASHIFY_COMMANDS {
	return {
		create_appid		=> [1, \%appid_hmap],
		create_group		=> [1, \%subject_hmap],
		create_host		=> [1, \%host_hmap],
		create_logical_host	=> [1, \%logical_host_hmap],
		create_subject		=> [1, \%subject_hmap],
		modify			=> [1, {%princ_hmap, %appid_hmap}],
		modify_group		=> [1, \%subject_hmap],
		modify_host		=> [1, \%host_hmap],
		modify_subject		=> [1, \%subject_hmap],
		list_subject		=> [0, \%subject_hmap],
		list_group		=> [0, \%subject_hmap],
		add_acl			=> [2, \%acl_hmap],
		sacls_query		=> [0, \%sacls_query_hmap],
		search_host		=> [0, \%host_hmap],
	};
}

sub KHARON_COMMAND_ALIASES {
	return {
		is_owner	=> 'is_appid_owner',
		is_pwner	=> 'is_appid_owner',
		reset_password	=> 'reset_passwd',
	};
}

sub CMD_help {
	my ($self) = @_;
	my $out = $self->{out};

	$self->print( <<EOM );
General commands:

	master			returns the name of the master KDC

Commands that operate on principals and appids:

	list			lists principals that match provided globs
	query			displays the principal
	mquery			displays all principals matching the globs
	modify			modifies a principal
	remove			removes a principal
	enable			enables a principal
	disable			disables a principal
	create_appid		creates a new non-human user
	create_user		creates a new user account
	desdeco			upgrades the user to the strong_human policy
	reset_passwd		resets user's passwd
	is_owner		tests if princ owns appid

Commands that operate on policies:

	listpols		lists the policies that match the wildcard

Commands that operate of subjects and groups

	create_subject		create a subject
	list_subject		list subjects
	modify_subject		modify a subject
	query_subject		query a subject
	remove_subject		remove a subject

	create_group		create a group
	list_group		list groups
	modify_group		modify a group
	query_group		query a group
	remove_group		remove a group

Commands that operate on hosts:

	create_host		create a host
	create_logical_host	create a logical host, i.e. a cluster
	bind_host		assign a ``bootbinding'' to a host
	remove_host		remove a host
	modify_host		modify the attributes of a host

Commands that operate on host secrets:

	new_host_secret		create new master secret
	bind_host_secret	create/change host secret
	read_host_secret	return the host's current secret

Show a list of available commands:

	list_commands

For a more complete description of commands with usage and examples,
please refer to the manual page which can be accessed via:

	\$ man krb5_admin
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

sub FORMAT_mquery {
	my ($self, $cmd, $args, @rets) = @_;

	for my $i (@rets) {
		$self->FORMAT_query($cmd, $args, $i);
		$self->print("\n");
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
	if (defined($ret->{owner})) {
		$self->qout("Owner:", join(',', @{$ret->{owner}}));
	}
	if (defined($ret->{desc})) {
		$self->qout("Desc:", $ret->{desc});
	}
	if (defined($ret->{cstraint})) {
		$self->qout("Cstraint:", join(', ', @{$ret->{cstraint}}));
	}
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

sub FORMAT_list_labels {
	my ($self, $cmd, $inargs, $ret) = @_;

	for my $label (keys %$ret) {
		$self->qout($label, $ret->{$label}->{desc});
	}
}

sub FORMAT_is_appid_owner {
	my ($self, $cmd, $args, @rets) = @_;

	return 1	if $rets[0] == 0;
	return 0;
}

sub FORMAT_query_acl {
	my ($self, $cmd, $inargs, $ret) = @_;

	if (!defined($ret)) {
		$self->printerr("Not found.");
		return 1;
	}

	my %args = @$inargs;

	if (exists($args{name}) && exists($args{type})) {
		if ($ret == 0) {
			$self->print("Not found.");
			return 1;
		}
		return 0;
	}

	if (exists($args{name})) {
		$self->print($ret->{type} . "\n");
		return 0;
	}

	if (exists($args{type})) {
		for my $acl (keys %$ret) {
			$self->print("$acl\n");
		}
		return 0;
	}

	for my $acl (keys %$ret) {
		$self->qout($ret->{$acl}->{type}, $acl);
	}

	return 0;
}

sub FORMAT_query_aclgroup {
	my ($self, $cmd, $args, $ret) = @_;
	my $out = $self->{out};

	if (@$args > 0) {
		for my $memb (@$ret) {
			print $out "$memb\n";
		}
		return 0;
	}

	for my $group (keys %$ret) {
		for my $memb (@{$ret->{$group}}) {
			$self->qout($group, $memb);
		}
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
		    "<proid> <file>\n";
	}

	my $fh = IO::File->new($file, O_CREAT|O_EXCL|O_WRONLY, 0600);
	die "Can't open $file: $!\n" if !defined($fh);

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
		    "location which permits system:anyuser access\n";
	}

	my $pass;
	eval { $pass = $kmdb->proid_passwd($proid); };
	if ($@) {
		unlink($file) or die formaterr($@)." and unlink failed: $!\n";
		die $@;
	}
	print $fh "$pass\n";
}
