#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Krb5Host::Local;

use base qw/Krb5Admin::Krb5Host/;

use IO::File;
use File::Path;
use File::Temp qw/ :mktemp /;
use Fcntl ':flock';
use POSIX qw(strftime);
use Sys::Hostname;
use Sys::Syslog;
use Time::HiRes qw(gettimeofday);

use Krb5Admin::Client;
use Krb5Admin::KerberosDB;
use Krb5Admin::Utils qw/host_list/;
use Krb5Admin::C;

use strict;
use warnings;

#
# Constants:

our $DEFAULT_KEYTAB = '/etc/krb5.keytab';
our $KRB5_KEYTAB_CONFIG = '@@KRB5_KEYTAB_CONF@@';
our $KINIT    = '@@KINIT@@';
our @KINITOPT = qw(@@KINITOPT@@ -l 10m);

#
# And we define a few lookup tables:

our %enctypes = (
	0x12	=> 'aes256-cts',
	0x11	=> 'aes128-cts',
	0x17	=> 'rc4-hmac',
	0x10	=> 'des3-cbc-sha1',
	0x01	=> 'des-cbc-crc',
	0x03	=> 'des-cbc-md5',
);
our %revenctypes;
for my $i (keys %enctypes) {
	$revenctypes{$enctypes{$i}} = $i;
}
our $bootetype_name = "aes256-cts";
our $bootetype_code = $revenctypes{$bootetype_name};

#
# First we define the object's interface, the public methods:

our %kt_opts = (
	local			=> 0,
	kadmin			=> 0,
	invoking_user		=> undef,
	user2service		=> {},
	allowed_enctypes	=> [],
	admin_users		=> {},
	krb5_lib		=> '',
	krb5_libs		=> {},
	krb5_lib_quirks		=> {},
	default_krb5_lib	=> 'mitkrb5/1.4',
	user_libs		=> {},
	use_fetch		=> 0,
	force			=> 0,
	verbose			=> 1,
);

sub new {
	my ($proto, %args) = @_;
	my $class = ref($proto) || $proto;

	my $self = { %kt_opts };

	$self->{ctx}		= Krb5Admin::C::krb5_init_context();

	bless($self, $class);

	#
	# Take the configuration parameters passed in:

	for my $opt (keys %args) {
		$self->set_opt($opt, $args{$opt});
	}

	return $self;
}

sub DESTROY {
	my ($self) = @_;

	local($?);
	for my $lock (keys %$self) {
		next if $lock !~ /^lock\.user\.([^.]+)\.count$/;
		next if $self->{"lock.user.$1.count"} < 1;

		unlink("/var/run/krb5_keytab/lock.user.$1");
	}
	unlink($self->{ccfile}) if exists($self->{ccfile});
}

sub set_opt {
	my ($self, $opt, $val) = @_;

	#
	# admin_users is a little strange.  we're given an array but
	# we convert it into a hash for efficiency internally.  We deal
	# with this up front:

	if ($opt eq 'admin_users') {
		if (ref($val) ne 'ARRAY') {
			die "admin_users must be of type ARRAY but is " .
			    "of type " . ref($val) . "\n";
		}
		my @l = ();
		@l = @{$val};
		$self->{admin_users} = { map { $_ => 1 } @l };
		return;
	}

	die "Unrecognised option: $opt.\n" if !exists($kt_opts{$opt});

	if (!defined($val)) {
		$self->{$opt} = $kt_opts{$opt};
		return;
	}

	if (ref($kt_opts{$opt}) ne ref($val)) {
		die "Option $opt must be of type " . ref($kt_opts{$opt}) .
		    " but is of type " . ref($val) . "\n";
	}

	$self->{$opt} = $val;
}

#
# Basic remote admin:

sub show_krb5_conf {
	my ($self) = @_;
	my @ret;

	my $fh = IO::File->new('/etc/krb5.conf', 'r');

	die "Can't open /etc/krb5.conf.  $!\n" if !defined($fh);

	for my $line (<$fh>) {
		chomp($line);
		push(@ret, $line);
	}

	return \@ret;
}

#
# Remote keytab management:

sub list_keytab {
	my ($self, $user) = @_;
	my $ret;

	if (!$self->is_admin()) {
		syslog('err', "%s attempted to list %s's keytab",
		    $self->{invoking_user}, $user);
		die "list is an administrative function only.\n";
	}
	syslog('info', "%s listed %s's keytab", $self->{invoking_user}, $user);

	$ret->{ktname} = get_kt($user);
	$ret->{ktname} =~ s/^WR//o;

	for my $key ($self->get_keys($ret->{ktname})) {
		push(@{$ret->{keys}}, {
			kvno	=> $key->{kvno},
			princ	=> $key->{princ},
			enctype	=> $key->{enctype},
		});
	}

	return $ret;
}

sub query_keytab {
	my ($self, $user) = @_;
	my $ret;

	$self->user_acled($user);

	my @keys = $self->get_keys(get_kt($user));
	my @princs = get_princs(@keys);

	for my $princ (get_princs(@keys)) {
		my @libs;

		for my $lib ($self->supports_libs($princ, @keys)) {
			push(@libs, [$lib, $self->lib_requires_admin($lib)]);
		}

		$ret->{$princ} = \@libs;
	}

	return $ret;
}

sub generate_keytab {
	my ($self, $user, $lib, @inprincs) = @_;

	$self->user_acled($user);

	my $ctx = $self->{ctx};
	my $user_libs = $self->{user_libs};
	my @keys = $self->get_keys(get_kt($user));
	my @princs = get_princs(@keys);
	my @errs;
	my @ret;

	if (@inprincs) {
		@inprincs = $self->expand_princs($user, @inprincs);
		@inprincs = map {unparse_princ($_)} @inprincs;
	} else {
		@inprincs = @princs;
	}

	for my $i (@inprincs) {
		if (!in_set($i, \@princs)) {
			push(@errs, "$i does not exist in the keytab.\n");
		}
	}

	for my $i (@princs) {
		next	if @inprincs && !in_set($i, \@inprincs);

		my $working_lib = $self->working_lib($i, @keys);

		if (!defined($working_lib) || (exists($user_libs->{$user}) &&
		    !in_set($working_lib, $user_libs->{$user}))) {
			$working_lib = $user_libs->{$user}->[0];
		}

		if (!defined($working_lib)) {
			push(@errs, "Can't determine library for $i.");
			next;
		}

		push(@ret, "krb5_keytab -p $user -L " . $working_lib . " $i");
	}

	return (\@errs, \@ret);
}

sub test_keytab {
	my ($self, $user, $lib, @inprincs) = @_;
	my @errs;

	$self->user_acled($user);
	$self->validate_lib($user, $lib);

	my $ctx = $self->{ctx};
	my @keys = $self->get_keys(get_kt($user));
	my @princs = get_princs(@keys);

	@inprincs = $self->expand_princs($user, @inprincs);
	@inprincs = map {unparse_princ($_)} @inprincs;

	$lib = $self->{default_krb5_lib} if !defined($lib);

	for my $i (@inprincs) {
		if ($i =~ m{^bootstrap/RANDOM}) {
			$self->vprint("Not testing $i\n");
			next;
		}
		$self->vprint("Testing $i\n");
		if (!in_set($i, [@princs])) {
			push(@errs, "$i does not exist in the keytab.");
			next;
		}
		if (!in_set($lib, [$self->supports_libs($i, @keys)])) {
			push(@errs, "$i will not work with $lib.");
		}
	}
	die [@errs] if @errs > 0;
	return undef;
}

#
# change_keytab() and install_keytab() are implemented in terms of
# install_all_keys as they are quite similar in operation.  They
# should have the same ACLs which are currently internally implemented
# in install_all_keys.  At some point, we are likely to change to
# using Kharon ACLs and then we will do things just a little
# differently.

sub change_keytab {
	my ($self, $user, $lib, @inprincs) = @_;

	$self->install_all_keys($user, 'change', $lib, @inprincs);
}

sub install_keytab {
	my ($self, $user, $lib, @inprincs) = @_;

	$self->install_all_keys($user, 'default', $lib, @inprincs);
}


#
# And now, the internal helper functions:

sub is_admin {
	my ($self) = @_;

	die "Invoking user is not set.\n" if !defined($self->{invoking_user});

	return $self->{admin_users}->{$self->{invoking_user}} ? 1 : 0;
}

#
# is_acled() only determines if the invoking user is allowed to modify
# the keytab of a designated user.

sub user_acled {
	my ($self, $user) = @_;

	return if $self->is_admin();
	return if $self->{invoking_user} eq 'root';
	return if $self->{invoking_user} eq $user;

	die "Access denied for operation, " . $self->{invoking_user} .
	    " does not\nhave krb5_keytab administrative privileges.\n";
}

sub validate_lib {
	my ($self, $user, $krb5_lib) = @_;
	my $krb5_libs = $self->{krb5_libs};
	my $user_libs = $self->{user_libs};
	my $allowed_enctypes = $self->{allowed_enctypes};

	if (defined($krb5_lib)) {
		if (!defined($krb5_libs->{$krb5_lib})) {
			die "Library \"$krb5_lib\" is not defined.\n";
		}

		my $enctypes = $krb5_libs->{$krb5_lib};
		if (!is_subset($enctypes, [@$allowed_enctypes])) {
			die "Invalid encryption type(s) [" .
			    join(',', grep {!in_set($_, [@$allowed_enctypes])}
			    @$enctypes) .  "] specified.\n";
		}
	}

	my $real_krb5_lib = $self->{default_krb5_lib};
	$real_krb5_lib = $krb5_lib if defined($krb5_lib);
	if (defined($real_krb5_lib) && exists($user_libs->{$user}) &&
	    !in_set($real_krb5_lib, $user_libs->{$user})) {
		die "$user does not support $real_krb5_lib.\n";
	}

	return 1;
}

#
# The following two functions are explicitly not re-entrant while being
# used, so one must be careful that all functions that call the first will
# call the second before they return control to the caller.  And, we cannot
# use threads with this module.  We can look into this at a future time,
# there are solutions to this issue but they will require some hackery
# to how we invoke KNC and populate the ccache.

sub use_private_krb5ccname {
	my ($self) = @_;

	if (!defined($self->{ccfile})) {
		(my $fh, $self->{ccfile}) = mkstemp("/tmp/krb5_keytab.XXXXXX");
		undef($fh);
	}

	if (exists($self->{old_krb5ccname})) {
		die 'called $kt->use_private_krb5ccname() while a ' .
		    'private ccname is already in use.';
	}

	$self->{old_krb5ccname} = $ENV{KRB5CCNAME};
	$ENV{KRB5CCNAME} = "FILE:$self->{ccfile}";
}

sub reset_krb5ccname {
	my ($self) = @_;

	if (!exists($self->{old_krb5ccname})) {
		die 'called $kt->reset_krb5ccname() while no ' .
		    'private ccname is already in use.';
	}

	$ENV{KRB5CCNAME} = $self->{old_krb5ccname};
	delete $self->{old_krb5ccname};
}

sub vprint {
	my ($self, @args) = @_;

	if ($self->{verbose} > 0) {
		my ($s, $us) = gettimeofday();
		my $t = sprintf("%s.%06s -[%5d]- ",
		    strftime("%Y-%m-%d %T", localtime($s)), $us, $$);
		print STDERR $t, @args;
	}
}

sub format_err {
	my ($at) = @_;

	return $at->[0] . ": " . $at->[1]	if ref($at) eq 'ARRAY';
	return $at->{errstr}			if ref($at) eq 'HASH';
	return $at;
}

sub get_ugid {
	my @pwd = getpwnam($_[0]);

	die "can't determine uid for $_[0]" if @pwd < 9;

	($pwd[2], $pwd[3]);
}

sub in_set {
	my ($member, $set) = @_;

	for my $i (@$set) {
		return 1 if $i eq $member;
	}
	return 0;
}

sub is_subset {
	my ($subset, $set) = @_;
	my %tmp;

	for my $i (@$set) { $tmp{$i} = 1 }
	for my $i (@$subset) {
		return 0 if !$tmp{$i};
	}
	return 1;
}

sub enctypes_require_admin {
	! scalar(grep { $_ =~ m{^aes[12]} } @_) ||
	  scalar(grep { $_ =~ m{^des-cbc-} } @_);
}

sub lib_requires_admin {
	my ($self, $lib) = @_;
	my $krb5_libs = $self->{krb5_libs};

	enctypes_require_admin(@{$krb5_libs->{$lib}});
}

sub lib_better {
	my ($self, $a, $b) = @_;
	my $krb5_libs = $self->{krb5_libs};

	my @a = grep { $_ !~ m{^des-cbc-} } @{$krb5_libs->{$a}};
	my @b = grep { $_ !~ m{^des-cbc-} } @{$krb5_libs->{$b}};

	return  1	if is_subset(\@a, \@b);
	return -1	if is_subset(\@b, \@a);
	return scalar(@b) <=> scalar(@a);
}

sub sort_libs {
	my ($self, @l) = @_;

	sort { $self->lib_better($a, $b) } @l;
}

sub max_kvno {
	my $kvno = -1;
	for my $i (@{$_[0]}) {
		$kvno = $i->{kvno}	if $i->{kvno} > $kvno;
	}
	return $kvno;
}

#
# Hereafter we find the library quirk logic.  We have two functions here,
# the first will determine if a set of keys representing a keytab satisfies
# the current library's quirks.  The other one will fix the list.  The idea
# is that if lib_quirks() fails, then you have to create a new keytab by
# using the output of fix_quirks().  We implement two quirks currently,
# the first deals with Java Dain Brammage, i.e. the keys must be in order
# in the keytab.  The second deals with libraries that throw errors if they
# come across enctypes they don't grok.  This list may grow with time...

sub keys_sorted {
	my ($order, @keys) = @_;
	my %princs;
	my $kvno;

	if ($order ne 'ascending' && $order ne 'descending') {
		die "keys_sorted called inappropriately...";
	}

	for my $i (@keys) {
		$kvno = $princs{$i->{princ}};
		$princs{$i->{princ}} = $i->{kvno};

		next		if !defined($kvno);
		return 0	if $order eq 'ascending'  && $kvno > $i->{kvno};
		return 0	if $order eq 'descending' && $kvno < $i->{kvno};
	}

	return 1;
}

sub is_quirky {
	my ($self, $lib, @keys) = @_;
	my $krb5_libs = $self->{krb5_libs};
	my $krb5_lib_quirks = $self->{krb5_lib_quirks};

	return 0 if !defined($lib) || !exists($krb5_lib_quirks->{$lib});

	if (in_set('ascending', $krb5_lib_quirks->{$lib})) {
		return 1 if (!keys_sorted('ascending', @keys));
	}

	if (in_set('descending', $krb5_lib_quirks->{$lib})) {
		return 1 if (!keys_sorted('descending', @keys));
	}

	if (in_set('nounsupp', $krb5_lib_quirks->{$lib})) {
		for my $i (@keys) {
			if (!in_set($i->{enctype},
			    ['des-cbc-crc', @{$krb5_libs->{$lib}}])) {
				return 1;
			}
		}
	}

	return 0;
}

sub fix_quirks {
	my ($self, $lib, @keys) = @_;
	my $krb5_libs = $self->{krb5_libs};
	my $krb5_lib_quirks = $self->{krb5_lib_quirks};

	return @keys if !defined($lib);
	return @keys if !exists($krb5_lib_quirks->{$lib});

	$self->vprint("Fixing keytab quirks " .
	    join(', ', @{$krb5_lib_quirks->{$lib}}) .  " for library: $lib\n");
	if (in_set('nounsupp', $krb5_lib_quirks->{$lib})) {

		my @libenc = ('des-cbc-crc', @{$krb5_libs->{$lib}});
		@libenc = map { $revenctypes{$_} } @libenc;

		@keys = grep { in_set($_->{enctype}, \@libenc) } @keys;

	}

	if (in_set('ascending', $krb5_lib_quirks->{$lib})) {
		@keys = sort {$a->{kvno} <=> $b->{kvno}} @keys;
	}

	if (in_set('descending', $krb5_lib_quirks->{$lib})) {
		@keys = sort {$b->{kvno} <=> $a->{kvno}} @keys;
	}

	@keys;
}

sub latest_key_etypes {
	my ($princ, @keys) = @_;
	my $maxkvno = -1;
	my @ret;

	for my $i (@keys) {
		next		if ($i->{princ} ne $princ);
		next		if ($i->{kvno} < $maxkvno);
		@ret = ()	if ($i->{kvno} > $maxkvno);
		push(@ret, $i->{enctype});
		$maxkvno = $i->{kvno};
	}

	@ret;
}

sub supports_libs {
	my ($self, $princ, @keys) = @_;
	my %krb5_libs = %{$self->{krb5_libs}};
	my @ret;

	my $enclist = [ latest_key_etypes($princ, @keys) ];

	@ret = grep { is_subset($enclist,
	    ['des-cbc-crc', @{$krb5_libs{$_}}]) } (keys %krb5_libs);

	#
	# Now we have to map this against a quirk table that we
	# define.  This is rather unfortunate, but we must deal
	# with a level of dain brammage in Java and old MIT krb5.

	@ret = grep { !$self->is_quirky($_, @keys) } @ret;

	#
	# And now we sort them into an order of preference for display.
	# This is just to encourage correct behaviour.

	$self->sort_libs(@ret);
}

sub working_lib {
	my ($self, $princ, @keys) = @_;
	my $krb5_libs = $self->{krb5_libs};

	my $enclist = [ latest_key_etypes($princ, @keys) ];

	my ($ret) = grep { is_subset($krb5_libs->{$_}, $enclist) }
	    $self->supports_libs($enclist);
	$ret;
}

sub parse_princ { Krb5Admin::C::krb5_parse_name(@_); }

# XXXrcd: maybe we should perform a little validation later.
# XXXrcd: also lame because it is code duplication.
# XXXrcd: this is also not strictly speaking correct because we do
#         not appropriately quote it.  This should be fixed...
sub unparse_princ {
	my ($realm, @comps) = @{$_[0]};

	return join('/', @comps) . '@' . $realm;
}

#
# Munge the output of Krb5Admin::C::read_kt into something
# that is a little easier for me to deal with:

sub get_keys {
	my ($self, $kt) = @_;
	my $ctx = $self->{ctx};

	$kt = "FILE:" . $DEFAULT_KEYTAB if !defined($kt) || $kt eq '';
	my @ktkeys = Krb5Admin::C::read_kt($ctx, $kt);

	for my $i (@ktkeys) {
		$i->{enctype} = $enctypes{$i->{enctype}};
	}
	@ktkeys;
}

#
# Delete a principal (all keys) from a keytab file.

sub del_kt_princ {
	my ($self, $strprinc, $kt) = @_;
	my $ctx = $self->{ctx};

	$kt = "WRFILE:" . $DEFAULT_KEYTAB if !defined($kt) || $kt eq '';
	my @ktents = Krb5Admin::C::read_kt($ctx, $kt);

	for my $ktent (@ktents) {
		next if ($ktent->{"princ"} ne $strprinc);
		Krb5Admin::C::kt_remove_entry($ctx, $kt, $ktent)
	}
}

sub get_princs {
	my %ret;

	for my $i (@_) {
		$ret{$i->{princ}} = 1;
	}
	keys %ret;
}

#
# calculate the instances that we may need to fetch.

sub get_instances {
	my ($self, $realm) = @_;
	my $ctx = $self->{ctx};
	my @tmp;
	my %ret;

	@tmp = map {[ parse_princ($ctx, $_->{princ}) ]} ($self->get_keys(''));

	for my $i (grep { $_->[1] eq 'host' && $_->[0] eq $realm } @tmp) {
		$ret{$i->[2]} = 1;
	}
	keys %ret;
}

sub get_defrealm {
	my ($self) = @_;
	my $ctx = $self->{ctx};

	if (!defined($self->{defrealm})) {
		$self->{defrealm} = Krb5Admin::C::krb5_get_realm($ctx);
	}

	return $self->{defrealm};
}

#
# expand_princs takes the user name and either a list of strings
# representing princs, or a list of array ref princ representations
# and returns a list of said array refs.  The expansion is:
#
#	0.  if no princs are specified, start the procedure using
#	    either the user name or ``host'' if root,
#
#	1.  populate the realm if not specified,
#
#	2.  if the instance is not specified then expand it as
#	    either:
#
#		i.   if working with a host principal, we call
#		     host_list() which determines the valid host
#		     names for the current host, or
#
#		ii.  otherwise, we use all of the instances that
#		     we find associated with host principals in
#		     /etc/krb5.keytab as this is the maximal set
#		     that we could ever hope to fetch.

sub expand_princs {
	my ($self, $user, @princs) = @_;
	my $ctx = $self->{ctx};
	my @insts;
	my @hostinsts;
	my $instances;
	my $realm;
	my @ret;

	if (@princs == 0) {
		@princs = ($user);
		@princs = ('host')	if $user eq 'root';
	}

	for my $pr (@princs) {
		if (ref($pr) ne 'ARRAY') {
			$pr = [parse_princ($ctx, $pr)];
		}

		$realm = $pr->[0];
		if (!defined($realm) || $realm eq '') {
			$realm = $self->get_defrealm();
		}

		if (!defined($pr->[2]) || $pr->[2] eq '') {
			if ($pr->[1] eq 'host') {
				if (@hostinsts == 0) {
					@hostinsts = host_list(hostname());
				}
				@insts = @hostinsts;
			} else {
				if (!exists($instances->{$realm}) ||
				    @{$instances->{$realm}} == 0) {
					$instances->{$realm} =
					    [$self->get_instances($realm)];
				}
				@insts = @{$instances->{$realm}};
			}
		} else {
			@insts = ($pr->[2]);
		}

		push(@ret, map { [ $realm, $pr->[1], $_ ] } @insts);
	}

	return @ret;
}


#
# check_acls takes a single user and a list of principals specified
# as listrefs: [ REALM, name, instance ] and will exit if the requested
# operation is disallowed.
#
# This only checks if the user's keytab is allowed to contain the service
# principals requested and is used to allow, e.g. imapsvr to install keys
# for imap/hostname@REALM into /var/spool/keytabs/imapsvr if you are running
# your imap servers as the imapsvr user in your environment.
#
# Okay.  Now, we have a list of array refs representing the requested
# principals.  We need to do a little sanity checking on the data.  What
# we're doing here is a tad odd from first sight, but the configuration
# file contains a variable %user2service which is a hash which keys on
# the user.  The value is an array ref of services which the user is
# allowed to request in its keytabs.  We extract this array ref and turn
# it into a hash so that it can be used as a constant time lookup in the
# grep.  We also add $user to the hash for good measure as we implicitly
# allow the user to request keys for the service of the same name...

sub check_acls {
	my ($self, $user, @services) = @_;
	my @errs;
	my %user2service = %{$self->{user2service}};

	return if $user eq 'root';

	our %acl_svcs;
	$user2service{$user} = [$user] if !defined($user2service{$user});
	%acl_svcs = map { $_ => 1 } @{$user2service{$user}};

	for my $i (grep { !defined($acl_svcs{$_->[1]}) } @services) {
		push(@errs, "Permission denied: $user can't create " .
		    unparse_princ($i));
	}

	die \@errs if @errs;
}

sub obtain_lock {
	my ($self, $user) = @_;

	$self->{"lock.user.$user.count"} //= 0;
	return if $self->{"lock.user.$user.count"}++ > 0;

	my $lockdir  = "/var/run/krb5_keytab";
	my $lockfile = "$lockdir/lock.user.$user";

	#
	# Here we pessimistically create the lock directory.  Because this is
	# in /var/run, we assume that only root can create it---but just to be
	# sure we hammer the perms and ownership in the right way.  We use
	# mkpath to ensure that we create /var/run on SunOS 5.7 which
	# surprisingly doesn't come with it...

	mkpath($lockdir, 0, 0700);
	chmod(0700, $lockdir);
	chown(0, 0, $lockdir);

	my @s = stat($lockdir);
	die("lock directory invalid")
	    if (!@s || $s[2] != 040700 || $s[4] || $s[5]);

	$self->vprint("obtaining lock: $lockfile\n");

	#
	# XXXrcd: we have the possibility here of deadlocks as there is
	#         no timeout.  We have a couple of options, set an alarm
	#         or fall back to another locking method such as fcntl.

	my $lock_fh = new IO::File($lockfile, O_CREAT|O_WRONLY)
	    or die "Could not open lockfile $lockfile: $!";
	flock($lock_fh, LOCK_EX) or die "Could not obtain lock: $!";

	$self->vprint("lock obtained\n");

	#
	# And we save the lock in $self so that we can keep the lock
	# open and later unlock.

	$self->{"lock.user.$user.fh"} = $lock_fh;
}

sub release_lock {
	my ($self, $user) = @_;

	$self->{"lock.user.$user.count"} //= 0;
	if ($self->{"lock.user.$user.count"} < 1) {
		die "release_lock called for $user where no lock is held.";
	}

	return if --$self->{"lock.user.$user.count"};

	delete $self->{"lock.user.$user.fh"};
	unlink("/var/run/krb5_keytab/lock.user.$user");
}

#
# get_kt() determines the location of the keytab based on the user on
# which we are operating.

sub get_kt {
	my ($user) = @_;

	return "WRFILE:/var/spool/keytabs/$user" if $user ne 'root';
	return 'WRFILE:/etc/krb5.keytab';
}

#
# Here, what we do is a kinit(1) for the key and check the return code.
# If the kinit(1) is successful, then it's quite likely that we do not
# need to contact the KDC and so we don't.  This is is heuristic that we
# expect to work almost all the time.  And if it fails for some reason,
# then we simply contact the KDC which is not a problem.

sub need_new_key {
	my ($self, $kt, $key) = @_;
	my $ctx = $self->{ctx};

	my @ktkeys;
	eval { @ktkeys = Krb5Admin::C::read_kt($ctx, $kt); };

	if ($@ || !grep { $_->{princ} eq $key } @ktkeys) {
		return 1;
	}

	#
	# XXXrcd: need to use builtin kinit functions _but_ we
	#         have to avoid using the older keys as we are
	#         testing the integrity of the keytab.  Perhaps
	#         we must write a new C function to do this?

	# Avoid spawning shells, ignore stderr and stdout.
	#
	my $pid = fork();
	return 1 if ! defined($pid); # Can't fork
	if ($pid == 0) {
		open(STDOUT, ">/dev/null");
		open(STDERR, ">&STDOUT");
		exec { $KINIT } $KINIT, @KINITOPT,
			"-cMEMORY:foo", "-kt", "$kt", "$key";
		exit 1;
	}
	waitpid($pid, 0);
	return 1 if ($? != 0);
	return 0;
}

sub mk_keys {
	my ($self, @args) = @_;
	my $ctx = $self->{ctx};

	map {Krb5Admin::C::krb5_make_a_key($ctx, $_)} @args;
}

sub ktuniq {
	my @keys = @_;
	my %princs;
	my @ret;

	for my $i (@keys) {
		push(@{$princs{$i->{princ}}->{$i->{kvno}}}, $i);
	}

	for my $i (keys %princs) {
		for my $j (keys %{$princs{$i}}) {
			push(@ret, @{$princs{$i}->{$j}});
		}
	}

	@ret;
}

sub write_keys_internal {
	my ($self, $lib, $kt, @keys) = @_;
	my $ctx = $self->{ctx};

	$self->vprint("Starting to write keys in write_keys_internal...\n");
	for my $i ($self->fix_quirks($lib, @keys)) {
		next if $i->{enctype} == 0;

		$self->vprint("Writing (" . $i->{princ} . ", " .
		    $i->{kvno} . ", " . $i->{enctype} . ")\n");

		Krb5Admin::C::write_kt($ctx, $kt, $i);
	}
	$self->vprint("Finished writing keys in write_keys_internal...\n");
}

sub write_keys_kt {
	my ($self, $user, $lib, $princ, $kvno, @keys) = @_;
	my $ctx = $self->{ctx};
	my $oldkt;
	my $kt = get_kt($user);

	for my $i (@keys) {
		$i->{princ} = $princ	if defined($princ);
		$i->{kvno}  = $kvno	if defined($kvno);
	}

	$self->write_keys_internal($lib, $kt, @keys);

	my @ktkeys;
	eval { @ktkeys = Krb5Admin::C::read_kt($ctx, $kt); };

	return if $self->{force} < 2 && !$self->is_quirky($lib, @ktkeys);

	$self->vprint("Recreating keytab file fixing quirks...\n");

	$oldkt = $kt;
	$oldkt =~ s/WRFILE://;
	unlink("$oldkt.tmp");
	$kt = "WRFILE:$oldkt.tmp";
	@keys = ktuniq(@ktkeys, @keys);

	$self->write_keys_internal($lib, $kt, @keys);

	$kt =~ s/^WRFILE://;
	chmod(0400, $kt)		or die "chmod: $!";
	chown(get_ugid($user), $kt)	or die "chown: $!";
	rename($kt, $oldkt)		or die "rename: $!";

	$self->vprint("New keytab file renamed into position, quirk-free\n");
}

sub install_key {
	my ($self, $kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $ctx = $self->{ctx};
	my $default_krb5_lib = $self->{default_krb5_lib};
	my $krb5_libs = $self->{krb5_libs};
	my $strprinc = unparse_princ($princ);
	my $kt = get_kt($user);
	my $ret;
	my $etypes;

	if (!$kmdb) {
		die "Cannot connect to KDC.";
	}

	$etypes = $krb5_libs->{$lib} if defined($lib);

	if ($action ne 'change' && $self->{force} < 1) {
		return if !$self->need_new_key($kt, $strprinc);
	}

	$kmdb->master()		if $action eq 'change';

	$self->vprint("installing: $strprinc\n");

	my $func = $kmdb->can('change');
	eval { $ret = $kmdb->query($strprinc) };
	my $err = $@;
	if ($err) {
		die $err if $action ne 'default';
		$self->vprint("query error: " . format_err($err) . "\n");
		$self->vprint("creating: $strprinc\n");

		$func = $kmdb->can('create');
	}

	#
	# Now, in this mode, we cannot simply fetch the keys and
	# so, well, we will see if we are up to date.
	#
	# XXXrcd: If we aren't, well, the best thing that we can
	#         do is either toss an exception or just warn and
	#         change the keys.  For now, we die, if the instance
	#         is not the system fqdn (hostname is assumed to be
	#         an fqdn). For other instances, we abort, as the
	#         key may be shared among the members of a cluster.

	if (!$err && $action eq 'default') {
		my @ktkeys;
		eval { @ktkeys = Krb5Admin::C::read_kt($ctx, $kt); };
		@ktkeys = grep { $_->{"princ"} eq $strprinc } @ktkeys;

		if (max_kvno(\@ktkeys) < max_kvno($ret->{keys})) {
			#
			# If the instance matches the local hostname,
			# just change the key, it should not be shared
			# with other hosts.

			if ($princ->[2] ne hostname()) {
				die "The kvno for $strprinc is less than".
				    " the KDCs, aborting as the key may".
				    " be shared with other hosts. If the".
				    " is not shared, you may use $0 -c".
				    " to force a key change.\n";
			}
			$action = 'change';
		} else {
			$self->vprint("The keys for $strprinc already " .
			    "exist.\n");
			return;
		}
	}

	my $kvno = 0;
	my @kvno_arg = ();
	if ($action eq 'change') {
		# Find the max kvno:
		$kvno = max_kvno($ret->{keys});
		die "Could not determine max kvno" if $kvno == -1;
		@kvno_arg = ($kvno + 1);
	}

	if (!defined($etypes) && $action eq 'change') {
		my %enctypes;

		for my $i (grep {$_->{kvno} == $kvno} @{$ret->{keys}}) {
			$enctypes{$i->{enctype}}=1;
		}
		$etypes = [ keys %enctypes ];
	}

	if (!defined($etypes)) {
		$etypes = $krb5_libs->{$default_krb5_lib};
		$etypes = [map { $revenctypes{$_} } @$etypes];
	}
	my $gend = $kmdb->genkeys('change', $strprinc, $kvno + 1, @$etypes);
	$self->write_keys_kt($user, $lib, undef, undef, @{$gend->{'keys'}});
	&$func($kmdb, $strprinc, @kvno_arg, 'public' => $gend->{'public'},
	    'enctypes' => $etypes);

	return;
}

sub install_key_legacy {
	my ($self, $kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $krb5_libs = $self->{krb5_libs};
	my $strprinc = unparse_princ($princ);
	my $kt = get_kt($user);
	my @ret;
	my $etypes;

	if (!$kmdb) {
		die "Cannot connect to KDC.";
	}

	$etypes = $krb5_libs->{$lib} if defined($lib);

	if ($action ne 'change' && $self->{force} < 1) {
		return if !$self->need_new_key($kt, $strprinc);
	}

	$self->vprint("installing (legacy): $strprinc\n");

	$kmdb->master()		if $action eq 'change';

	eval { @ret = $kmdb->fetch($strprinc) };
	if ($@) {
		die $@ if $action ne 'default';
		$self->vprint("fetch error: " . format_err($@) . "\n");
		$self->vprint("creating: $strprinc\n");
		eval {
			$kmdb->create($strprinc);
			if (defined($etypes)) {
				$kmdb->change($strprinc, -1,
				    [$self->mk_keys(@$etypes)]);
			}
		};
		if ($@) {
			$self->vprint("creation error: ".format_err($@)."\n");
		}
		@ret = $kmdb->fetch($strprinc);
	}

	$self->write_keys_kt($user, $lib, $strprinc, undef, @ret);

	return if $action ne 'change';

	# Find the max kvno:
	my $kvno = -1;
	for my $i (@ret) {
		$kvno = $i->{kvno} if $i->{kvno} > $kvno;
	}
	die "Could not determine max kvno" if $kvno == -1;

	if (!defined($etypes)) {
		my %enctypes;

		for my $i (grep {$_->{kvno} == $kvno} @ret) {
			$enctypes{$i->{enctype}}=1;
		}
		$etypes = [ keys %enctypes ];
	}
	$kvno++;
	my @keys = $self->mk_keys(@$etypes);
	$self->write_keys_kt($user, $lib, $strprinc, $kvno, @keys);
	$kmdb->change($strprinc, $kvno, \@keys);

	return;
}

sub bootstrap_host_key {
	my ($self, $kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $default_krb5_lib = $self->{default_krb5_lib};
	my $krb5_libs = $self->{krb5_libs};
	my $use_fetch = $self->{use_fetch};
	my $ctx = $self->{ctx};
	my $strprinc = unparse_princ($princ);
	my $realm = $princ->[0];

	$self->vprint("bootstrapping a host key.\n");

	#
	# If we are here, then we've decided that we are bootstrapping
	# which means that we need to obtain credentials for a bootstrap
	# principal of the form bootstrap/*@REALM.  We find one and try
	# it.  If it fails to connect, we try another one.  We presume
	# that we're failing because the princ doesn't exist in the KDC
	# but perhaps we should test the result of Krb5Admin::Client->new()
	# to see if there was another reason...

	my $bootprinc;
	foreach my $ktent ($self->get_keys()) {
		# Ignore bootstrap keys with an unexpected enctype.
		next if (!defined($ktent->{"enctype"}) ||
		    $ktent->{"enctype"} ne $bootetype_name);
		my ($r, $n) = parse_princ($ctx, $bootprinc = $ktent->{"princ"});
		next if ($r ne $realm || $n ne 'bootstrap');

		$self->vprint("Trying to connect with $bootprinc creds.\n");
		if (!defined($kmdb)) {
			eval {
				$kmdb = Krb5Admin::Client->new($bootprinc,
				    { realm => $realm });
				$kmdb->master();
			};
			if ($@) {
				$self->vprint("$bootprinc failed to connect" .
				    " to a KDC for $realm: " .
				    format_err($@) . "\n");
			}
		}

		last if defined($kmdb);
	}

	if (!defined($kmdb)) {
		die "Can not connect to KDC.";
	}

	$self->vprint("Connected.\n");

	my $ret;
	eval { $ret = $kmdb->query($strprinc) };
	my $err = $@;
	if ($err) {
		die $err if $action ne 'default';
		$self->vprint("query error: " . format_err($err) . "\n");
		$self->vprint("creating: $strprinc\n");
	}

	my $kvno = 0;
	$kvno = max_kvno($ret->{keys})		if defined($ret);

	#
	# XXX: With etype aliases in Heimdal, may not need the rev map...

	my $etypes = $krb5_libs->{$lib} if defined($lib);
	if (!defined($etypes)) {
		$etypes = $krb5_libs->{$default_krb5_lib};
	}
	$etypes = [map { $revenctypes{$_} } @$etypes];

	my $gend = $kmdb->genkeys('bootstrap_host_key', $strprinc, $kvno + 1,
	    @$etypes);
	$self->write_keys_kt($user, $lib, undef, undef, @{$gend->{keys}});
	eval {
		$kmdb->bootstrap_host_key($strprinc, $kvno + 1,
		    public => $gend->{public}, enctypes => $etypes);

		#
		# The KDC deleted the bootstrap principal, so we do
		# likewise, but ignore errors, we got the main job done!

		eval { $self->del_kt_princ($bootprinc); };
	};

	#
	# SUCCCESS!

	return if !$@;

	$self->vprint("bootstrapping host key failed: ". format_err($@) ."\n");

	#
	# so, if we failed then perhaps we do not have
	# permissions?  If this is the case, then, well,
	# we're connected to the KDC already, we can simply
	# ask it what we need to do to make progress.

	$ret = $kmdb->query_host(name => $princ->[2]);

	if (!defined($ret)) {
		die "Cannot determine the host's bootbinding.";
	}

	if (!defined($bootprinc = $ret->{bootbinding})) {
		die "$strprinc is not bound to any bootstrap id.";
	}

	$self->vprint("host is actually bound to " . $bootprinc . "\n");

	$kmdb = Krb5Admin::Client->new($bootprinc, {realm => $realm});

	$self->vprint("Connected as " . $bootprinc . "\n");

	$gend = $kmdb->genkeys('bootstrap_host_key', $strprinc, $kvno + 1,
	    @$etypes);
	$self->write_keys_kt($user, $lib, undef, undef, @{$gend->{keys}});
	$kmdb->bootstrap_host_key($strprinc, $kvno + 1,
	    public => $gend->{public}, enctypes => $etypes);
	eval { $self->del_kt_princ($bootprinc); };

	return;
}

sub install_host_key {
	my ($self, $kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $use_fetch = $self->{use_fetch};
	my $f;

	#
	# host keys are just a little different than service keys.
	# If we have host credentials, then we may very well just
	# be able to use them.  If not, we must be bootstrapping and
	# we call bootstrap_host_key() which is a tad more complex.

	$f = \&install_key;
	$f = \&install_key_legacy	if $use_fetch;

	if ($kmdb) {
		#
		# XXXrcd: should we fail here or should we continue
		#         to the bootstrapping code because we may
		#         have lost our association with the KDC?

		return &$f(@_);
	}

	return bootstrap_host_key(@_);
}

sub install_bootstrap_key {
	my ($self, $kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $ctx = $self->{ctx};
	my $realm = $princ->[0];

	$self->vprint("installing a bootstrap key.\n");

	if (!defined($kmdb)) {
		$self->vprint("obtaining anonymous tickets from $realm.\n");
		# The default realm may not vend anon tickets, use the
		# target realm!
		#
		Krb5Admin::C::kinit_anonymous($ctx, $realm, undef);

		$self->vprint("connecting to $realm\'s KDC.\n");
		$kmdb = Krb5Admin::Client->new(undef, { realm => $realm });
	}

	my $gend = $kmdb->genkeys('create_bootstrap_id', 'bootstrap', 1,
	    $bootetype_code);
	my $binding = $kmdb->create_bootstrap_id(public => $gend->{public},
	    enctypes => [$bootetype_code], realm => $realm);
	$gend = $kmdb->regenkeys($gend, $binding);

	$self->write_keys_kt($user, undef, undef, undef, @{$gend->{keys}});

	# XXXrcd: must fix workflow here.
	# We must output the binding so that applications know what it is.
	return $binding;
}

#
# install_keys is a dispatcher that determines what to do with each
# key.  It will [optionally] create a connexion to krb5_admind ($kmdb)
# and dispatch to one of the functions that takes care of the particular
# kind of key that we want.  install_keys expects to be called with
# @princs being a list of parsed krb5 princs which have the same realm
# and instance.  It will either toss an exception if something goes
# horribly wrong or return an integral number of errors that were
# encountered.

sub install_keys {
	my ($self, $user, $kmdb, $got_tickets, $xrealm, $action, $lib,
	    @princs) = @_;
	my $use_fetch = $self->{use_fetch};
	my $realm = $princs[0]->[0];
	my $inst  = $princs[0]->[2];
	my $client;
	my $errs = [];
	my @ret;

	if (!$got_tickets) {
		$client = unparse_princ([defined($xrealm) ? $xrealm : $realm,
		    "host", $inst]);
	}

	if (!defined($kmdb)) {
		my $str = "";

		$str .= "connecting to $princs[0]->[0]'s KDCs";
		if (defined($client)) {
			$str .= " using $client creds.";
		}
		$self->vprint("$str\n");
		eval {
			$kmdb = Krb5Admin::Client->new($client,
			    { realm => $realm });
		};

		if (my $err = $@) {
			$self->vprint("Cannot connect to KDC: " .
			    format_err($err) . "\n");
		}
	}

	for my $princ (@princs) {
		my $strprinc = unparse_princ($princ);

		$self->vprint("Focussing on $strprinc.\n");

		my $f = \&install_key;

		$f = \&install_key_legacy	if $use_fetch;
		$f = \&install_host_key		if $princ->[1] eq 'host';

		if ($princ->[1] eq 'bootstrap' && $princ->[2] eq 'RANDOM') {
			$f = \&install_bootstrap_key;
		}

		my @res;
		eval {
			@res = &$f($self,$kmdb, $action, $lib, $client,
			    $user, $princ);
		};
		if (my $err = $@) {
			my $errstr = sprintf("Failed to install (%s) " .
			    "keys for %s instance %s, %s", $action, $user,
			    $strprinc, format_err($err));
			syslog('err', "%s", $errstr);
			push(@$errs, $errstr);
		} else {
			syslog('info', "Installed (%s) keys for %s " .
			    "instance %s", $action, $user, $strprinc);
		}

		push(@ret, @res);
	}

	die $errs if @$errs > 0;
	return @ret;
}

#
# install_all_keys just takes:
#
#	1.  the user,
#
#	2.  an action (default or change),
#
#	3.  the desired krb5 library compatibility, and
#
#	4.  a simple list of principals which are represented by
#	    listrefs [ REALM, service, instance ].  It breaks up
#	    the requests into groups with like instances and calls
#	    install_keys().
#
# It works by building a hash of instance => [ princs ] and iterating
# over the keys of that map calling install_keys.

sub install_all_keys {
	my ($self, $user, $action, $lib, @princs) = @_;
	my $ctx = $self->{ctx};
	my $use_fetch = $self->{use_fetch};
	my $kmdb = $self->{kmdb};
	my $got_tickets = $self->{got_tickets};
	my $xrealm = $self->{xrealm};
	my %instmap;
	my $kt = get_kt($user);
	my $errs = [];
	my @ret;

	$self->user_acled($user);
	$self->validate_lib($user, $lib);

	@princs = $self->expand_princs($user, @princs);

	$self->vprint("checking acls...\n");
	$self->check_acls($user, @princs);	# this will throw on failure.

	for my $i (@princs) {
		push(@{$instmap{$i->[0]}->{$i->[2]}}, $i);
	}

	my @connexions;
	for my $realm (keys %instmap) {
		for my $inst (keys %{$instmap{$realm}}) {
			push(@connexions, [$realm, $inst,
			    $instmap{$realm}->{$inst}]);
		}
	}

	my $instkeys = \&install_key;
	if ($use_fetch) {
		$instkeys = \&install_key_legacy;
	}

	$self->use_private_krb5ccname();
	$self->obtain_lock($user);

	for my $i (@connexions) {
		$self->vprint("installing keys for connexion $i->[0], " .
		    "$i->[1]...\n");

		my @res;
		eval {
			@res = $self->install_keys($user, $kmdb, $got_tickets,
			    $xrealm, $action, $lib, @{$i->[2]});
		};

		my $err;
		$err = $@ if $@;
		push(@$errs, @$err)  if defined($err) && ref($err) eq 'ARRAY';
		push(@$errs,  $err)  if defined($err) && ref($err) ne 'ARRAY';

		push(@ret,  @res);
	}

	$kt =~ s/^WRFILE://;
	chmod(0400, $kt)		or die "chmod: $!";
	chown(get_ugid($user), $kt)	or die "chown: $!";

	$self->release_lock($user);
	$self->reset_krb5ccname();

	$self->vprint("Successfully updated keytab file\n") if @$errs == 0;
	die $errs if defined($errs) && @$errs > 0;

	return @ret;
}

1;
