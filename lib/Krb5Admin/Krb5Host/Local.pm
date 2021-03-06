#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::Krb5Host::Local;

use base qw/Krb5Admin::Krb5Host CURVE25519_NWAY::Kerberos/;

use Cwd;
use IO::File;
use File::Basename;
use File::Find;
use File::Path;
use File::Temp qw/ :mktemp /;
use Fcntl ':flock';
use POSIX qw(strftime);
use Sys::Hostname;
use Sys::Syslog;
use Time::HiRes qw(gettimeofday sleep);

use Krb5Admin::Client;
use Krb5Admin::FileLocks;
use Krb5Admin::IVFuncs;
use Krb5Admin::Krb5Host::Client;
use Krb5Admin::Krb5Host::Keytabs;
use Krb5Admin::Local;
use Krb5Admin::Utils qw/host_list force_symlink/;
use Krb5Admin::C;

use strict;
use warnings;

#
# Constants:

our $DEFAULT_KEYTAB = '/etc/krb5.keytab';
our $KRB5_KEYTAB_CONFIG = '@@KRB5_KEYTAB_CONF@@';
our $KINIT    = '@@KRB5DIR@@/bin/kinit';
our @KINITOPT = qw(@@KINITOPT@@ -l 10m -F);
our $hostname = hostname();

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
	admin_users		=> {},
	allowed_enctypes	=> [],
	config			=> undef,
	default_krb5_lib	=> 'mitkrb5/1.4',
	disabled_user_defaults  => {},
	ext_sync_func		=> sub {},
	force			=> 0,
	interactive		=> 0,
	invoking_user		=> undef,
	kadmin			=> 0,
	keytab_retries		=> 3,
	kmdb			=> undef,	# XXXrcd: more logic
	kmdb_config		=> '/etc/krb5/krb5_admind.conf',
	kmdb_config_provided	=> 0,
	krb5_lib		=> '',
	krb5_lib_quirks		=> {},
	krb5_libs		=> {},
	ktdir			=> undef,
	ktroot			=> undef,
	local			=> 0,
	subdomain_prefix	=> '',
	testing			=> 0,
	tixdir			=> ['/var/spool/tickets'],
	use_fetch		=> 0,
	user2service		=> {},
	user_libs		=> {},
	userqual		=> 0,
	verbose			=> 0,
	xrealm			=> undef,
);

sub new {
	my ($proto, %args) = @_;
	my $class = ref($proto) || $proto;

	my $self = { %kt_opts };

	$self->{ctx}		= Krb5Admin::C::krb5_init_context();
	$self->{defrealm}	= Krb5Admin::C::krb5_get_realm($self->{ctx});
	$self->{locks}		= Krb5Admin::FileLocks->new();

	bless($self, $class);

	#
	# Take the configuration parameters passed in:

	$self->set_opt(%args);
	$self->{myname} //= hostname();

	return $self;
}

sub DESTROY {
	my ($self) = @_;

	local($?);
	unlink($self->{ccfile}) if exists($self->{ccfile});
}

sub internal_set_opt {
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

	#
	# Percolate lockdir and testing to Krb5Admin::FileLocks:

	if ($opt eq 'lockdir') {
		$self->{locks}->set_opt($opt, $val);
		return;
	}

	if ($opt eq 'testing') {
		$self->{locks}->set_opt($opt, $val);
	}

	die "Unrecognised option: $opt.\n" if !exists($kt_opts{$opt});

	if (!defined($val)) {
		$self->{$opt} = $kt_opts{$opt};
		return;
	}

	if (defined($kt_opts{$opt}) && ref($kt_opts{$opt}) ne ref($val)) {
		die "Option $opt must be of type " . ref($kt_opts{$opt}) .
		    " but is of type " . ref($val) . "\n";
	}

	$self->{$opt} = $val;
}

sub set_opt {
	my ($self, %opts) = @_;

	for my $opt (keys %opts) {
		$self->internal_set_opt($opt, $opts{$opt});
	}
}

sub KHARON_SET_CREDS {
	my ($self, @creds) = @_;

	if (@creds == 0) {
		die "Must provide a credential to set_creds";
	}

	if (@creds > 1) {
		die "Krb5Admin::Krb5Host::Local does not support " .
		    "multiple credentials";
	}

	$self->{client} = $creds[0];
}

sub my_stat {
	my ($fn) = @_;

	my %cc;
	my @s = stat($fn) or return;

	$cc{mode}	= $s[2];
	$cc{nlink}	= $s[3];
	$cc{uid}	= $s[4];
	$cc{username}	= getpwuid($cc{uid});
	$cc{gid}	= $s[5];
	$cc{group}	= getgrgid($cc{gid});
	$cc{size}	= $s[7];
	$cc{atime}	= $s[8];
	$cc{mtime}	= $s[9];
	$cc{ctime}	= $s[10];

	return \%cc;
}

sub full_file_info {
	my ($fn) = @_;
	my %ret;

	$ret{path} = readlink($fn);
	$ret{stat} = my_stat($fn);

	my $fh = IO::File->new($fn, 'r');
	if (!defined($fh)) {
		$ret{error} = $!;
		return \%ret;
	}

	local $/;
	$ret{contents} = <$fh>;
	return \%ret;
}

#
# Basic remote admin:

sub KHARON_ACL_show_krb5_conf { return 1; }

sub show_krb5_conf {
	my ($self) = @_;

	sub ffinfo { ($_[0] => full_file_info($_[0])) }

	return {
		ffinfo('/etc/krb5.conf'),
		ffinfo('/etc/krb5/krb5_admind.conf'),
		ffinfo('/etc/krb5/krb5_hostd.conf'),
		ffinfo('/etc/krb5/krb5_keytab.conf'),
	};
}

#
# Remote keytab management:

sub KHARON_IV_list_keytab {
	my ($self, $cmd, $user) = @_;
	my $usage = "$cmd <user>";

	require_username($usage, 1, $user);
}
sub KHARON_ACL_list_keytab { return 1; }

sub list_keytab {
	my ($self, $user) = @_;
	my $ret;

	$ret->{ktname} = $self->get_kt($user);
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

sub KHARON_IV_query_keytab  { KHARON_IV_list_keytab(@_) }
sub KHARON_ACL_query_keytab { KHARON_ACL_list_keytab(@_) }

sub query_keytab {
	my ($self, $user) = @_;
	my $ret;

	my @keys = $self->get_keys($self->get_kt($user));
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
	my @keys = $self->get_keys($self->get_kt($user));
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
	my @keys = $self->get_keys($self->get_kt($user));
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

sub KHARON_IV_query_ticket {
	my ($self, $cmd, @users) = @_;
	my $usage = "$cmd [<user> ...]";

	require_usernames($usage, 1, @users);
}
sub KHARON_ACL_query_ticket { return 1; }

sub query_ticket {
	my ($self, @users) = @_;

	#
	# XXXrcd: for now, query_ticket only understands the primary
	#         location---that being the first array element.

	my $tixdir = $self->{tixdir}->[0];
	   $tixdir = $tixdir->{path}		if ref($tixdir) eq 'HASH';

	chdir($tixdir) or die;

	my %ret;
	find(sub {
		my $user = $_;
		my $realm = $File::Find::dir;

		$realm =~ s/^..(:@)?//;

		return if @users > 0 &&
			  (grep { $user eq $_ } @users) == 0;

		return if !-f $user;

		$ret{$user}->{$realm} = my_stat($user);
	}, '.');

	chdir('/');	# XXXrcd: back to the origin?

	return \%ret;
}

sub install_ticket {
	my ($self, $princstr, $tix) = @_;
	my $ctx = $self->{ctx};

	my $tixdir = $self->{tixdir};

	if (!defined($princstr)) {
		die "install_tickets called on undefined value.\n"
	}

	if (!defined($tix)) {
		die "install_tickets called without \$tix.\n"
	}

	my @princ = Krb5Admin::C::krb5_parse_name($ctx, $princstr);

	#
	# XXXrcd: Implement more appropriate name mappings, in
	#         the future...
	#
	#         For now, we just use the princ's name which is
	#         suboptimal...
	#
	#         This could be a security issue in the future, so
	#         we must revisit this decision.  For now, it is not
	#         as we call it with specified realms and it is a
	#         matter of configuration to only use realms that
	#         you trust.

	if (@princ != 2) {
		die "Fully qualified principal (\"$princstr\") is not " .
		    "eligible for prestashed tickets.\n";
	}

	my ($realm, $user) = @princ;

	my @errs;
	for my $t (@$tixdir) {
		if (ref($t) eq '') {
			$self->install_ticket_in_dir($realm, $user, undef, $tix, $t);
			next;
		}

		if (ref($t) ne 'HASH') {
			# This is a permanent error, no need to try
			# any other tix---the config is broken.
			die "install_ticket: Can't grok \$tixdir " .
			    "(from config)\n";
		}

		#
		# Now, ref($t) must equal HASH:

		my ($name, $passwd, $uid);

		if (defined($t->{username})) {
			($name, $passwd, $uid) = getpwnam($t->{username});

			if (!defined($uid)) {
				die "$t->{username} has no uid " .
				    "from \$tixdir\n";
			}
		}

		# It's okay for username to be undef, but not path.
		if (!defined($t->{path})) {
			die "\$tixdir hashes must specify ``path''";
		}

		$self->install_ticket_in_dir($realm, $user, $uid, $tix,
		    $t->{path});
	}

	die join(', ', @errs) if @errs > 0;
}

sub install_ticket_in_dir {
	my ($self, $realm, $user, $override_uid, $tix, $tixdir) = @_;
	my $ctx = $self->{ctx};

	my ($name, $passwd, $uid) = getpwnam($user);
	my $warn;

	# We first setup the correct directories unconditionally, let's
	# just make sure that they are all in place:
	#
	# XXXrcd: may not always be able to create $tixdir?

	my $defrealm = $self->get_defrealm();

	mkdir($tixdir, 0755);
	chmod(0755, $tixdir);

	my @st = stat($tixdir);
	if ($st[4] ne '0') {
		die "Will not prestash to non-root-owned directory!";
	}

	force_symlink(".", "$tixdir/\@$defrealm");

	if ($realm ne $defrealm) {
		$tixdir .= "/\@$realm";
		mkdir($tixdir, 0755);
		chmod(0755, $tixdir);
	}

	if (!defined($name) || $name ne $user) {
		die "Tickets received for illegal username: %s", $user
			unless ($user =~ m{^\w(-?\w+)*$});
		$warn = sprintf "Tickets received for non-existent user %s",
			$user;
		$uid = 0;
		$user .= ":nopwent";
	} else {
		unlink("$tixdir/$user:nopwent");
	}

	$uid = $override_uid	if defined($override_uid);

	# Install new tickets atomically by writing to a temporary ccache,
	# and moving it into place.

	my $ccache_fn = "$tixdir/$user";
	my $ccache_tmp = "$tixdir/.$user";
	my $ccache = "FILE:$ccache_tmp";
	Krb5Admin::C::init_store_creds($ctx, $ccache, $tix);
	chown($uid, 0, $ccache_tmp); # XXXrcd: chown() may fail in test mode.
	rename($ccache_tmp, $ccache_fn) or
		die "$0: rename($ccache_tmp, $ccache_fn): $!\n";
	die "$warn\n" if defined($warn);

	# Workaround for rpc.gssd which expects tickets to be of the
	# form krb5cc_*.  We install an alternate ccache of the name
	# krb5cc_:$user, so that rpc.gssd finds it.

	my $alt_fn  = "$tixdir/krb5cc_:$user";
	my $alt_tmp = "$tixdir/.krb5cc_:$user";
	$ccache = "FILE:$alt_tmp";
	Krb5Admin::C::init_store_creds($ctx, $ccache, $tix);
	chown($uid, 0, $alt_tmp); # XXXrcd: chown() may fail in test mode.
	rename($alt_tmp, $alt_fn) or
		die "$0: rename($alt_tmp, $alt_fn): $!\n";

	return;
}

sub fetch_tickets_realm {
	my ($self, $clnt, $realm) = @_;
	my $ctx = $self->{ctx};
	my @errs;

	my $kmdb = $self->get_kmdb();

	if (!defined($kmdb)) {
		$kmdb = Krb5Admin::Client->new($clnt, {realm=>$realm});
	}

	my $tix = $kmdb->fetch_tickets($realm);

	for my $princstr (keys %$tix) {
		my @princ = Krb5Admin::C::krb5_parse_name($ctx, $princstr);

		if ($princ[0] ne $realm) {
			my $err = "failed to install prestashed ticket for " .
			    "$princstr: realm doesn't match $realm";
			push(@errs, $err);
			syslog('err', "%s", $err);
		}

		eval { $self->install_ticket($princstr, $tix->{$princstr}); };

		if ($@) {
			push(@errs, $@);
			syslog('err', "%s", "failed to install prestashed " .
			    "ticket for $princstr: $@");
		} else {
			syslog('info', "installed prestashed ticket for %s",
			    $princstr);
		}
	}

	die join("\n", @errs) if @errs > 0;
}

sub fetch_tickets {
	my ($self, @realms) = @_;
	my @errs;

	#
	# XXXrcd: and ACLs.  ACLs ACLs ACLs.
	# XXXrcd: may also want to test euid == 0.

	syslog('info', "Running krb5_prestash fetch");

	$self->use_private_krb5ccname();

	my $clnt = 'host/' .  [host_list($self->{myname})]->[0];

	@realms = ($self->get_defrealm())	if @realms == 0;

	for my $realm (@realms) {
		eval {
			$self->{locks}->run_with_exlock(":::PRESTASH:::",
			    \&fetch_tickets_realm, $self, $clnt, $realm);
		};
		push(@errs, $@) if $@;
	}

	$self->reset_krb5ccname();

	die join("\n", format_err(@errs)) . "\n" if @errs > 0;
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

#
# validate_lib() determines if lib is valid but makes no assertion to
# whether it is allowed.

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
}

#
# and lib_acled() determines if the invoking user is allowed to
# install or change keys to library specified.

sub lib_acled {
	my ($self, $user, $krb5_lib) = @_;
	my $krb5_libs = $self->{krb5_libs};
	my $user_libs = $self->{user_libs};
	my $allowed_enctypes = $self->{allowed_enctypes};

	my $real_krb5_lib = $self->{default_krb5_lib};
	$real_krb5_lib = $krb5_lib if defined($krb5_lib);
	if (defined($real_krb5_lib) && exists($user_libs->{$user}) &&
	    !in_set($real_krb5_lib, $user_libs->{$user})) {
		die "$user does not support $real_krb5_lib.\n";
	}

	# XXXrcd: need to do something about this---we are allowing
	#         too much, aren't we?

	return;
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

	$kt = $self->get_init_kt() if !defined($kt) || $kt eq '';
	my @ktkeys = @{Krb5Admin::C::read_kt($ctx, $kt)};

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
	my @ktents = @{Krb5Admin::C::read_kt($ctx, $kt)};

	for my $ktent (@ktents) {
		next if ($ktent->{"princ"} ne $strprinc);
		Krb5Admin::C::kt_remove_entry($ctx, $kt, $ktent);
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
#
# XXXrcd: we replace the prior logic which calculates all of the
#         instances we could fetch by looking at the host keys as
#         we have decided to make the fetching of cluster keys
#         something which must be explicitly requested.  We leave
#         the prior code as comments for use by those that wish
#         to revert to such behaviour.

sub get_instances {
	my ($self, $user, $realm) = @_;
	my $prefix = '';

	$prefix = "$user." if $self->{userqual} == 1;

	return map { "$prefix$_" } (host_list($self->{myname}));

#	my $ctx = $self->{ctx};
#	my @tmp;
#	my %ret;
#
#	@tmp = map {[ parse_princ($ctx, $_->{princ}) ]} ($self->get_keys(''));
#
#	for my $i (grep { $_->[1] eq 'host' && $_->[0] eq $realm } @tmp) {
#		$ret{$i->[2]} = 1;
#	}
#	keys %ret;
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
					@hostinsts = host_list($self->{myname});
				}
				@insts = @hostinsts;
			} else {
				if (!exists($instances->{$realm}) ||
				    @{$instances->{$realm}} == 0) {
					$instances->{$realm} =
					    [$self->get_instances($user,
					    $realm)];
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

sub match_acl_templates {
	my ($princ, $templates) = @_;

	return undef if @$princ != 3;

	foreach my $t (@$templates) {
		next if (@$t != 3);
		my $i = 0;
		for ($i = 0; $i< 3; $i++) {
			next if (!defined $t->[$i] || $t->[$i] eq "");
			last if ($princ->[$i] ne $t->[$i]);
		}
		return 1 if ($i == 3);
	}
	return undef;
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
	my $user2service = $self->{user2service};

	return if $user eq 'root';

	if (!defined($user2service->{$user})) {
		$user2service->{$user} = [];
	}

	# if the user has been "disabled" then we don't assign the implicit
	# permissions
	if (!defined($self->{disabled_user_defaults}->{$user})) {
		push(@{$user2service->{$user}},
		    [$self->{defrealm}, $user, $hostname]);
		if (defined $self->{subdomain_prefix}) {
			push(@{$user2service->{$user}},
			    [$self->{defrealm}, undef, sprintf("%s.%s%s",
			    $user, $self->{subdomain_prefix},$hostname)]);
		}
	}

	for my $i (@services) {
		if (!match_acl_templates($i, $user2service->{$user})) {
			push(@errs, "Permission denied: $user can't create " .
			    unparse_princ($i));
		}
	}

	die \@errs if @errs;
}

sub mk_kt_dir {
	my ($self) = @_;
	my $ktdir = $self->{ktdir}	// "/var/spool/keytabs";
	my $ktroot = $self->{ktroot}	// "/";
	my $realroot;
	my $realktdir;

	$ktdir = "$ktroot/$ktdir";

	mkdir($ktdir, 0755);
	chmod(0755, $ktdir);
	die "$ktdir does not exist or isn't readable" if ! -d "$ktdir";

	$realroot  = Cwd::realpath($ktroot);
	$realroot .= "/"			if $realroot ne '/';
	$realktdir = Cwd::realpath($ktdir);

	if ($realroot ne substr($realktdir, 0, length($realroot))) {
		die "$realroot not the initial segment of $realktdir\n";
	}

	my $target;
	$target = substr($realktdir, length($realroot));
	$target =~ s#^/##;
	$target =~ s#[^/][^/]*#..#g;
	$target .= "/etc/krb5.keytab";

	force_symlink($target, "$ktdir/" .  '%{username}');
	force_symlink($target, "$ktdir/root");
}

#
# get_kt() determines the location of the keytab based on the user on
# which we are operating.

sub get_kt {
	my ($self, $user) = @_;
	my $prefix = "WRFILE:";

	return "$prefix$user" if defined($user) && $user =~ m#^/#;

	$prefix .= $self->{ktroot} . "/"	 if defined($self->{ktroot});
	$user = 'root'				 if !defined($user) ||
						    $user eq '';
	return "$prefix$self->{ktdir}/$user"	 if defined($self->{ktdir});
	return "$prefix/var/spool/keytabs/$user" if $user ne 'root';
	return "$prefix/etc/krb5.keytab";
}

sub get_init_kt {
	my ($self) = @_;

	if ($self->{testing}) {
		return $self->get_kt();
	}

	return "FILE:$self->{ktdir}/root"	if defined($self->{ktdir});
	return "FILE:/etc/krb5.keytab";
}

#
# Here, we make a quick determination to see if we need a new key.  We
# have stopped using the kinit(1) method and replaced it by fetching a
# ticket for the service key in question and validating that it works
# against our keytab.  This is a bit more robust.
#
# The arguments are:
#
#	$kt		string refering to keytab
#	$princ		string principal
#	$kvno		required kvno (undef == any)

sub need_new_key {
	my ($self, $kt, $princ, $kvno) = @_;
	my $ctx = $self->{ctx};

	my @ktkeys;
	eval {
		@ktkeys = @{Krb5Admin::C::read_kt($ctx, $kt)};
		@ktkeys = grep { $_->{princ} eq $princ} @ktkeys;
		if (defined($kvno)) {
			@ktkeys = grep { $_->{kvno} == $kvno} @ktkeys;
		}
	};

	return 1 if $@;
	return 1 if @ktkeys == 0;

	#
	# Now, we know that we have a chance, i.e. we have at least one
	# key for $princ, $kvno, we contact the KDC and have a chat.  We
	# will try to get a key for $kvno and if it fails, we will try
	# again.  The presumption here is that $kvno was determined during
	# an exchange with the master KDC and so whatever slave we are
	# talking to will eventually get updated.
	#
	# XXXrcd: we return that we require a new key on any error which
	#         is not strictly speaking correct.  Certain errors such
	#         as decrypt integrity check failed, principal not found,
	#         and so on mean we need a new key.  Other errors such as
	#         cannot contact KDC mean that the KDC infrastructure is
	#         having ``issues'' and we should likely punt in this
	#         situation.  We'll have to revisit this at a later date.
	#
	# XXXrcd: also: what about the case where a slave returns me kvno-1
	#         and it gives decrypt integrity check failed but the master
	#         has kvno and it is correct?  This should loop rather than
	#         give an error, shouldn't it?

	local $ENV{KRB5CCNAME} = "MEMORY:need_new_key-dont-thread-me";
	eval {
		Krb5Admin::C::kinit_kt($ctx, "host/" . $self->{myname},
		    undef, undef);
	};

	for my $i (1..10) {
		my $k;
		eval { $k = Krb5Admin::C::kt_kvno($ctx, $kt, $princ); };

		return 1 if $@;
		return 0 if !defined($kvno) || $k == $kvno;

		sleep(3);
	}

	return 1;
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

sub write_keys_with_quirks {
	my ($self, $lib, $kt, @keys) = @_;
	my $ctx = $self->{ctx};

	$self->vprint("Starting to write keys in write_keys_with_quirks...\n");
	for my $i ($self->fix_quirks($lib, @keys)) {
		next if $i->{enctype} == 0;

		$self->vprint("Writing (" . $i->{princ} . ", " .
		    $i->{kvno} . ", " . $i->{enctype} . ")\n");

		Krb5Admin::C::write_kt($ctx, $kt, $i);
	}
	$self->vprint("Finished writing keys in write_keys_with_quirks...\n");
}

sub write_keys_internal {
	my ($self, $user, $uid, $lib, $princ, $kvno, @keys) = @_;
	my $ctx = $self->{ctx};
	my $oldkt;
	my $kt = $self->get_kt($user);

	die "Empty key list write_keys_internal\n" if @keys == 0;

	for my $i (@keys) {
		$i->{princ} = $princ	if defined($princ);
		$i->{kvno}  = $kvno	if defined($kvno);
	}

	$self->write_keys_with_quirks($lib, $kt, @keys);

	if (!$self->{testing}) {
		if (!defined($uid)) {
			($uid) = get_ugid($user);
		}
		(my $ktfile = $kt) =~ s/WRFILE://;
		chmod(0400, $ktfile)
		    or die "chmod(0400, $ktfile): $!\n";
		chown($uid, 0, $ktfile)
		    or die "chown($uid, 0, $ktfile): $!\n";
	}

	my @ktkeys;
	eval { @ktkeys = @{Krb5Admin::C::read_kt($ctx, $kt)}; };

	for my $ktent (@ktkeys) {
		#
		# remove keys that are represented in @keys
		# by kvno but not enctype.  Here, we assume
		# that if a key is provided of a particular
		# princ, kvno then all of the keys for that
		# princ, kvno are provided.  It may seem a
		# little strange to do all of this after we
		# added the keys rather than just removing
		# all of the keys with matching princ, kvno
		# before we start but it is important to
		# ensure that we never remove a key that is
		# currently in use.  Krb5Admin::C::write_kt()
		# already has logic to overwrite mismatched
		# keys and to leave matching keys in place.

		my @tmp;

		@tmp = grep { $ktent->{princ} eq $_->{princ} } @keys;
		@tmp = grep { $ktent->{kvno}  eq $_->{kvno} }  @tmp;

		#
		# Now, @tmp should represent the keys passed in that
		# match $ktent's princ and kvno.  If there are none,
		# then we are not operating on this princ, kvno and
		# so we leave the key in place.

		next if @tmp == 0;

		#
		# Otherwise, we leave the key in place if one of the
		# keys in @tmp has the same enctype as the key, i.e.
		# we just wrote it.

		next if grep { $ktent->{enctype} eq $_->{enctype} } @tmp;

		eval { Krb5Admin::C::kt_remove_entry($ctx, $kt, $ktent); };
	}

	#
	# We do not really need to reload here but we're making sure that
	# nothing went horribly wrong...

	@ktkeys = ();
	eval { @ktkeys = @{Krb5Admin::C::read_kt($ctx, $kt)}; };

	if (defined($self->{ext_sync_func})) {
		$self->{ext_sync_func}->($ctx, $kt, @keys);
	}

	return if $self->{force} < 2 && !$self->is_quirky($lib, @ktkeys);

	$self->vprint("Recreating keytab file fixing quirks...\n");

	$oldkt = $kt;
	$oldkt =~ s/WRFILE://;
	unlink("$oldkt.tmp");
	$kt = "WRFILE:$oldkt.tmp";
	@keys = ktuniq(@ktkeys, @keys);

	$self->write_keys_with_quirks($lib, $kt, @keys);

	$kt =~ s/^WRFILE://;
	if (!$self->{testing}) {
		if (!defined($uid)) {
			($uid) = get_ugid($user);
		}
		chmod(0400, $kt)	or die "chmod(0400, $kt): $!\n";
		chown($uid, 0, $kt)	or die "chown($uid, 0, $kt): $!\n";
	}
	rename($kt, $oldkt)		    or die "rename: $!\n";

	$self->vprint("New keytab file renamed into position, quirk-free\n");
}

sub write_keys_kt_uid {
	my ($self, @args) = @_;
	my $u = $args[0];

	$self->{locks}->run_with_exlock($u, \&write_keys_internal, @_);
}

sub write_keys_kt {
	my ($self, $u, @args) = @_;

	return $self->write_keys_kt_uid($u, undef, @args);
}

# XXXrcd: hmmm, we're saving kmdb in our hash.  Should we undef it if
#	  set_opt() is called with various parameters?  Or in any other
#	  circumstances?
sub get_kmdb {
	my ($self, %args) = @_;
	my $realm = $args{realm};
	my $xrealm = $args{xrealm};

	#
	# Here we attempt to return a kmdb handle if we are configured
	# to fetch one in a predefined way.  Otherwise, we return undef
	# and let the caller obtain one the way in which they would like.

	return $self->{kmdb} if defined($self->{kmdb});

	#
	# Below, all of the mechanisms require administrative access, so we
	# enforce it here:

	if ($self->{invoking_user} ne 'root') {
		if ($self->{local}) {
			die "Local access requires root\n";
		}
		if (defined($self->{winprinc})) {
			die "Windows bootstrapping requires root\n";
		}
	}

	#
	# Are we configured to use the local Kerberos DB?

	if ($self->{local}) {
		$self->{kmdb} = Krb5Admin::Local->new({
			config => $self->{kmdb_config},
			config_provided => $self->{kmdb_config_provided},
		});
		return $self->{kmdb};
	}

	#
	# How about windows principal bootstrapping?

	if (defined($self->{winprinc})) {
		my @princs;

		@princs = ($self->{winprinc}) if $self->{winprinc} ne '';

		if (@princs == 0) {
			my %hashprincs;

			die "opt xrealm must be defined if winprinc == ''.\n"
			    if !defined($xrealm);

			%hashprincs = map { $_->{princ} => 1 }
			    ($self->get_keys(''));
			@princs = map { [parse_princ($_)] } (keys %hashprincs);
			@princs = grep { $_->[0] eq $xrealm } @princs;
			@princs = grep { $_->[1] =~ /\$$/o } @princs;
			@princs = grep { !defined($_->[2]) } @princs;

			if (@princs == 0) {
				die "Can't find any principals in realm " .
				    $xrealm . " which end in a buck (\$).\n";
			}

			@princs = map { unparse_princ($_) } @princs;
		}

		my $ret;
		for my $princ (@princs) {
			# XXXrcd: get rid of system($KINIT).
			$ret = system($KINIT, '-k', @KINITOPT, $princ);

			if ($ret == 0) {
				$self->{kmdb} = Krb5Admin::Client->new(undef,
				    {realm=>$realm});
				return $self->{kmdb};
			}

			$self->vprint("Warning: Could not obtain tickets for ".
			    "$princ.\n");
		}

		die "could not obtain creds for any windows principal.\n";
	}

	#
	# And, finally, we try to obtain admin tickets if we are so
	# configured.
	return if !$self->{kadmin};

	if (!$self->{interactive}) {
		die "Must be run interactively to use kadmin princs.\n";
	}

	print "Please enter your Kerberos administrative principal\n";
	print "This is generally your username followed by ``/admin'',\n";
	print "I.e.: user/admin\n\n";

	for (my $i=0; $i < 10; $i++) {
		print "Admin principal: ";
		my $admin = <STDIN>;

		chomp($admin);

		if ($admin !~ m,[a-z0-9A-Z]+/admin,) {
			print "Invalid Kerberos admin principal.\n";
			next;
		}

		# XXXrcd: remove system($KINIT) because das ist nicht gut.
		system($KINIT, @KINITOPT, $admin) and next;
		$self->{kmdb} = Krb5Admin::Client->new(undef, {realm=>$realm});
		return $self->{kmdb};
	}
}

sub get_hostbased_kmdb {
	my ($self, $realm, $inst) = @_;
	my $xrealm = $self->{xrealm};
	my $client;
	my $kmdb;

	$kmdb = $self->get_kmdb(realm => $realm);
	return $kmdb if defined($kmdb);

	$inst = $self->owner_inst($realm, $inst);

	if (defined($self->{hostbased_kmdb})		&&
	    $self->{hostbased_kmdb_realm} eq $realm	&&
	    $self->{hostbased_kmdb_inst}  eq $inst) {
		return $self->{hostbased_kmdb};
	}

	$xrealm //= $realm;
	$client = unparse_princ([$xrealm, "host", $inst]);

	# XXXrcd: put a message into get_kmdb()...
	$self->vprint("connecting to ${realm}'s KDCs using $client creds.\n");

	$kmdb = Krb5Admin::Client->new($client, { realm => $realm });

	if (defined($kmdb)) {
		$self->{hostbased_kmdb}		= $kmdb;
		$self->{hostbased_kmdb_realm}	= $realm;
		$self->{hostbased_kmdb_inst}	= $inst;
	}

	return $kmdb;
}

sub reset_hostbased_kmdb {
	my ($self) = @_;

	undef($self->{hostbased_kmdb});
}

#
# We override the methods in CURVE25519_NWAY::Kerberos to perform the
# appropriate locking and writing of keytabs.  These functions are passed
# $priv which is expected to be a list reference documented in:
# CURVE25519_NWAY::Kerberos.

sub curve25519_privfunc {
	my ($priv, $hnum, $fromkdc) = @_;

	#
	# We only accept this kind of information as a hash ref
	# from the KDC.

	return undef if $hnum != 0;
	return undef if ref($fromkdc) ne 'HASH';

	my ($op, $user, $name, $lib, $kvno, %args) = @$priv;

	if (!defined($kvno) && defined($fromkdc->{kvno})) {
		$kvno = $fromkdc->{kvno};
	}

	return [$op, $user, $name, $lib, $kvno, %args];
}

sub KHARON_ACL_curve25519_start		{ KHARON_ACL_curve25519_final(@_); }
sub KHARON_ACL_curve25519_step		{ return 1; }

my @curve25519_ops = qw(change create);

# XXX - validate user is a user
sub KHARON_ACL_curve25519_final {
	my ($self, $cmd, $priv) = @_;

	my ($op, $user, $name) = @$priv;

	if ((grep { $op eq $_ } @curve25519_ops) < 1) {
		return "arg1 must be one of: " . join(', ', @curve25519_ops);
	}

	return cluster_acl($self, $name);
}

sub cluster_acl {
	my ($self, $name) = @_;
	my $ctx   = $self->{ctx};
	my $creds = $self->{client};

	# Cache ACL results for a given cluster name and requesting client
	# credentials.
	#
	if (exists $self->{"_acl"}->{$name}->{$creds}) {
	    return $self->{"_acl"}->{$name}->{$creds};
	}
	# Instantiate initial undef value
	my $r = \$self->{"_acl"}->{$name}->{$creds};

	my $defrealm = Krb5Admin::C::krb5_get_realm($ctx);

	my ($crealm, $cservice, $chost) =
	    Krb5Admin::C::krb5_parse_name($ctx, $creds);

	my ($realm, $service, $logical) =
	    Krb5Admin::C::krb5_parse_name($ctx, $name);

	#
	# XXXrcd: should we enforce restrictions on realm in @pp?  Certainly,
	#         we can't just as a random KDC whether we're in a cluster
	#         with some hosts that it administers.  So, we'll enforce
	#         this for now...

	if ($crealm ne $defrealm) {
		return "Client must come from default realm.";
	}

	if ($cservice ne 'host') {
		return "Only host princs can negotiate keys.";
	}

	if ($realm ne $defrealm) {
		return "Cluster logical names must be in the default realm.";
	}

	my $kmdb = $self->get_hostbased_kmdb($realm, $self->{myname});
	my $master;
	MASTER_FALLBACK: {
		my $cluster = $kmdb->query_hostmap($logical);
		my @hosts = ($self->{myname}, $chost);
		for my $host (@hosts) {
			next if grep { $_ eq $host } @$cluster;

			if (!defined($master)) {
				$master = $kmdb->master();
				redo MASTER_FALLBACK;
			}
			$$r = sprintf("host %s is not a member of cluster %s.",
				      $host, $logical);
		}
	}
	$self->reset_hostbased_kmdb();
	return ($$r //= 1);
}

sub curve25519_start {
	my ($self, $priv, $hnum, $pub) = @_;
	# XXXrcd: validate args.
	my ($op, $user, $name, $lib, $kvno, %args) = @$priv;

	return $self->SUPER::curve25519_start($priv, $hnum, $pub);
}

sub curve25519_final {
	my ($self, $priv, $hnum, $nonces, $pub) = @_;
	my ($op, $user, $name, $lib, $kvno, %args) = @$priv;

	my $keys = $self->SUPER::curve25519_final($priv, $hnum, $nonces, $pub);

	$self->write_keys_kt($user, $lib, undef, undef, @$keys);

	return;
}

sub KHARON_ACL_write_old {
	my ($self, $cmd, $user, $princ) = @_;
	return cluster_acl($self, $princ);
}

sub write_old {
	my ($self, $user, $strprinc, $lib, @keys) = @_;
	$self->write_keys_kt($user, $lib, $strprinc, undef, @keys);
}

sub recover_old_keys {
	my ($user, $strprinc, $lib, $kmdb, @hosts) = @_;
	my @keys;

	eval { @keys = $kmdb->fetch_old($strprinc) };
	if (@keys) {
		foreach my $host (@hosts) {
			$host->write_old($user, $strprinc, $lib, @keys);
		}
	}
}

sub install_key_locked {
	my ($kmdb, $self, $action, $lib, $user, $princ, $local_authz) = @_;
	my $ctx = $self->{ctx};
	my $default_krb5_lib = $self->{default_krb5_lib};
	my $krb5_libs = $self->{krb5_libs};
	my $strprinc = unparse_princ($princ);
	my $kt = $self->get_kt($user);
	my $ret;
	my $etypes;

	$etypes = $krb5_libs->{$lib} if defined($lib);

	eval { $ret = $kmdb->query($strprinc) };
	my $err = $@;
	if ($err) {
		die $err if $action ne 'default';
		$self->vprint("query error: " . format_err($err) . "\n");
		$self->vprint("creating: $strprinc\n");
	}

	#
	# Now, in this mode, we cannot simply fetch the keys and
	# so, well, we will see if we are up to date.  We check this
	# by first comparing kvno's but we need to realise that just
	# because we have a kvno in our keytab, it does not mean that
	# it is actually valid, so we must also test that.
	#
	# XXXrcd: If we aren't, well, the best thing that we can
	#         do is either toss an exception or just warn and
	#         change the keys.  For now, we die, if the instance
	#         is not the system fqdn (hostname is assumed to be
	#         an fqdn). For other instances, we abort, as the
	#         key may be shared among the members of a cluster.

	my $kvno;
	$kvno = max_kvno($ret->{keys})		if defined($ret);

	if (!$err && $action eq 'default') {
		if (!$self->need_new_key($kt, $strprinc, $kvno)) {
			$self->vprint("The keys for $strprinc already " .
			    "exist.\n");
			return;
		}

		$action = 'change';
	}

	if (!defined($etypes) && $action eq 'change') {
		# XXXrcd: shadows global.
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

	#
	# Deal with clustering.  If we are asking for a cluster princ,
	# then we calculate the hosts in the cluster and store them in
	# @hosts.  We sort the list to ensure that we fail more quickly
	# if we can't obtain locks as any two hosts requesting a change
	# will try to lock the same host first.  How the sorting is
	# accomplished is immaterial as long as all hosts sort in the
	# same way and so we simply lexically sort on hostname.

	my $cluster;
	my @hosts;

	if ($princ->[2] ne $self->{myname}
	    && defined($cluster = $kmdb->query_hostmap($princ->[2]))
	    && @$cluster > 0) {
		die sprintf("host %s is not a member of cluster %s.\n",
		            $self->{myname}, $princ->[2])
			unless (grep($_ eq $self->{myname}, @$cluster));
		for my $h (sort @$cluster) {
			if ($h eq $self->{myname}) {
				push(@hosts, $self);
				next;
			}
			push(@hosts, Krb5Admin::Krb5Host::Client->new($h));
		}
	} else {
		@hosts = ($self);
	}

	CURVE25519_NWAY::do_nway(['change', $user, $strprinc, $lib,
	    undef, enctypes => $etypes, local_authz => $local_authz],
	    [$kmdb, @hosts], privfunc => \&curve25519_privfunc);

	$self->vprint("About to recover old keys.\n");

	recover_old_keys($user, $strprinc, $lib, $kmdb, @hosts);

	return;
}

sub install_key {
	my ($self, $action, $lib, $user, $princ, $local_authz) = @_;
	my $strprinc = unparse_princ($princ);
	my $kt = $self->get_kt($user);

	if ($action ne 'change' && $self->{force} < 1) {
		return if !$self->need_new_key($kt, $strprinc);
	}

	$self->vprint("installing: $strprinc\n");

	my $kmdb = $self->get_hostbased_kmdb($princ->[0], $princ->[2]);
	die "Cannot connect to KDC.\n"	if !$kmdb;

	#
	# XXXrcd: for now we "eval" the KDC side locking as it may not
	#         be implemented.  If the function is not implemented,
	#         then we use old-style locks which although imperfect
	#         are likely better than nothing...

	my $can_lock_hostprinc = 1;
	eval {
		$kmdb->lock_hostprinc($strprinc);
	};
	if ($@) {
		if (ref($@) eq 'HASH' && $@->{errstr} =~ /^No handler def/) {
			$can_lock_hostprinc = 0;
			$kmdb->master();
			$self->{locks}->obtain_lock($user);
		} else {
			die $@;
		}
	}
	eval {
		install_key_locked($kmdb, @_);
	};
	my $err = $@;
	if ($can_lock_hostprinc) {
		$kmdb->unlock_hostprinc($strprinc);
	} else {
		$self->{locks}->release_lock($user);
	}
	die $err if $err;
	return;
}

sub install_key_fetch_locked {
	my ($self, $action, $lib, $user, $princ) = @_;
	my $krb5_libs = $self->{krb5_libs};
	my $strprinc = unparse_princ($princ);
	my $kt = $self->get_kt($user);
	my @ret;
	my $etypes;

	my $kmdb = $self->get_hostbased_kmdb($princ->[0], $princ->[2]);
	die "Cannot connect to KDC.\n"	if !$kmdb;

	$etypes = $krb5_libs->{$lib} if defined($lib);

	if ($action ne 'change' && $self->{force} < 1 && !$self->{local}) {
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
	die "Could not determine max kvno\n" if $kvno == -1;

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

sub install_key_fetch {
	my ($self, @args) = @_;
	my $u = $args[2];

	$self->{locks}->run_with_exlock($u, \&install_key_fetch_locked, @_);
}

sub bootsort {
	my ($ctx, $realm, $a, $b) = @_;
	my ($ra, $na) = parse_princ($ctx, $a->{"princ"});
	my ($rb, $nb) = parse_princ($ctx, $b->{"princ"});

	return -1	if $ra eq $realm      && $rb ne $realm;
	return  1	if $ra ne $realm      && $rb eq $realm;
	return -1	if $na eq 'bootstrap' && $nb ne 'bootstrap';
	return  1	if $na ne 'bootstrap' && $nb eq 'bootstrap';
	return $a cmp $b;
}

sub bootstrap_host_key_locked {
	my ($self, $action, $lib, $user, $princ) = @_;
	my $default_krb5_lib = $self->{default_krb5_lib};
	my $krb5_libs = $self->{krb5_libs};
	my $use_fetch = $self->{use_fetch};
	my $ctx = $self->{ctx};
	my $strprinc = unparse_princ($princ);
	my $realm = $princ->[0];

	$self->vprint("bootstrapping a host key.\n");

	my $kmdb = $self->get_kmdb(realm => $realm);

	#
	# If we are here, then we've decided that we are bootstrapping
	# which means that we need to obtain credentials for a bootstrap
	# principal of the form bootstrap/*@REALM.  We find one and try
	# it.  If it fails to connect, we try another one.  We presume
	# that we're failing because the princ doesn't exist in the KDC
	# but perhaps we should test the result of Krb5Admin::Client->new()
	# to see if there was another reason...

	my $bootprinc;
	my @ktents = sort { bootsort($ctx, $realm, $a, $b) } $self->get_keys();
	foreach my $ktent (@ktents) {
		# Ignore bootstrap keys with an unexpected enctype.
		next if (!defined($ktent->{"enctype"}) ||
		    $ktent->{"enctype"} ne $bootetype_name);
		my ($r, $n) = parse_princ($ctx, $bootprinc = $ktent->{"princ"});

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
		die "Can not connect to KDC.\n";
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

	my $kvno = 1;
	$kvno = max_kvno($ret->{keys})		if defined($ret);

	#
	# XXX: With etype aliases in Heimdal, may not need the rev map...

	my $etypes = $krb5_libs->{$lib} if defined($lib);
	if (!defined($etypes)) {
		$etypes = $krb5_libs->{$default_krb5_lib};
	}
	$etypes = [map { $revenctypes{$_} } @$etypes];

	eval {
		CURVE25519_NWAY::do_nway(['bootstrap_host_key', $user,
		    $strprinc, $lib, undef, enctypes => $etypes],
		    [$kmdb, $self], privfunc => \&curve25519_privfunc);

		$kmdb = $self->get_hostbased_kmdb($princ->[0], $princ->[2]);

		recover_old_keys($user, $strprinc, $lib, $kmdb, $self);

		#
		# The KDC deleted the bootstrap principal, so we do
		# likewise, but ignore errors, we got the main job done!

		my ($r, $n) = parse_princ($ctx, $bootprinc);
		if ($n eq 'bootstrap') {
			eval { $self->del_kt_princ($bootprinc); };
		}
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

	$ret = $kmdb->query_host($princ->[2]);

	if (!defined($ret)) {
		die "Cannot determine the host's bootbinding.\n";
	}

	if (!defined($bootprinc = $ret->{bootbinding})) {
		die "$strprinc is not bound to any bootstrap id.\n";
	}

	$self->vprint("host is actually bound to " . $bootprinc . "\n");

	$kmdb = Krb5Admin::Client->new($bootprinc, {realm => $realm});

	$self->vprint("Connected as " . $bootprinc . "\n");

	CURVE25519_NWAY::do_nway(['bootstrap_host_key', $user,
	    $strprinc, $lib, undef, enctypes => $etypes],
	    [$kmdb, $self], privfunc => \&curve25519_privfunc);

	$kmdb = $self->get_hostbased_kmdb($princ->[0], $princ->[2]);

	recover_old_keys($user, $strprinc, $lib, $kmdb, $self);

	my ($r, $n) = parse_princ($ctx, $bootprinc);
	if ($n eq 'bootstrap') {
		eval { $self->del_kt_princ($bootprinc); };
	}

	return;
}

sub bootstrap_host_key {
	my ($self, @args) = @_;
	my $u = $args[2];

	$self->{locks}->run_with_exlock($u, \&bootstrap_host_key_locked, @_);
}

sub install_host_key {
	my ($self, $action, $lib, $user, $princ) = @_;
	my $use_fetch = $self->{use_fetch};
	my $f;

	#
	# host keys are just a little different than service keys.
	# If we have host credentials, then we may very well just
	# be able to use them.  If not, we must be bootstrapping and
	# we call bootstrap_host_key() which is a tad more complex.

	my $kmdb;
	eval {
		$kmdb = $self->get_hostbased_kmdb($princ->[0], $princ->[2]);
	};

	if ($kmdb) {
		$f = \&install_key;
		$f = \&install_key_fetch	if $use_fetch || $self->{local};

		my $result;
		eval { $result = &$f(@_); };
		return $result unless ($@);
	}

	return bootstrap_host_key(@_);
}

sub install_bootstrap_key_locked {
	my ($self, $action, $lib, $user, $princ) = @_;
	my $ctx = $self->{ctx};
	my $realm = $princ->[0];

	die "Must be root to request bootstrap key.\n" if $user ne 'root';

	$self->vprint("installing a bootstrap key.\n");

	my $kmdb = $self->get_kmdb(realm => $realm);
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

	return $binding;
}

sub install_bootstrap_key {
	my ($self, @args) = @_;
	my $u = $args[2];

	$self->{locks}->run_with_exlock($u, \&install_bootstrap_key_locked, @_);
}

# Use host/<primary_hostname> unless the instance requested exactly matches
# some host/<secondary_name> in the system keytab file.
#
sub owner_inst {
	my ($self, $realm, $host) = @_;

	foreach my $ktent ($self->get_keys()) {
		my $princ = $ktent->{"princ"};
		my @princ = parse_princ($self->{ctx}, $princ);
		next if @princ != 3;
		next if ($realm ne $princ[0]);
		next if ($princ[1] ne "host");
		my $phost = $princ[2];
		return $host if ($phost eq $host);
	}
	return $hostname;
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
#
# The innards of install_keys have been refactored into install_single_key.

sub install_single_key {
	my ($self, $user, $action, $lib, $princ) = @_;
	my $use_fetch = $self->{use_fetch};
	my $local_authz = 1;

	eval {
		$self->vprint("checking acls...\n");
		$self->check_acls($user, $princ);
	};
	$local_authz = 0 if $@;

	my $strprinc = unparse_princ($princ);

	$self->vprint("Focussing on $strprinc.\n");

	my $f = \&install_key;

	$f = \&install_key_fetch	if $use_fetch || $self->{local};
	$f = \&install_host_key		if $princ->[1] eq 'host' &&
					   $user eq 'root';

	if ($princ->[1] eq 'bootstrap' && $princ->[2] eq 'RANDOM') {
		$f = \&install_bootstrap_key;
	}

	my @res;
	eval {
		@res = &$f($self, $action, $lib, $user, $princ,
		    $local_authz, {invoking_user => $user});
	};

	if (my $err = $@) {
		my $errstr = sprintf("Failed to install (%s) " .
		    "keys for %s instance %s, %s", $action, $user,
		    $strprinc, format_err($err));
		syslog('err', "%s", $errstr);
		die $errstr;
	}

	syslog('info', "Installed (%s) keys for %s " .
	    "instance %s", $action, $user, $strprinc);

	return @res;
}

sub install_single_key_with_retry {
	my ($self, $user, $action, $lib, $princ) = @_;
	my $errs = [];

	my $delay = 1;
	my @args = ($self, $user, $action, $lib, $princ);
	for (my $i=0; $i < $self->{keytab_retries}; $i++) {
		my @res;
		eval {
			@res = install_single_key(@args);
		};

		return @res		if !$@;
		push(@$errs, $@);

		$self->vprint("ERR: " . format_err($@) . "\n");

		sleep($delay + rand(1));
		$delay *= 1.5;
	}

	die $errs;
}

sub install_keys {
	my ($self, $user, $action, $lib, @princs) = @_;
	my $errs = [];
	my @ret;

	my @args = ($self, $user, $action, $lib);
	for my $princ (@princs) {
		my @res;
		eval {
			@res = install_single_key_with_retry(@args, $princ);
		};

		push(@$errs, @{$@})	if $@;
		push(@ret, @res);
	}

	$self->reset_hostbased_kmdb();
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
	my %instmap;
	my $kt = $self->get_kt($user);
	my $errs = [];
	my @ret;

	$self->user_acled($user);
	$self->validate_lib($user, $lib);

	my ($uid, $gid) = get_ugid($user);

	@princs = $self->expand_princs($user, @princs);

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

	local $ENV{'KRB5_KTNAME'}   = $self->get_init_kt('root');

	$self->use_private_krb5ccname();
	$self->mk_kt_dir();

	for my $i (@connexions) {
		$self->vprint("installing keys for connexion $i->[0], " .
		    "$i->[1]...\n");

		my @res;
		eval {
			@res = $self->install_keys($user, $action, $lib,
			    @{$i->[2]});
		};

		my $err;
		$err = $@ if $@;
		push(@$errs, @$err)  if defined($err) && ref($err) eq 'ARRAY';
		push(@$errs,  $err)  if defined($err) && ref($err) ne 'ARRAY';

		push(@ret,  @res);
	}

	$kt =~ s/^WRFILE://;
	if (-f $kt && !$self->{testing}) {
		chmod(0400, $kt)	or die "chmod(0400, $kt): $!\n";
		chown($uid, 0, $kt)	or die "chown($uid, 0, $kt): $!\n";
	}

	$self->reset_hostbased_kmdb();
	$self->reset_krb5ccname();

	$self->vprint("Successfully updated keytab file\n") if @$errs == 0;
	die $errs if defined($errs) && @$errs > 0;

	return @ret;
}

sub KHARON_ACL_do_update {
	my ($self) = @_;
	my $client = $self->{client};

	#
	# Allow admin users and any user named krb5notify/

	return 1 if $client =~ m/^([-a-zA-Z0-9])+\/admin@.+$/;
	return 1 if $client =~ m{^krb5notify(?:/[-_a-zA-Z0-9\.]+)?\@.+$};

	return undef;
}

sub do_update {
	my ($self) = @_;

	# Refresh tickets from the realm of the requesting KDC
	#
	# XXX: We're assuming the KDC handles only one realm, ideally the KDC
	# should provide the desired realm.

	my $ctx = $self->{ctx};
	my ($realm, @dummy) = parse_princ($ctx, $self->{client});

	my $kmdb = $self->get_hostbased_kmdb($realm, $self->{client});

	# We slap the get_hostbased_kmdb handle on to the global kmdb
	# handle here to make master work. This should be OK, because
	# nothing else in this execution of the hostd will try to use
	# this kmdb.

	$self->{kmdb} = $kmdb;
	$self->{kmdb}->master();
	$self->fetch_tickets($realm);
	return "OK";
}

sub mkkts {
	my ($self) = @_;
	# XXXrcd: this should be in only one place...
	my $ktdir = $self->{ktdir} // '/var/spool/keytabs';

	my %args;
	$args{ctx} = $self->{ctx};
	$args{sqldbname} = "$ktdir/.ktabs";

	return Krb5Admin::Krb5Host::Keytabs->new(%args);
}

#
# The new API for managing key locations:

#
# XXXrcd: below we directly call the KHARON_IV_* in each of the
#         functions.  We play to fix this by changing to a "Local"
#         object like we did with Krb5Admin::Local...

sub KHARON_IV_fetch_generator {
	my ($self, $cmd, $generator) = @_;
	my $usage = "$cmd <generator>";

	require_fqprinc($self->{ctx}, $usage, 1, $generator);
}

sub fetch_generator {
	my ($self, $generator) = @_;
	my $ctx = $self->{ctx};

	$self->KHARON_IV_fetch_generator("fetch_generator", $generator);
	my @princ = parse_princ($ctx, $generator);

	$self->use_private_krb5ccname();
	my $kmdb = $self->get_hostbased_kmdb($princ[0], hostname());

	my @keys = $kmdb->fetch("WELLKNOWN/DERIVED-KEY/KRB5-CRYPTO-PRFPLUS/"
	    . $generator);

	$self->reset_hostbased_kmdb();
	$self->reset_krb5ccname();

	my @args = ($generator);
	my $kts = $self->mkkts();

	for my $key (@keys) {
		$kts->mk_generator($generator, $key);
	}

	return;
}

sub KHARON_IV_mk_generator {
	my ($self, $cmd, $generator, $kvno, $enctype, $key) = @_;
	my $usage = "$cmd <generator> <kvno> <enctype> <key>";

	require_fqprinc($self->{ctx}, $usage, 1, $generator);
	require_scalar($usage, 2, $kvno);
	require_scalar($usage, 3, $enctype);
	require_scalar($usage, 4, $key);
}

sub mk_generator {
	my ($self, $generator, $kvno, $enctype, $key) = @_;

	$self->KHARON_IV_mk_generator("mk_generator", $generator,
	    $kvno, $enctype, $key);

	my $kts = $self->mkkts();
	$kts->mk_generator($generator,
	    {kvno=>$kvno, enctype=>$enctype, key=>$key});
	return;
}

sub rm_generator {
	my ($self, @args) = @_;
	my $kts = $self->mkkts();

	return $kts->rm_generator(@args);
}

sub list_generators {
	my ($self, @args) = @_;
	my $kts = $self->mkkts();

	return $kts->list_generators(@args);
}

sub KHARON_IV_mk_keytab {
	my ($self, $cmd, $path, $uid) = @_;
	my $usage = "$cmd <path> <uid>";

	require_scalar($usage, 1, $path);
	require_number($usage, 2, $uid);
}

sub mk_keytab {
	my ($self, $path, $uid) = @_;
	my $kts = $self->mkkts();

	KHARON_IV_mk_keytab($self, "mk_keytab", $path, $uid);
	$kts->mk_keytab($path, $uid);
}

sub rm_keytab {
	my ($self, @paths) = @_;
	my $kts = $self->mkkts();

	for my $path (@paths) {
		$kts->rm_keytab($path);
	}
}

sub list_keytabs {
	my ($self, @path) = @_;
	my $kts = $self->mkkts();

	return $kts->list_keytabs(@path);
}

sub add_princ_to_keytab {
	my ($self, $p, $keytab) = @_;
	my $kts = $self->mkkts();

	$kts->add_key($keytab, $p);
	my $keys = $kts->get_full_keys_for_princ($p);

	my %kvnos;

	for my $key (@$keys) {
		push(@{$kvnos{$key->{'kvno'}}}, $key);
	}

	my $uid = $kts->query_keytab($keytab)->{uid};

	for my $kvno (keys %kvnos) {
		$self->write_keys_kt_uid($keytab, $uid, undef,
		    $p, $kvno, @{$kvnos{$kvno}});
	}

	return;
}

sub rm_princ_from_keytab {
	my ($self, $p, $keytab) = @_;
	my $kts = $self->mkkts();

	$kts->rm_key($keytab, $p);

	return;
}

sub list_keys {
	my ($self) = @_;
	my $kts = $self->mkkts();

	$kts->list_keys();
}

1;
