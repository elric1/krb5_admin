package Krb5Admin::FileLocks;

use Fcntl ':flock';
use File::Path;
use IO::File;
use MIME::Base64;

use Carp;

use strict;
use warnings;

our %fl_opts = (
	lockdir		=> '/var/run/krb5_keytab',
	testing		=> 0,
	locks		=> {},
);

sub new {
	my ($proto, %args) = @_;
	my $class = ref($proto) || $proto;

	my $self = { %fl_opts };

	bless($self, $class);

	$self->set_opt(%args);

	return $self;
}

sub DESTROY {
	my ($self) = @_;

	local($?);
	drop_all(@_);
}

sub internal_set_opt {
	my ($self, $opt, $val) = @_;

        die "Unrecognised option: $opt.\n" if !exists($fl_opts{$opt});

        if (!defined($val)) {
                $self->{$opt} = $fl_opts{$opt};
                return;
        }

        if (defined($fl_opts{$opt}) && ref($fl_opts{$opt}) ne ref($val)) {
                die "Option $opt must be of type " . ref($fl_opts{$opt}) .
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

sub create_lock_dir {
	my ($self) = @_;

	return if defined($self->{created});

	#
	# Here we pessimistically create the lock directory.  Because this is
	# in /var/run, we assume that only root can create it---but just to be
	# sure we hammer the perms and ownership in the right way.  We use
	# mkpath to ensure that we create /var/run on SunOS 5.7 which
	# surprisingly doesn't come with it...

	my $lockdir = $self->{lockdir};
	mkpath($lockdir, 0, 0700);
	chmod(0700, $lockdir);
	chown(0, 0, $lockdir);

	if (!$self->{testing}) {
		my @s = stat($lockdir);
		die("lock directory \"$lockdir\" invalid")
		    if (!@s || $s[2] != 040700 || $s[4] || $s[5]);
	}

	$self->{created} = 1;
	return;
}

#
# inner_obtain_lock returns nothing.  It tosses an exception
# signifying a permanent error.  It will set the fh in the
# object on success.

sub inner_obtain_lock {
	my ($self, $name, $type, $timeout) = @_;

	my $lockfile = $self->lock_name($name);

	my $lock = $self->{locks}->{$name};

	$lock->{type} = $type;
	$lock->{fh}   = new IO::File($lockfile, O_CREAT|O_WRONLY)
	    or die "Could not open lockfile $lockfile: $!";

	#
	# We attempt to flock() the file and use an alarm timer to
	# bail if it takes too long (to prevent deadlocks.)

	return $self->timed_flock($name, $type, $timeout);
}

sub timed_flock {
	my ($self, $name, $type, $timeout) = @_;
	$timeout //= 60;

	my $lockfile = $self->lock_name($name);
	my $lock_fh  = delete $self->{locks}->{$name}->{fh};

	local $SIG{ALRM} = sub { };

	my $fail;
	alarm($timeout);
	flock($lock_fh, $type) or $fail = "Could not obtain lock: $!\n";
	alarm(0);

	die $fail if defined($fail);

	#
	# Because we actually unlink(2) this file when we are finished,
	# we must check to see if we've got the file that we intended.

	my @fdstat = stat($lock_fh);
	my @fnstat = stat($lockfile);

	return	if @fnstat == 0;
	return	if $fdstat[0] != $fnstat[0];
	return	if $fdstat[1] != $fnstat[1];

	$self->{locks}->{$name}->{fh} = $lock_fh;
	return $lock_fh;
}

sub lock_name {
	my ($self, $name) = @_;

	my $b64_name;
	$b64_name = encode_base64($name, '');
	$b64_name =~ s,/,.,go;

	return $self->{lockdir} . "/lock.$b64_name";
}

sub kill_lock {
	my ($self, $name) = @_;
	my $type = $self->{locks}->{$name}->{type};

	if ($type == LOCK_SH) {
		my $fh;

		eval { $fh = $self->timed_flock($name, LOCK_EX, 2); };

		if (defined($fh)) {
			$type = LOCK_EX;
		}
	}

	if ($type == LOCK_EX) {
		unlink($self->lock_name($name));
	}
	delete $self->{locks}->{$name};
}

#
# The public interface:

sub drop_all {
	my ($self) = @_;

	for my $name (keys %{$self->{locks}}) {
		$self->kill_lock($name);
	}
}

sub obtain_lock {
	my ($self, $name, $type) = @_;

	$type //= LOCK_EX;

	$self->create_lock_dir();

	$self->{locks}->{$name} //= {};

	my $lock = $self->{locks}->{$name};
	$lock->{count} //= 0;
	if ($lock->{count} > 0) {
		$lock->{count}++;
		return;
	}

	my $end = time() + 120;
	while (time() < $end && !defined($lock->{fh})) {
		$self->inner_obtain_lock($name, $type, $end - time());
	}

	if (!defined($lock->{fh})) {
		die "Failed to obtain lock.\n";
	}

	$lock->{count}++;

	return;
}

sub release_lock {
	my ($self, $name) = @_;

	my $lock = $self->{locks}->{$name};

	if (!defined($lock) || $lock->{count} < 1) {
		die "release_lock called for $name where no lock is held.";
	}

	return if --$lock->{count};

	$self->kill_lock($name);
	return;
}

sub has_lock {
	my ($self, $name) = @_;

	my $lock = $self->{locks}->{$name};

	if (defined($lock) && $lock->{count} > 0) {
		return $lock->{$name}->{type};
	}

	return undef;
}

sub run_with_exlock {
	my ($self, $name, $cmd, @args) = @_;
	my $ret;

	$self->obtain_lock($name);
	eval {
		$ret = &$cmd(@args);
	};
	my $err = $@;
	$self->release_lock($name);
	die $err if $err;
	return $ret;
}

1;
