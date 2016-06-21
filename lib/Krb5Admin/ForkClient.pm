#
#
# Blame: "Roland C. Dowdeswell" <elric@imrryr.org>

package Krb5Admin::ForkClient;
use base qw(Krb5Admin Kharon::Class::Client);

use Kharon::Protocol::ArrayHash;
use Kharon::Engine::Server;
use Kharon::Engine::Client::Fork;
use Kharon::Entitlement::Object;
use Kharon::Entitlement::Stack;
use Kharon::Entitlement::SimpleSQL;
use Kharon::Log::Null;

use Krb5Admin::Daemon;

use POSIX qw/dup2 _exit/;
use Sys::Hostname;

use strict;
use warnings;

sub run_daemon {
	my ($fh, $config, %args) = @_;

	dup2($fh->fileno(), 0);
	dup2($fh->fileno(), 1);

	$config->{master} = hostname();

	#
	# We default the logger to not log as this module is generally
	# used for testing.

	if (!defined($config->{logger})) {
		$config->{logger} = Kharon::Log::Null->new();
	}

	eval { Krb5Admin::Daemon::run($config, %args); };
	_exit($@ ? 1 : 0);
}

sub new {
	my ($proto, $config, %args) = @_;
	my $class = ref($proto) || $proto;

	my $self = $class->SUPER::new();

	$args{REMOTE_IP} = 'SOCKETPAIR'	if !defined($args{REMOTE_IP});

	my $ahr = Kharon::Protocol::ArrayHash->new(banner => {version=>'2.0'});
	my $pec = Kharon::Engine::Client::Fork->new(protocols => [$ahr]);

	my ($kid, $fh) = $pec->Connect();

	run_daemon($fh, $config, %args) if $kid == 0;

	$self->{pec} = $pec;
	$self->{kid} = $kid;

	bless($self, $class);
}

1;
