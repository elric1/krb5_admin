#
#

package Krb5Admin::NotifyClient;

use Exporter;   
@ISA = qw(Exporter);
@EXPORT_OK = qw{ notify_update_required };

use DBI;
use Sys::Hostname;
use Sys::Syslog;
use IO::Pipe;
use Krb5Admin::Krb5Host::Client;

my $SENDMAIL = "/usr/sbin/sendmail";
my $CF = "/etc/postfix-prestash";

sub notify_host {
	my ($krb5, $host) = @_;
	my $host_email = "notify\@$host";
	my @sendmail = ($SENDMAIL, "-i", "-f" ,'', "-C" , "$CF", $host_email);

	#
	# Short-circuit if the host principal doesn't exist.  This
	# means that the host hasn't yet been bootstrapped.  We delay
	# this test until this function as in previous opportunities,
	# we might be dealing with a cluster name for which we would
	# not expect to find a host princ.

	eval { $krb5->query("host/$host"); };
	return if $@;

	my $pid = fork();
	if ($pid == 0) {
		close(STDIN);
		close(STDERR);
		exec { $SENDMAIL } @sendmail;
		exit(1);
	}
	if (!defined $pid) {
		die [500, "Error with sendmail exec"];
	} else {
		waitpid($pid, 0);
	}
}

sub notify_update_required {
	my ($krb5, $host) = @_;
	my $hdef = $krb5->query_host($host);
	if ($hdef->{is_logical}) {
		my $hostmaps = $krb5->query_hostmap($host);
		for my $hmap (@$hostmaps) {
			notify_host($krb5, $hmap);
		}
	} else {
		notify_host($krb5, $host);
	}
}

1;
