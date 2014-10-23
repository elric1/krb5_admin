#
#

package Krb5Admin::NotifyClient;

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
