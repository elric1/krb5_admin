


package Krb5Admin::NotifyClient;

use DBI;
use Sys::Hostname;
use Sys::Syslog;
use IO::Pipe;
use Krb5Admin::Krb5Host::Client;

my $SENDMAIL="/usr/sbin/sendmail";
my $CF="/etc/postfix-prestash";

# This should fork exec maybe?
# host to specify the client cred
sub notify_update_required {
    my ($host) = @_;
    my $host_email = "notify\@$host"; 
    my @sendmail = ($SENDMAIL, "-i", "-f" ,'', "-C" , "$CF", $host_email );

    my $pid = fork();
    if ($pid == 0) {
	close(STDIN);
	exec(@sendmail);
    }
    
    if (!defined $pid) {
	die [500, "Error with sendmail exec"];
    } else {
	waitpid($pid, 0);

    }

}

1;
