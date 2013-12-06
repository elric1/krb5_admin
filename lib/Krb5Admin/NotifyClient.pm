


package Krb5Admin::NotifyClient;

use DBI;
use Sys::Hostname;
use Sys::Syslog;
use IO::Pipe;
use Krb5Admin::Krb5Host::Client;

my $SENDMAIL="/usr/sbin/sendmail";


# This should fork exec maybe?
# host to specify the client cred
sub notify_update_required {
    my ($host) = @_;
    my $host_email = "notify\@$host"; 
    my @sendmail = ($SENDMAIL, "-i", "-f" ,'', "-C" , "/test/postfix-prestash", $host_email );
    my $p = IO::Pipe->new();
    $p->reader(@sendmail);
    local $_;
    while (<$p>) {
    	$pw = $_;
	last;
    }
    $p->close(); 
}

1;
