# 
#

package Krb5Admin::Log;

use base qw(Kharon::Log::Syslog);

use warnings;
use strict;

sub cmd_log {
        my ($self, $level, $code, $cmd, @args) = @_;

	@args = $args[0]	if $cmd eq 'create_user';
	@args = $args[0]	if $cmd eq 'change_passwd';
	@args = @args[0,1]	if $cmd eq 'change';

	return $self->SUPER::cmd_log($level, $code, $cmd, @args);
}

1;

