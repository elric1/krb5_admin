#!/usr/pkg/bin/perl
#

use Test::More tests => 1;

use Krb5Admin::C;

use strict;
use warnings;

$ENV{KRB5_CONFIG} = 'FILE:./t/krb5.conf';

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, undef);

ok(@{Krb5Admin::C::krb5_list_pols($ctx, $hndl, '*')} > 0, "Policies exist");

exit(0);
