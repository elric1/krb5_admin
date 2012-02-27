#!/usr/pkg/bin/perl
#

use Test::More tests => 1;

use Krb5Admin::C;

use strict;
use warnings;

$ENV{KRB5_CONFIG} = 'FILE:./t/krb5.conf';

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $hndl  = Krb5Admin::C::krb5_get_kadm5_hndl($ctx, 'db:t/test-hdb');

unlink('t/test-hdb.db');

Krb5Admin::C::init_kdb($ctx, $hndl);

ok(1);

exit(0);
