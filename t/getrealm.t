#!/usr/pkg/bin/perl
#

use Test::More tests => 1;

use Krb5Admin::C;

use strict;
use warnings;

$ENV{KRB5_CONFIG} = './t/krb5.conf';

my  $ctx   = Krb5Admin::C::krb5_init_context();
our $REALM = Krb5Admin::C::krb5_get_realm($ctx);

ok($REALM eq 'TEST.REALM', "Realm $REALM unexpected");

exit 0;
