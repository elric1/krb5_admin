use strict;
use warnings;
use ExtUtils::MakeMaker;

my $KRB5_DIR = '/usr/local';

my %args;
$args{NAME}		= 'Krb5Admin';
$args{AUTHOR}		= q{Roland C. Dowdeswell <elric@imrryr.org>};
$args{VERSION_FROM}	= 'lib/Krb5Admin/KerberosDB.pm';
$args{ABSTRACT_FROM}	= 'lib/Krb5Admin/KerberosDB.pm';

if ($ExtUtils::MakeMaker::VERSION >= 6.3002) {
	$args{LICENSE} = 'mit';
}

$args{EXE_FILES}	= ['scripts/krb5_admind', 'scripts/krb5_admin'];

$args{dist}		= { COMPRESS => 'gzip -9f', SUFFIX => 'gz', };
$args{clean}		= { FILES => 'Kharon-*' };

WriteMakefile(%args);
