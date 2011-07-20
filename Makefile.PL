use strict;
use warnings;
use ExtUtils::MakeMaker;

my %args = (
    NAME     => 'Krb5Admin',
    AUTHOR   => 'Roland C. Dowdeswell <elric@imrryr.org>',
    VERSION  => '0.1',
    ABSTRACT => 'Framework for building Kerberos Administration Infrastructure',

    OPTIMIZE => '-g',
    EXE_FILES=> ['scripts/krb5_admind', 'scripts/krb5_admin'],

    dist     => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean    => { FILES => 'Kharon-*' },
);

if ($ExtUtils::MakeMaker::VERSION >= 6.3002) {
	$args{LICENSE} = 'mit';
}

WriteMakefile(%args);
