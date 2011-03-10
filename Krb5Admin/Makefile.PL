use ExtUtils::MakeMaker;

use strict;
use warnings;
use ExtUtils::MakeMaker;

my $HAVE	= '-DHAVE_MIT';
my $KRB5_DIR	= '/usr/local';

my %args;

$args{NAME}	= 'Krb5Admin::C';
$args{OBJECT}	= 'C_wrap.o';
$args{INC}	=  "-I${KRB5_DIR}/include"			.
		  " -I${KRB5_DIR}/include/krb5"			.
		  " -I/var/tmp/krb5-1.4.4/src/include"          .
		  " -I/var/tmp/krb5-1.4.4/src/include/krb5";

$args{CCFLAGS}	= $HAVE;
$args{LIBS}	= "-L${KRB5_DIR}/lib -Wl,-R${KRB5_DIR}/lib ";

$args{LIBS} .= "-lkrb5 -lkadm5srv";

WriteMakefile(%args);

sub MY::xs_c {
	"C_wrap.c: C.c C.i C.h \n	swig -perl5 ${HAVE} -const C.i\n\n"
}
