#
#

use Config;
use ExtUtils::MakeMaker;

use strict;
use warnings;

#
# XXXrcd: we use environment variables to determine the location
#         of the Kerberos libraries because for some reason,
#         ExtUtils::MakeMaker doesn't let me pass new variables
#         on the command line without emitting a warning.
#
#         We also attempt to locate a few of these things automagically.

my $KRB5DIR;
my $HAVE;

$KRB5DIR = $ENV{KRB5DIR}	if defined($ENV{KRB5DIR});
if (defined($ENV{KRB5TYPE})) {
	$HAVE = '-DHAVE_MIT'		if $ENV{KRB5TYPE} eq 'mit';
	$HAVE = '-DHAVE_HEIMDAL'	if $ENV{KRB5TYPE} eq 'heimdal';

	die "Unrecognised Kerberos type: " . $ENV{KRB5TYPE} .
	    ".  Must be mit or heimdal.\n";
}

#
# XXXrcd: we look for the .so rather than .so.X or .so.X.Y because we
#         are building and we therefore expect that the symlinks will
#         be installed.

for my $dir (qw{/usr /usr/local /usr/pkg}) {
	last	if defined($KRB5DIR);

	if (-f "$dir/lib/libgssapi.so" || -f "$dir/lib/libgssapi_krb5.so") {
		$KRB5DIR = $dir;
	}
}

#
# XXXrcd: here we take a rather heuristic approach for now.  We're just
#         looking for known differences between the two alternatives.

if (!defined($HAVE)) {
	if (-f "$KRB5DIR/lib/libheimbase.so") {
		$HAVE = '-DHAVE_HEIMDAL';
	}
	if (-f "$KRB5DIR/lib/libkrb5support.so") {
		$HAVE = 'DHAVE_MIT';
	}
}

#  $HAVE	.= ' -DHAVE_CTX_IN_KADM5';

if (!defined($KRB5DIR)) {
	die "Can't find the Kerberos libraries.\n";
}

if (!defined($HAVE)) {
	die "Can't determine type of Kerberos libraries.\n";
}

my %args;

$args{NAME}	= 'Krb5Admin::C';
$args{OBJECT}	= 'C_wrap.o curve25519-donna.o';

$args{INC}	= "-I${KRB5DIR}/include";

$args{PM}	= { 'C.pm' => '$(INST_LIB)/Krb5Admin/C.pm' };

if ($HAVE eq '-DHAVE_MIT') {
	$args{INC}	.= " -I${KRB5DIR}/include/krb5"		.
			   " -I/var/tmp/krb5-1.4.4/src/include"          .
			   " -I/var/tmp/krb5-1.4.4/src/include/krb5";
}

$args{CCFLAGS}	= $Config{ccflags} . " " . $HAVE;
$args{LIBS}	= "-L${KRB5DIR}/lib -Wl,-R${KRB5DIR}/lib ";

$args{LIBS} .= "-lkrb5 -lkadm5srv";

$args{clean} = { FILES => "C_wrap.c C.pm" };

WriteMakefile(%args);

sub MY::xs_c {
	"C.pm: C_wrap.c\n\n" .
	"C_wrap.c: C.c C.swig C.h \n	swig -perl5 ${HAVE} -const C.swig\n\n";
}
