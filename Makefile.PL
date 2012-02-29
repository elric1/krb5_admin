use strict;
use ExtUtils::MakeMaker;

#
# First, we find the Kerberos libraries.  The builder can specify a
# number of environment variables to help us:
#
#		KRB5DIR		the directory to find Kerberos.
#				If not specified, we will look for
#				libgssapi{,_krb5}.so in /usr, /usr/pkg,
#				and /usr/local.
#		KRB5TYPE	either mit or heimdal.  We'll try to
#				figure it out if not specified.
#
# NOTE: we do not allow the user to pass KRB5DIR and KRB5TYPE on the
# command line as ExtUtils::MakeMaker will complain if we do that.
#
# NOTE: Krb5Admin/Makefile.PL does more autodiscovery because it needs
# to know a bit more about Kerberos than does this Makefile.PL.

my $KRB5DIR;
$KRB5DIR = $ENV{KRB5DIR}	if defined($ENV{KRB5DIR});

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

if (!defined($KRB5DIR)) {
	die "Can't find the Kerberos libraries.\n";
}

$ENV{KRB5DIR} = $KRB5DIR;

#
# XXXrcd: here we take a rather heuristic approach for now.  We're just
#         looking for known differences between the two alternatives.

if (!defined($ENV{KRB5TYPE})) {
	if (-f "$KRB5DIR/lib/libheimbase.so") {
		$ENV{KRB5TYPE} = 'heimdal';
	}
	if (-f "$KRB5DIR/lib/libkrb5support.so") {
		$ENV{KRB5TYPE} = 'mit';
	}
}

if (!defined($ENV{KRB5TYPE})) {
	die "Could not determine Kerberos type.\n";
}

if ($ENV{KRB5TYPE} != 'heimdal' && $ENV{KRB5TYPE} != 'mit') {
	die "Unrecognised Kerberos type: " . $ENV{KRB5TYPE} .
	    ".  Must be mit or heimdal.\n";
}

my %args = (
    NAME     => 'Krb5Admin',
    AUTHOR   => 'Roland C. Dowdeswell <elric@imrryr.org>',
    VERSION  => '0.1',
    ABSTRACT => 'Framework for building Kerberos Administration Infrastructure',

    OPTIMIZE => '-g',
    EXE_FILES=> ['scripts/krb5_admind', 'scripts/krb5_admin',
		 'scripts/krb5_prestash'],

    PM_FILTER=> qq{sed -e s,\@\@KINIT\@\@,$KRB5DIR/bin/kinit, },

    dist     => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean    => { FILES => 'Kharon-*' },
#    test     => { TESTS => 't/curve25519.t t/getkdc.t t/getrealm.t'},
);

#
# XXXrcd: For MIT Kerberos, we only support a subset of the tests, currently.

if ($ENV{KRB5TYPE} eq 'mit') {
	$args{test} = { TESTS => 't/curve25519.t t/getkdc.t t/getrealm.t'};
}

my @manpages = qw{
		man/krb5_admin.1
		man/krb5_admind.8
		man/krb5_admind.conf.5
		man/krb5_prestash.1
	};

if ($ExtUtils::MakeMaker::VERSION >= 6.3002) {
	$args{LICENSE} = 'mit';
}

WriteMakefile(%args);

package MY;
sub constants {
	my ($self, @args) = @_;

	my $txt = $self->SUPER::constants(@args);

	$txt =~ s#^(INSTALL.*)(SCRIPT.*)bin#\1\2bin\n\1SBIN\2sbin#mg;
	$txt =~
	    s#^(DESTINSTALL.*)(SCRIPT.*)(SCRIPT\))#\1\2\3\n\1SBIN\2SBIN\3#mg;

	return $txt;
}

sub installbin {
	my ($self, @args) = @_;

	my $txt = $self->SUPER::installbin(@args);

	$txt =~
	    s#\$\(INST_SCRIPT\)/krb5_admind#\$(INST_SBIN_SCRIPT)/krb5_admind#g;

	$txt =~
	    s#^(..INST_SBIN.*)#$1 \$(INST_SBIN_SCRIPT)\$(DFSEP).exists#m;

	return "INST_SBIN_SCRIPT = \$(INST_SCRIPT)/../sbin\n\n" . $txt . "\n" .
	    "\$(INST_SBIN_SCRIPT)\$(DFSEP).exists :: Makefile.PL\n" .
	    "	\$(NOECHO) \$(MKPATH) \$(INST_SBIN_SCRIPT)\n" .
	    "	\$(NOECHO) \$(CHMOD) \$(PERM_DIR) \$(INST_SBIN_SCRIPT)\n" .
	    "	\$(NOECHO) \$(TOUCH) \$(INST_SBIN_SCRIPT)\$(DFSEP).exists\n";
}

sub install {
	my ($self, @args) = @_;

	my $txt = $self->SUPER::install(@args);

	$txt =~ s#^(doc_install.*)$#$1 manpage_install#m;

	$txt =~
	    s#^(\s*..INST)(_SCRIPT.*)(SCRIPT\).*)$#\1\2\3\n\1_SBIN\2SBIN\3#mg;

	my %manhash;
	for my $manpage (@manpages) {
		$manpage =~ /^(.*)\.(\d)$/;
		# XXXrcd: errors??

		push(@{$manhash{"man$2"}}, $manpage);
	}

	$txt .= "\n\nmanpage_install: " . join(' ', @manpages) . "\n";

	for my $mansect (keys %manhash) {
		for my $manpage (@{$manhash{$mansect}}) {
			my $mpbase = $manpage;
			$mpbase =~ s#.*/##;
			$txt .= "\tmkdir -p " .
			    "\$(DESTDIR)\$(PREFIX)/man/$mansect\n";
			$txt .= "\tinstall -c -m 644 $manpage " .
			    "\$(DESTDIR)\$(PREFIX)/man/$mansect/$mpbase\n";
		}
	}

	$txt .= "\n";

	return $txt;
}
