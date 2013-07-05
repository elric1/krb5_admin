use strict;
use ExtUtils::MakeMaker;

my $KRB5TYPE = "heimdal";	# Heimdal by default!
$KRB5TYPE = $ENV{KRB5TYPE}	if defined($ENV{KRB5TYPE});

my $KRB5DIR;
$KRB5DIR = $ENV{KRB5DIR}	if defined($ENV{KRB5DIR});

my $KINITOPT = "";		# Additional kinit options
$KINITOPT = $ENV{KINITOPT}	if defined($ENV{KINITOPT});

my $KRB5_KEYTAB_CONF = "/etc/krb5/krb5_keytab.conf";
$KRB5_KEYTAB_CONF = $ENV{KRB5_KEYTAB_CONF} if defined $ENV{KRB5_KEYTAB_CONF};

#
# First, we find the Kerberos libraries.  The builder can specify a
# number of environment variables to help us:
#
#		KRB5DIR		the directory to find Kerberos.
#				If not specified, we will look for
#				libgssapi{,_krb5}.so in /usr, /usr/pkg,
#				/usr/local and /opt/heimdal.
#		KRB5TYPE	either mit or heimdal.
#
# NOTE: we do not allow the user to pass KRB5DIR and KRB5TYPE on the
# command line as ExtUtils::MakeMaker will complain if we do that.
#
# NOTE: Krb5Admin/Makefile.PL does more autodiscovery because it needs
# to know a bit more about Kerberos than does this Makefile.PL.

if ($KRB5TYPE ne 'heimdal' && $KRB5TYPE ne 'mit') {
    die sprintf("Unrecognised Kerberos type: %s.  Must be mit or heimdal.\n",
		$KRB5TYPE);
}

#
# XXXrcd: we look for the .so rather than .so.X or .so.X.Y because we
#         are building and we therefore expect that the symlinks will
#         be installed.

for my $dir (qw{/usr /usr/local /usr/pkg /opt/heimdal}) {
	last	if defined($KRB5DIR);

	if ($KRB5TYPE eq "mit" && -f "$dir/lib/libgssapi_krb5.so") {
		$KRB5DIR = $dir;
	}

	if ($KRB5TYPE eq "heimdal" && -f "$dir/lib/libgssapi.so") {
		$KRB5DIR = $dir;
	}
}

if (!defined($KRB5DIR)) {
	die "Can't find the Kerberos libraries.\n";
}

$ENV{KRB5TYPE} = $KRB5TYPE;
$ENV{KRB5DIR} = $KRB5DIR;

my %args = (
    NAME     => 'Krb5Admin',
    AUTHOR   => 'Roland C. Dowdeswell <elric@imrryr.org>',
    VERSION  => '0.1',
    ABSTRACT => 'Framework for building Kerberos Administration Infrastructure',

    OPTIMIZE => '-g',
    EXE_FILES=> ['scripts/krb5_admind', 'scripts/krb5_admin',
		 'scripts/krb5_prestash'],

    PM_FILTER=> qq{sed} .
	qq{ -e "s,\@\@KRB5DIR\@\@,$KRB5DIR,"} .
	qq{ -e "s,\@\@KINITOPT\@\@,$KINITOPT,"} .
	qq{ -e "s,\@\@KRB5_KEYTAB_CONF\@\@,$KRB5_KEYTAB_CONF," },

    dist     => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean    => { FILES => 'Kharon-* t/sqlite.db' },
#    test     => { TESTS => 't/curve25519.t t/getkdc.t t/getrealm.t'},
);

#
# XXXrcd: For MIT Kerberos, we only support a subset of the tests, currently.

if ($KRB5TYPE eq 'mit') {
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
	    "	\$(NOECHO) \$(CHMOD) \$(PERM_RWX) \$(INST_SBIN_SCRIPT)\n" .
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
