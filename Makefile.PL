use strict;
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

	$txt =~
	    s#^(\s*..INST)(_SCRIPT.*)(SCRIPT\).*)$#\1\2\3\n\1_SBIN\2SBIN\3#mg;

	return $txt;
}
