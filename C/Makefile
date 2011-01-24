# $Id: Makefile,v 1.12 2009/11/30 19:30:50 dowdes Exp $
#

INSTALL_PREFIX		= /usr/pkg
INSTALL_EXEC_PREFIX	= /usr/pkg
P5LIB			= ${INSTALL_PREFIX}/lib/perl5/Krb5_Admin/C
SOLIB			= ${INSTALL_EXEC_PREFIX}/lib/perl5/auto/Krb5_Admin/C

PERL	= perl
SWIG	= swig

KRB5_DIR= /usr/local/

#CFLAGS+= -O2 -Wall -Wno-unused-variable -Werror -Wuninitialized
# CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes 
#CFLAGS+= -Wpointer-arith
# CFLAGS+= -Wmissing-declarations -Wnested-externs
#CFLAGS+= -Wno-sign-compare -Wno-traditional
# CFLAGS+= -Wa,--fatal-warnings
#CFLAGS+= -Wreturn-type -Wswitch
# CFLAGS+= -Wshadow
# CFLAGS+= -Wcast-qual
#CFLAGS+= -Wwrite-strings
#CFLAGS+= -Wextra -Wno-unused-parameter
#CFLAGS+= -std=gnu99

CFLAGS+= `${PERL} -e 'use Config; print $$Config{ccflags};'`
CFLAGS+= -I/usr/pkg/lib/perl5/5.12.0/x86_64-netbsd-thread-multi/CORE/
CFLAGS+= -I${KRB5_DIR}/include -I${KRB5_DIR}/include/krb5
CFLAGS+= -I/var/tmp/krb5-1.4.4/src/include
CFLAGS+= -Dbool=char -fpic

LDFLAGS+= -L${KRB5_DIR}/lib -Wl,-R,${KRB5_DIR}/lib
LDFLAGS+= `${PERL} -e 'use Config; print $$Config{ldflags};'`
LDADD+= -lkrb5 -lk5crypto -lcom_err -lkadm5srv

all: krb5_keytab.so

build:

install:
	@mkdir -p ${SOLIB} ${P5LIB}
	@rsync -aL krb5_keytab.so ${SOLIB}
	@rsync -aL krb5_keytab.pm ${P5LIB}

clean:
	rm -f krb5_keytab.so krb5_keytab_wrap.[ch] *.o krb5_keytab.pm

krb5_keytab.so: krb5_keytab_wrap.o
	${CC} -shared ${LDFLAGS} -o krb5_keytab.so krb5_keytab_wrap.o ${LDADD}

krb5_keytab_wrap.c: krb5_keytab.i krb5_keytab.c krb5_keytab.h
	${SWIG} -perl5 -const krb5_keytab.i
