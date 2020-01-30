AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = fido2-useradd
noinst_LTLIBRARIES = libmodauthnzfido2.la
noinst_DATA = mod_authnz_fido2.la

AM_CFLAGS = -g -Wall -Wextra ${APACHE_CFLAGS} ${JWT_CFLAGS} ${JANSSON_CFLAGS} ${FIDO_CFLAGS}
AM_LDFLAGS = ${JWT_LIBS} ${JANSSON_LDFLAGS} ${FIDO_LIBS} ${APR_LDFLAGS}

libmodauthnzfido2_la_SOURCES = mod_authnz_fido2.c conf.c util.c
fido2_useradd_SOURCES = fido2-useradd.c

install-exec-local:
	${APXS} -i -a -n 'authnz_fido2' mod_authnz_fido2.la

mod_authnz_fido2.la: libmodauthnzfido2.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${JWT_CFLAGS} ${JWT_LIBS} \
		${JANSSON_CFLAGS} ${JANSSON_LDFLAGS} ${FIDO_CFLAGS} ${FIDO_LIBS}

clean-local:
	rm -f mod_authnz_fido2.la

distclean-local:
	rm -f configure Makefile.in \
	   	  aclocal.m4 compile config.guess config.h.in config.sub \
	   	  depcomp install-sh ltmain.sh missing m4/*
	rm -rf autom4te.cache debian/tmp
