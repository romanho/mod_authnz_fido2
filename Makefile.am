AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = fido2-useradd
noinst_LTLIBRARIES = libmodauthnzfido2.la
noinst_DATA = mod_authnz_fido2.la

AM_CFLAGS = -g -Wall -Wno-pointer-sign \
		  	${APACHE_CFLAGS} ${JWT_CFLAGS} ${FIDO_CFLAGS}
AM_LDFLAGS = ${JWT_LIBS} ${FIDO_LIBS} ${APR_LDFLAGS}

libmodauthnzfido2_la_SOURCES = mod_authnz_fido2.c conf.c token.c util.c
fido2_useradd_SOURCES = fido2-useradd.c

install-exec-local:
	moddir=$(DESTDIR)$$($(APXS) -q LIBEXECDIR)/; \
	mkdir -p $$moddir; \
	$(APXS) -i -S LIBEXECDIR=$$moddir -n 'authnz_fido2' mod_authnz_fido2.la

mod_authnz_fido2.la: libmodauthnzfido2.la
	${APXS} -c -o $@ $< ${APACHE_CFLAGS} ${JWT_CFLAGS} ${JWT_LIBS} \
		${FIDO_CFLAGS} ${FIDO_LIBS}

clean-local:
	rm -f mod_authnz_fido2.la

distclean-local:
	rm -f configure Makefile.in \
	   	  aclocal.m4 compile config.guess config.h.in config.sub \
	   	  depcomp install-sh ltmain.sh missing m4/*
	rm -rf autom4te.cache debian/tmp
