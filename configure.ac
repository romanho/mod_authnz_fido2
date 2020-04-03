AC_INIT(FIDO2 authentication module for Apache 2, 0.1, roman@hodek.net, mod_authnz_fido2)
#AC_PREREQ(2.60)
#AC_CONFIG_SRCDIR(mod_authnz_fido2.c)
#AC_REVISION($Revision$)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([-Wportability])
AC_CONFIG_MACRO_DIRS([m4])

AC_PROG_CC
AC_PROG_CC_C_O
AM_PROG_LIBTOOL

AC_PATH_PROGS(PKG_CONFIG, pkg-config)
if test -z "$PKG_CONFIG"; then
    AC_MSG_ERROR([cannot locate pkg-config])
fi

if ! $PKG_CONFIG libcrypto --exists; then
    AC_MSG_ERROR([cannot locate OpenSSL Toolkit])
fi

AC_ARG_WITH(apache,
    AC_HELP_STRING([--with-apache=DIR],[use Apache in DIR]),
    [with_apache="$withval:$PATH"], [with_apache="$PATH"])
AC_PATH_PROGS([APXS], [apxs apxs2], [], [$with_apache])
if test -z "$APXS"; then
    AC_MSG_ERROR([cannot locate Apache apxs])
fi

AC_ARG_WITH(apr_config, AC_HELP_STRING([[--with-apr-config=FILE]], [Path to apr-config program]),
			[ apr_config="$withval" ],
			[AC_PATH_PROGS(apr_config,
				[apr-config apr-0-config apr-1-config], 
				[no], 
				[$PATH:/usr/sbin]
			)]
)
if test "$apr_config" = "no"; then
   AC_MSG_ERROR(Could not find the apr-config program.  You can specify a location with the --with-apr-config=FILE option.  It may be named apr-0-config or apr-1-config and can be found in your apache2 bin directory.)
fi
$apr_config --cppflags &> /dev/null
if test "$?" != "0"; then
  AC_MSG_ERROR($apr_config is not a valid apr-config program)
fi
APR_LDFLAGS="`${apr_config} --link-ld --libs`"
AC_SUBST(APR_LDFLAGS)

APACHE_CFLAGS="-I`${APXS} -q INCLUDEDIR` -I`${apr_config} --includedir`"
AC_SUBST(APACHE_CFLAGS)

CRYPTO_CFLAGS="`$PKG_CONFIG --cflags libcrypto`"
CRYPTO_LIBS="`$PKG_CONFIG --libs libcrypto`"
AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(CRYPTO_LIBS)

PKG_CHECK_MODULES([JWT], [libjwt >= 1.7])
PKG_CHECK_MODULES([FIDO], [libfido2 >= 1.2])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
