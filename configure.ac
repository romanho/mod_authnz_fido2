AC_INIT(FIDO2 authentication module for Apache 2, 0.1, roman@hodek.net, mod_authnz_fido2)
AC_PREREQ(2.60)
AC_CONFIG_SRCDIR(mod_authnz_fido2.c)
AC_REVISION($Revision$)

AC_PROG_CC
AC_PROG_CC_C_O

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

CRYPTO_CFLAGS="`$PKG_CONFIG --cflags libcrypto`"
CRYPTO_LIBS="`$PKG_CONFIG --libs libcrypto`"
AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(CRYPTO_LIBS)

PKG_CHECK_MODULES([JWT], [libjwt >= 1.7])
PKG_CHECK_MODULES([JANSSON], [jansson >= 2.0])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
