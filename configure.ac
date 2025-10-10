AC_INIT([strider], [0.4.0])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AR
LT_INIT([disable-static])

AC_ARG_WITH([kbuild], [], [kbuilddir="$withval"], [kbuilddir="/lib/modules/$(uname -r)/build"])

PKG_CHECK_MODULES([libnl_genl], [libnl-genl-3.0])
PKG_CHECK_MODULES([libxtables], [xtables])
xtlibdir="$($PKG_CONFIG --variable=xtlibdir xtables)"

AC_SUBST([kbuilddir])
AC_SUBST([xtlibdir])
AC_CONFIG_FILES([Makefile strider/Makefile striderctl/Makefile xt_strider/Makefile])
AC_OUTPUT
