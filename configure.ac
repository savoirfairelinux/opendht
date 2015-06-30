AC_INIT(opendht, 0.1)
AC_CONFIG_AUX_DIR(ac)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Build in debug mode, adds stricter warnings, disables optimization]))
AS_IF([test "x$enable_debug" = "xyes"],
      [CXXFLAGS="${CXXFLAGS} -g -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -O0"],
      [CXXFLAGS="${CXXFLAGS} -O3"])

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AR

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
   then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])

AM_PATH_PYTHON([3.3],, [:])
AM_CONDITIONAL([HAVE_PYTHON], [test -n "$PYTHON"])

if test -n "$PYTHON"; then
  AC_CHECK_PROGS([CYTHON], [cython])
  if test -z "$CYTHON";
     then AC_MSG_WARN([Cython not found - continuing without cython support])
  fi
fi
AM_CONDITIONAL([USE_CYTHON], [test -n "$CYTHON"])

case "${host_os}" in
  "")
    SYS=unknown
    ;;
  *android*)
    SYS=android
    ;;
  linux*)
    SYS=linux
    ;;
  darwin*)
    SYS=darwin
    ;;
  mingw32*)
    SYS=mingw32
    WIN32=1
    AC_DEFINE([_POSIX_SOURCE], [1], [IEEE Std 1003.1.])
    AC_DEFINE([_POSIX_C_SOURCE], [200809L], [IEEE Std 1003.1.])
    AC_DEFINE([_XOPEN_SOURCE], [700], [POSIX and XPG 7th edition])
    AC_DEFINE([_XOPEN_SOURCE_EXTENDED], [1], [XPG things and X/Open Unix extensions.])
    AC_DEFINE([_BSD_SOURCE], [1], [ISO C, POSIX, and 4.3BSD things.])
    LDFLAGS="${LDFLAGS} -lws2_32"
    AC_SUBST(WINDOWS_ARCH)
    AC_SUBST(PROGRAMFILES)
    ;;
  *)
    SYS="${host_os}"
    ;;
esac

AM_CONDITIONAL(WIN32, [test "x$SYS" = "xmingw32"])
AS_IF([test "x$SYS" = "xandroid"],
      [], [LDFLAGS="${LDFLAGS} -lpthread"])

LT_INIT()
LT_LANG(C++)

AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

PKG_PROG_PKG_CONFIG()
PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.1])

AC_ARG_ENABLE([tools], AS_HELP_STRING([--disable-tools],[Disable tools (CLI DHT node)]),,build_tools=yes)
AM_CONDITIONAL(ENABLE_TOOLS, test x$build_tools == xyes)

AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile doc/Makefile])])
AM_COND_IF([USE_CYTHON], [AC_CONFIG_FILES([tools/python/Makefile])])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tools/Makefile
                 opendht.pc])
AC_OUTPUT
