AC_INIT(opendht, 0.6.1)
AC_CONFIG_AUX_DIR(ac)
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Build in debug mode, adds stricter warnings, disables optimization]))
AS_IF([test "x$enable_debug" = "xyes"],
      [CXXFLAGS="${CXXFLAGS} -g -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -O0"],
      [CXXFLAGS="${CXXFLAGS} -O3"])

AC_PROG_CXX
AM_PROG_AR

dnl Check for Doxygen
AC_ARG_ENABLE([doc], AS_HELP_STRING([--enable-doc], [Enable documentation generation (doxygen)]))
AS_IF([test "x$enable_doc" = "xyes"], [
       AC_CHECK_PROGS([DOXYGEN], [doxygen])
       AS_IF([test -z "$DOXYGEN"], [AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])])
])
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])

dnl Check for Python
AC_ARG_ENABLE([python], [AS_HELP_STRING([--disable-python], [Disble python binding])])
AS_IF([test "x$enable_python" != "xno"], [
       AM_PATH_PYTHON([3.3],, [:])
       AS_IF([test -n "$PYTHON"],[
              AC_CHECK_PROGS([CYTHON], [cython3])
              AS_IF([test -z "$CYTHON"],[AC_MSG_WARN([Cython not found - continuing without python support])])
              AC_CHECK_PROGS([PIP], [pip3])
              AS_IF([test -z "$PIP"],[AC_MSG_WARN([pip not found - continuing without python uninstall support])])
              ])
       ])
AM_CONDITIONAL([USE_CYTHON], [test -n "$CYTHON"])
AM_CONDITIONAL([HAVE_PIP], [test -n "$PIP"])

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

AX_CXX_COMPILE_STDCXX(11,[noext],[mandatory])

PKG_PROG_PKG_CONFIG()
PKG_CHECK_MODULES([Nettle], [nettle >= 2.4])
PKG_CHECK_MODULES([GnuTLS], [gnutls >= 3.1])
PKG_CHECK_MODULES([MsgPack], [msgpack >= 1.2])
CXXFLAGS="${CXXFLAGS} -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT"

AC_ARG_ENABLE([tools], AS_HELP_STRING([--disable-tools],[Disable tools (CLI DHT node)]),,build_tools=yes)
AM_CONDITIONAL(ENABLE_TOOLS, test x$build_tools == xyes)
AM_COND_IF([ENABLE_TOOLS], [
  AC_CHECK_HEADERS([readline/readline.h readline/history.h], [], [
    AC_MSG_ERROR([unable to find readline.h])
  ])
])

AC_CONFIG_FILES([doc/Doxyfile doc/Makefile])

dnl Configure setup.py if we build the python module
AM_COND_IF([USE_CYTHON], [
    AC_SUBST(CURRENT_SOURCE_DIR, ".")
    AC_SUBST(CURRENT_BINARY_DIR, ".")
    AC_SUBST(PROJECT_SOURCE_DIR, "..")
    AC_SUBST(PROJECT_BINARY_DIR, "../src/.libs")
    AC_CONFIG_FILES([python/Makefile python/setup.py])
])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/argon2/Makefile
                 tools/Makefile
                 opendht.pc])
AC_OUTPUT
