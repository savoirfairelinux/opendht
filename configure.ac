AC_INIT(opendht, 0.1)
AC_CONFIG_AUX_DIR(ac)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Build in debug mode, adds stricter warnings, disables optimization]))
AS_IF([test "x$enable_debug" = "xyes"],
      [CXXFLAGS="${CXXFLAGS} -g -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -O0"],
      [CXXFLAGS="${CXXFLAGS} -O3 -flto"])

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AR

LT_INIT()
LT_LANG(C++)

AX_CXX_COMPILE_STDCXX_11([noext],[mandatory])

PKG_PROG_PKG_CONFIG()
PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.1])

AC_ARG_ENABLE([tools], AS_HELP_STRING([--disable-tools],[Disable tools (CLI DHT node)]),,build_tools=yes)
AM_CONDITIONAL(ENABLE_TOOLS, test x$build_tools == xyes)

AC_CONFIG_FILES([Makefile src/Makefile tools/Makefile opendht.pc])
AC_OUTPUT
