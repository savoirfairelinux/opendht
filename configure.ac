dnl define macros
m4_define([opendht_major_version], 1)
m4_define([opendht_minor_version], 5)
m4_define([opendht_patch_version], 0)
m4_define([opendht_version],
		  [opendht_major_version.opendht_minor_version.opendht_patch_version])

AC_INIT(opendht, [opendht_version])
AC_CONFIG_AUX_DIR(ac)
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST

AC_SUBST(OPENDHT_MAJOR_VERSION, opendht_major_version)
AC_SUBST(OPENDHT_MINOR_VERSION, opendht_minor_version)
AC_SUBST(OPENDHT_PATCH_VERSION, opendht_patch_version)

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Build in debug mode, adds stricter warnings, disables optimization]))
AS_IF([test "x$enable_debug" = "xyes"],
      [CXXFLAGS="${CXXFLAGS} -g -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -O0 -pedantic-errors"],
      [CXXFLAGS="${CXXFLAGS} -O3 -pedantic-errors"])

AC_PROG_CXX
AM_PROG_AR

dnl Check for logs
AC_ARG_ENABLE([logs], [AS_HELP_STRING([--disable-logs], [Disble DHT logs])])
AS_IF([test "x$enable_logs" != "xno"], [
	AC_DEFINE([OPENDHT_LOG], [true], [Define if DHT logs are enabled])
], [
	AC_DEFINE([OPENDHT_LOG], [false], [Define if DHT logs are enabled])
])

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
              echo 'import Cython' | $PYTHON
              AS_IF([test $? == 0],[CYTHON=yes],[AC_MSG_WARN([Cython not found - continuing without python support])])
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
PKG_CHECK_MODULES([GnuTLS], [gnutls >= 3.3])
PKG_CHECK_MODULES([MsgPack], [msgpack >= 1.2])
CXXFLAGS="${CXXFLAGS} -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT"

dnl Check for Argon2
AC_ARG_WITH([argon2], AS_HELP_STRING([--without-argon2], [Use included Argon2]))
AS_IF([test "x$with_argon2" != "xno"],
			[PKG_CHECK_MODULES([Argon2], [libargon2], [have_argon2=yes], [have_argon2=no])],
			[have_argon2=no])
AS_IF([test "x$have_argon2" = "xyes"], [
  AC_MSG_NOTICE([Using system Argon2])
  AC_SUBST(argon2_lib, [", libargon2"])
], [
		AS_IF([test "x$with_argon2" = "xyes"], [
				AC_MSG_ERROR([Argon2 requested but not found])
		],[
				AC_MSG_NOTICE([Using included Argon2])
				AC_SUBST(Argon2_CFLAGS, "-I\${top_srcdir}/argon2/src -I\${top_srcdir}/argon2/include")
				AC_SUBST(Argon2_LIBS, "libargon2.la")
				AC_SUBST(Argon2_LDFLAGS, "-L\${abs_top_srcdir}/argon2/src/.libs")
		])
])

AM_CONDITIONAL([WITH_INCLUDED_ARGON2], [test "x$have_argon2" = "xno"])

AC_ARG_ENABLE([tools], AS_HELP_STRING([--disable-tools],[Disable tools (CLI DHT node)]),,build_tools=yes)
AM_CONDITIONAL(ENABLE_TOOLS, test x$build_tools == xyes)
AM_COND_IF([ENABLE_TOOLS], [
  AC_CHECK_HEADERS([readline/readline.h readline/history.h], [], [
    AC_MSG_ERROR([unable to find readline.h])
  ])
])

AC_ARG_ENABLE([proxy_server], AS_HELP_STRING([--enable-proxy-server], [Enable proxy server ability]), proxy_server=yes, proxy_server=no)
AM_CONDITIONAL(ENABLE_PROXY_SERVER, test x$proxy_server == xyes)
AC_ARG_ENABLE([push_notifications], AS_HELP_STRING([--enable-push-notifications], [Enable push notifications support]), push_notifications=yes, push_notifications=no)
AM_CONDITIONAL(ENABLE_PUSH_NOTIFICATIONS, test x$push_notifications == xyes)
AC_ARG_ENABLE([proxy_server_identity], AS_HELP_STRING([--enable-proxy-server-identity],
	[Enable proxy server ability]), proxy_server_identity=yes, proxy_server_identity=no)
AM_CONDITIONAL(ENABLE_PROXY_SERVER_IDENTITY, test x$proxy_server_identity == xyes)
AC_ARG_ENABLE([proxy_client], AS_HELP_STRING([--enable-proxy-client], [Enable proxy client ability]), proxy_client=yes, proxy_client=no)
AM_CONDITIONAL(ENABLE_PROXY_CLIENT, test x$proxy_client == xyes)

AM_COND_IF([ENABLE_PROXY_SERVER], [
	AC_CHECK_LIB(restbed, exit,, AC_MSG_ERROR([Missing restbed files]))
	PKG_CHECK_MODULES([Jsoncpp], [jsoncpp >= 1.7.2])
	CPPFLAGS+=" -DOPENDHT_PROXY_SERVER=true -ljsoncpp -lrestbed"
], [
	CPPFLAGS+=" -DOPENDHT_PROXY_SERVER=false"
])

AM_COND_IF([ENABLE_PUSH_NOTIFICATIONS], [
	CPPFLAGS+=" -DOPENDHT_PUSH_NOTIFICATIONS=true"
], [
	CPPFLAGS+=" -DOPENDHT_PUSH_NOTIFICATIONS=false"
])

AC_ARG_ENABLE([proxy_server_identity], AS_HELP_STRING([--enable-proxy-server-identity],
    [Enable proxy server ability]), proxy_server_identity=yes, proxy_server_identity=no)
AM_CONDITIONAL(ENABLE_PROXY_SERVER_IDENTITY, test x$proxy_server_identity == xyes -a x$proxy_server == xyes)
AM_COND_IF([ENABLE_PROXY_SERVER_IDENTITY], [
    CPPFLAGS+=" -DOPENDHT_PROXY_SERVER_IDENTITY=true"
], [
    CPPFLAGS+=" -DOPENDHT_PROXY_SERVER_IDENTITY=false"
])

AM_COND_IF([ENABLE_PROXY_CLIENT], [
	CPPFLAGS+=" -DOPENDHT_PROXY_CLIENT=true"
], [
	CPPFLAGS+=" -DOPENDHT_PROXY_CLIENT=false"
])

AM_CONDITIONAL(PROXY_CLIENT_OR_SERVER, test x$proxy_client == xyes | test x$proxy_server == xyes)
AM_COND_IF([PROXY_CLIENT_OR_SERVER], [
	AC_CHECK_LIB(restbed, exit,, AC_MSG_ERROR([Missing restbed files]))
	PKG_CHECK_MODULES([Jsoncpp], [jsoncpp >= 1.7.4])
	CPPFLAGS="${CPPFLAGS} ${Jsoncpp_CFLAGS}"
	LDFLAGS="${LDFLAGS} ${Jsoncpp_LIBS} -lrestbed"
], [])


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
                 tools/Makefile
                 opendht.pc])
AC_OUTPUT
