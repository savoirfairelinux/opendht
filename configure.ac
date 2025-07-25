dnl define macros
m4_define([opendht_major_version], 3)
m4_define([opendht_minor_version], 4)
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
      [CXXFLAGS="${CXXFLAGS} -g -Og -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -Wno-deprecated -pedantic-errors"],
      [CXXFLAGS="${CXXFLAGS} -O3 -Wno-deprecated -pedantic-errors -fvisibility=hidden"])

CPPFLAGS="${CPPFLAGS} -DOPENDHT_BUILD"
AM_CONDITIONAL([OPENDHT_SHARED], [test "x$enable_shared" != xno])
AM_COND_IF(OPENDHT_SHARED, [
  CPPFLAGS="${CPPFLAGS} -Dopendht_EXPORTS"
])

AM_PROG_AR
LT_INIT()
LT_LANG(C++)
AC_LANG(C++)
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX(17,[noext],[mandatory])

dnl Check for C binding
AC_ARG_ENABLE([c], [AS_HELP_STRING([--disable-c], [Disable DHT C binding])])
AM_CONDITIONAL(ENABLE_C, test x$enable_c != "xno")
AM_COND_IF(ENABLE_C, [
	AC_DEFINE([OPENDHT_C], [], [Define if DHT C biding is enabled])
])

dnl Check for indexation
AC_ARG_ENABLE([indexation], [AS_HELP_STRING([--disable-indexation], [Disable DHT indexation])])
AM_CONDITIONAL(ENABLE_INDEXATION, test x$enable_indexation != "xno")
AM_COND_IF(ENABLE_INDEXATION, [
	AC_DEFINE([OPENDHT_INDEXATION], [], [Define if DHT indexation is enabled])
])

AC_ARG_ENABLE([peer-discovery], [AS_HELP_STRING([--disable-peer-discovery], [Disable peer-discovery])])
AM_CONDITIONAL(ENABLE_PEER_DISCOVERY, test x$enable_peer_discovery != "xno")
AM_COND_IF(ENABLE_PEER_DISCOVERY, [AC_DEFINE([OPENDHT_PEER_DISCOVERY], [], [Define if peer discovery is enabled])])

dnl Check for Doxygen
AC_ARG_ENABLE([doc], AS_HELP_STRING([--enable-doc], [Enable documentation generation (doxygen)]))
AS_IF([test "x$enable_doc" = "xyes"], [
       AC_CHECK_PROGS([DOXYGEN], [doxygen])
       AS_IF([test -z "$DOXYGEN"],
          [AC_MSG_ERROR([Doxygen is required to generate the documentation.])])
])
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])

dnl Check for Python
AC_ARG_ENABLE([python], [AS_HELP_STRING([--disable-python], [Disable python binding])])
AS_IF([test "x$enable_python" = "xyes"], [
  AM_COND_IF([ENABLE_INDEXATION], [
    AM_PATH_PYTHON([3.3],, [:])
    AS_IF([test -n "$PYTHON"],[
      echo 'import Cython' | $PYTHON
      AS_IF([test $? == 0],
        [CYTHON=yes],
        [AC_MSG_ERROR([Cython not found, but required for Python support.])])
      AC_CHECK_PROGS([PIP], [pip3])
        AS_IF([test -z "$PIP"],
        [AC_MSG_WARN([pip not found - continuing without python uninstall support])])])
     ], [AC_MSG_ERROR([Python support requires DHT indexation to be turned on.])])])
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
    CPPFLAGS="$CPPFLAGS -D_POSIX_C_SOURCE=200809L"
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

PKG_PROG_PKG_CONFIG()

AC_ARG_ENABLE([proxy_server], AS_HELP_STRING([--enable-proxy-server], [Enable proxy server ability]), proxy_server=yes, proxy_server=no)
AM_CONDITIONAL(ENABLE_PROXY_SERVER, test x$proxy_server == xyes)

AC_ARG_ENABLE([push_notifications], AS_HELP_STRING([--enable-push-notifications], [Enable push notifications support]), push_notifications=yes, push_notifications=no)
AM_CONDITIONAL(ENABLE_PUSH_NOTIFICATIONS, test x$push_notifications == xyes)

AC_ARG_ENABLE([proxy_server_identity], AS_HELP_STRING([--enable-proxy-server-identity],
	[Enable proxy server ability]), proxy_server_identity=yes, proxy_server_identity=no)
AM_CONDITIONAL(ENABLE_PROXY_SERVER_IDENTITY, test x$proxy_server_identity == xyes -a x$proxy_server == xyes)
AC_ARG_ENABLE([proxy_server_identity], AS_HELP_STRING([--enable-proxy-server-identity],
	[Enable proxy server ability]), proxy_server_identity=yes, proxy_server_identity=no)

AC_ARG_ENABLE([proxy_client], AS_HELP_STRING([--enable-proxy-client], [Enable proxy client ability]), proxy_client=yes, proxy_client=no)
AM_CONDITIONAL(ENABLE_PROXY_CLIENT, test x$proxy_client == xyes)

AC_ARG_ENABLE([tests], AS_HELP_STRING([--enable-tests], [Enable tests]), build_tests=yes, build_tests=no)
AM_CONDITIONAL(ENABLE_TESTS, test "x$build_tests" == xyes)
AS_IF([test "x$build_tests" == xyes], [
	PKG_CHECK_MODULES([CppUnit], [cppunit >= 1.12])
])

AM_CONDITIONAL(PROXY_CLIENT_OR_SERVER, test x$proxy_client == xyes || test x$proxy_server == xyes)

PKG_CHECK_MODULES([Nettle], [nettle >= 2.4])
PKG_CHECK_MODULES([GnuTLS], [gnutls >= 3.3])
AC_CHECK_HEADERS([msgpack.hpp], [], [
  PKG_CHECK_MODULES([MsgPack], [msgpack >= 1.2])
])
PKG_CHECK_MODULES([Argon2], [libargon2])
AC_SUBST(argon2_lib, [", libargon2"])

AC_ARG_WITH([jsoncpp], AS_HELP_STRING([--without-jsoncpp], [Build without JsonCpp support]))
AS_IF([test "x$with_jsoncpp" != "xno"],
      [PKG_CHECK_MODULES([JsonCpp], [jsoncpp >= 1.7.2], [have_jsoncpp=yes], [have_jsoncpp=no])],
      [have_jsoncpp=no])
AS_IF([test "x$have_jsoncpp" = "xyes"], [
    AC_MSG_NOTICE([Using JsonCpp])
    CPPFLAGS="${CPPFLAGS} -DOPENDHT_JSONCPP"
    AC_SUBST(jsoncpp_lib, [", jsoncpp"])
], [
    AC_MSG_NOTICE([Not using JsonCpp])
    AM_COND_IF(PROXY_CLIENT_OR_SERVER, AC_MSG_ERROR(["JsonCpp is required for proxy/push notification support"]))
])

AC_ARG_WITH([openssl], AS_HELP_STRING([--without-openssl], [Build without OpenSSL support]))
AS_IF([test "x$with_openssl" != "xno"],
      [PKG_CHECK_MODULES([OpenSSL], [openssl >= 1.1], [have_openssl=yes], [have_openssl=no])],
      [have_openssl=no])
AS_IF([test "x$have_openssl" = "xyes"], [
    AC_MSG_NOTICE([Using OpenSSL])
    AC_SUBST(openssl_lib, [", openssl"])
], [
    AC_MSG_NOTICE([Not using OpenSSL])
])

PKG_CHECK_MODULES([Fmt], [fmt >= 5.3.0], [have_fmt=yes], [have_fmt=no])
AS_IF([test "x$have_fmt" = "xyes"], [
    AC_MSG_NOTICE([Using libfmt])
], [
    AC_MSG_NOTICE([Missing libfmt files])
])

AM_COND_IF([PROXY_CLIENT_OR_SERVER], [
    AC_CHECK_HEADERS([asio.hpp],, AC_MSG_ERROR([Missing Asio headers files]))
    CXXFLAGS="${CXXFLAGS} -DASIO_STANDALONE"
    # llhttp has no pkgconfig, instead we check with:
    AC_CHECK_LIB(llhttp, exit,, AC_MSG_ERROR([Missing llhttp library files]))
    AC_CHECK_HEADERS([llhttp.h], [llhttp_headers=yes; break;])
    AC_SUBST(http_lib, ["-lllhttp"])
    AS_IF([test "x$llhttp_headers" != "xyes"], AC_MSG_ERROR([Missing llhttp headers files]))
])

CXXFLAGS="${CXXFLAGS} -DMSGPACK_NO_BOOST -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT"

AC_ARG_ENABLE([tools], AS_HELP_STRING([--disable-tools],[Disable tools (CLI DHT node)]),,build_tools=yes)
AM_CONDITIONAL(ENABLE_TOOLS, test x$build_tools == xyes)
AM_COND_IF([ENABLE_TOOLS], [
  AC_CHECK_HEADERS([readline/readline.h readline/history.h], [],
    [AC_MSG_ERROR([Unable to find readline.h. Readline is required for the tools.])
  ])
])

AM_COND_IF(ENABLE_PROXY_SERVER, AC_DEFINE([OPENDHT_PROXY_SERVER], [], [Building with proxy server]))
AM_COND_IF(ENABLE_PROXY_CLIENT, AC_DEFINE([OPENDHT_PROXY_CLIENT], [], [Building with proxy client]))
AM_COND_IF(ENABLE_PUSH_NOTIFICATIONS, [CPPFLAGS="${CPPFLAGS} -DOPENDHT_PUSH_NOTIFICATIONS"], [])
AM_COND_IF(ENABLE_PROXY_SERVER_IDENTITY, [CPPFLAGS="${CPPFLAGS} -DOPENDHT_PROXY_SERVER_IDENTITY"], [])

dnl Configure setup.py if we build the python module
AC_SUBST(CURRENT_SOURCE_DIR, ".")
AC_SUBST(CURRENT_BINARY_DIR, ".")
AC_SUBST(PROJECT_SOURCE_DIR, "..")
AC_SUBST(PROJECT_BINARY_DIR, "../src/.libs")

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 c/Makefile
                 tools/Makefile
                 python/Makefile
                 python/setup.py
                 tests/Makefile
                 doc/Makefile
                 doc/Doxyfile
                 opendht.pc])
AC_OUTPUT
