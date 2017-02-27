bin_PROGRAMS = dhtnode dhtchat dhtscanner
noinst_HEADERS = tools_common.h

AM_CPPFLAGS = -I../include

dhtnode_SOURCES = dhtnode.cpp
dhtnode_LDFLAGS = -lopendht -lreadline -L@top_builddir@/src/.libs @Argon2_LDFLAGS@ @GnuTLS_LIBS@

dhtchat_SOURCES = dhtchat.cpp
dhtchat_LDFLAGS = -lopendht -lreadline -L@top_builddir@/src/.libs @Argon2_LDFLAGS@ @GnuTLS_LIBS@

dhtscanner_SOURCES = dhtscanner.cpp
dhtscanner_LDFLAGS = -lopendht -lreadline -L@top_builddir@/src/.libs @Argon2_LDFLAGS@ @GnuTLS_LIBS@
