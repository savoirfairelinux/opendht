bin_PROGRAMS = dhtnode dhtchat dhtscanner
noinst_HEADERS = tools_common.h

AM_CPPFLAGS = -isystem @top_srcdir@/include @JsonCpp_CFLAGS@ @MsgPack_CFLAGS@

dhtnode_SOURCES = dhtnode.cpp
dhtnode_LDFLAGS = -lopendht -lreadline -L@top_builddir@/src/.libs @GnuTLS_LIBS@

dhtchat_SOURCES = dhtchat.cpp
dhtchat_LDFLAGS = -lopendht -lreadline -L@top_builddir@/src/.libs @GnuTLS_LIBS@

dhtscanner_SOURCES = dhtscanner.cpp
dhtscanner_LDFLAGS = -lopendht -lreadline -L@top_builddir@/src/.libs @GnuTLS_LIBS@

if ENABLE_C
bin_PROGRAMS += dhtcnode
dhtcnode_CFLAGS = -isystem @top_srcdir@/c -isystem @top_srcdir@/include
dhtcnode_SOURCES = dhtcnode.c
dhtcnode_LDFLAGS = -lopendht-c -L@top_builddir@/c/.libs
endif
