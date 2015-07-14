if USE_CYTHON
SUBDIRS = python
endif

libexec_PROGRAMS = dhtnode dhtchat dhtscanner

AM_CPPFLAGS = -I../include

dhtnode_SOURCES = dhtnode.cpp
dhtnode_LDFLAGS = -lopendht -L../src/.libs @GNUTLS_LIBS@

dhtchat_SOURCES = dhtchat.cpp
dhtchat_LDFLAGS = -lopendht -L../src/.libs  @GNUTLS_LIBS@

dhtscanner_SOURCES = dhtscanner.cpp
dhtscanner_LDFLAGS = -lopendht -L../src/.libs  @GNUTLS_LIBS@
