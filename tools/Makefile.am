bin_PROGRAMS = dhtnode dhtchat dhtscanner

AM_CPPFLAGS = -I../include

dhtnode_SOURCES = dhtnode.cpp
dhtnode_LDFLAGS = -lopendht -lreadline -L../src/.libs @GnuTLS_LIBS@

dhtchat_SOURCES = dhtchat.cpp
dhtchat_LDFLAGS = -lopendht -lreadline -L../src/.libs @GnuTLS_LIBS@

dhtscanner_SOURCES = dhtscanner.cpp
dhtscanner_LDFLAGS = -lopendht -lreadline -L../src/.libs @GnuTLS_LIBS@
