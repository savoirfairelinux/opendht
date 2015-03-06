libexec_PROGRAMS = dhtnode dhtchat

AM_CPPFLAGS = -I../include
dhtnode_SOURCES = dhtnode.cpp
dhtnode_LDFLAGS = @GNUTLS_LIBS@ -lpthread -lopendht -L../src/.libs

AM_CPPFLAGS = -I../include
dhtchat_SOURCES = dhtchat.cpp
dhtchat_LDFLAGS = @GNUTLS_LIBS@ -lpthread -lopendht -L../src/.libs
