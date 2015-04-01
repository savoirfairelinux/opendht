libexec_PROGRAMS = dhtnode dhtchat

AM_CPPFLAGS = -I../include

dhtnode_SOURCES = dhtnode.cpp
dhtnode_LDFLAGS = -lopendht -L../src/.libs @GNUTLS_LIBS@

dhtchat_SOURCES = dhtchat.cpp
dhtchat_LDFLAGS = -lopendht -L../src/.libs  @GNUTLS_LIBS@
