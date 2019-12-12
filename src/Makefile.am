lib_LTLIBRARIES = libopendht.la

libopendht_la_CPPFLAGS = @CPPFLAGS@ -I$(top_srcdir)/include/opendht @Argon2_CFLAGS@ @JsonCpp_CFLAGS@ @MsgPack_CFLAGS@ @OpenSSL_CFLAGS@ @Fmt_CFLAGS@
libopendht_la_LIBADD   = @Argon2_LIBS@ @JsonCpp_LIBS@ @GnuTLS_LIBS@ @Nettle_LIBS@ @OpenSSL_LIBS@ @Fmt_LIBS@
libopendht_la_LDFLAGS  = @LDFLAGS@ @Argon2_LDFLAGS@ -version-number @OPENDHT_MAJOR_VERSION@:@OPENDHT_MINOR_VERSION@:@OPENDHT_PATCH_VERSION@
libopendht_la_SOURCES  = \
        dht.cpp \
        storage.h \
        listener.h \
        request.h \
        search.h \
        value_cache.h \
        op_cache.h \
        op_cache.cpp \
        net.h \
        parsed_message.h \
        node_cache.cpp \
        callbacks.cpp \
        routing_table.cpp \
        network_engine.cpp \
        utils.cpp \
        infohash.cpp \
        node.cpp \
        value.cpp \
        crypto.cpp \
        securedht.cpp \
        dhtrunner.cpp \
        default_types.cpp \
        log.cpp \
        network_utils.cpp \
        thread_pool.cpp

if WIN32
libopendht_la_SOURCES += rng.cpp
endif

nobase_include_HEADERS = \
        ../include/opendht.h \
        ../include/opendht/def.h \
        ../include/opendht/dht.h \
        ../include/opendht/callbacks.h \
        ../include/opendht/node_cache.h \
        ../include/opendht/routing_table.h \
        ../include/opendht/network_engine.h \
        ../include/opendht/scheduler.h \
        ../include/opendht/rate_limiter.h \
        ../include/opendht/utils.h \
        ../include/opendht/sockaddr.h \
        ../include/opendht/infohash.h \
        ../include/opendht/node.h \
        ../include/opendht/value.h \
        ../include/opendht/crypto.h \
        ../include/opendht/securedht.h \
        ../include/opendht/dhtrunner.h \
        ../include/opendht/default_types.h \
        ../include/opendht/log.h \
        ../include/opendht/log_enable.h \
        ../include/opendht/network_utils.h \
        ../include/opendht/rng.h \
        ../include/opendht/thread_pool.h

if ENABLE_PROXY_SERVER
libopendht_la_SOURCES += dht_proxy_server.cpp
nobase_include_HEADERS += ../include/opendht/dht_proxy_server.h
endif

if ENABLE_PROXY_CLIENT
libopendht_la_SOURCES += dht_proxy_client.cpp
nobase_include_HEADERS += ../include/opendht/dht_proxy_client.h ../include/opendht/dht_interface.h
endif

libopendht_la_SOURCES += base64.h base64.cpp
if PROXY_CLIENT_OR_SERVER
libopendht_la_SOURCES += http.cpp
nobase_include_HEADERS += ../include/opendht/proxy.h ../include/opendht/http.h
endif

if ENABLE_PEER_DISCOVERY
libopendht_la_SOURCES += peer_discovery.cpp
nobase_include_HEADERS += ../include/opendht/peer_discovery.h
endif

if ENABLE_INDEXATION
libopendht_la_SOURCES += indexation/pht.cpp
nobase_include_HEADERS += ../include/opendht/indexation/pht.h
endif

clean-local:
	rm -rf libargon2.la

######################
#  ARGON2 submodule  #
######################

if WITH_INCLUDED_ARGON2
noinst_LTLIBRARIES         = libargon2.la
libopendht_la_DEPENDENCIES = libargon2.la

libargon2_la_CFLAGS  = -std=c89 -fPIC -pthread -O3 -Wall -I@top_builddir@/argon2/include -I@top_builddir@/argon2/src
libargon2_la_SOURCES = \
        @top_builddir@/argon2/src/argon2.c \
        @top_builddir@/argon2/src/core.c \
        @top_builddir@/argon2/src/blake2/blake2b.c \
        @top_builddir@/argon2/src/thread.c \
        @top_builddir@/argon2/src/ref.c \
        @top_builddir@/argon2/src/encoding.c

noinst_HEADERS = \
        @top_builddir@/argon2/include/argon2.h \
        @top_builddir@/argon2/src/blake2/blake2.h \
        @top_builddir@/argon2/src/blake2/blake2-impl.h \
        @top_builddir@/argon2/src/blake2/blamka-round-ref.h \
        @top_builddir@/argon2/src/core.h \
        @top_builddir@/argon2/src/encoding.h \
        @top_builddir@/argon2/src/thread.h
endif
