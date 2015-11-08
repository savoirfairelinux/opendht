lib_LTLIBRARIES = libopendht.la

AM_CPPFLAGS = -I../include/opendht
libopendht_la_CXXFLAGS = @CXXFLAGS@
libopendht_la_LDFLAGS = @LDFLAGS@ @GNUTLS_LIBS@ @nettle_LIBS@

libopendht_la_SOURCES = \
        dht.cpp \
        utils.cpp \
        infohash.cpp \
        value.cpp \
        crypto.cpp \
        securedht.cpp \
        dhtrunner.cpp \
        default_types.cpp

if WIN32
libopendht_la_SOURCES += rng.cpp
endif

nobase_include_HEADERS = \
        ../include/opendht.h \
        ../include/opendht/dht.h \
        ../include/opendht/utils.h \
        ../include/opendht/infohash.h \
        ../include/opendht/value.h \
        ../include/opendht/crypto.h \
        ../include/opendht/securedht.h \
        ../include/opendht/dhtrunner.h \
        ../include/opendht/default_types.h \
        ../include/opendht/rng.h
