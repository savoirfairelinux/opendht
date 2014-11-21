lib_LTLIBRARIES = libopendht.la

AM_CPPFLAGS = -I../include/opendht
libopendht_la_CXXFLAGS = @CXXFLAGS@

libopendht_la_SOURCES = \
        dht.cpp \
        infohash.cpp \
        value.cpp \
        crypto.cpp \
        securedht.cpp \
        dhtrunner.cpp

nobase_include_HEADERS = \
        ../include/opendht.h \
        ../include/opendht/dht.h \
        ../include/opendht/infohash.h \
        ../include/opendht/value.h \
        ../include/opendht/crypto.h \
        ../include/opendht/securedht.h \
        ../include/opendht/dhtrunner.h \
        ../include/opendht/serialize.h
