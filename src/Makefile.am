lib_LTLIBRARIES = libdhtcpp.la

AM_CPPFLAGS = -I../include/dhtcpp
libdhtcpp_la_CXXFLAGS = @CXXFLAGS@

libdhtcpp_la_SOURCES = \
        dht.cpp \
        infohash.cpp \
        value.cpp \
        crypto.cpp \
        securedht.cpp \
        dhtrunner.cpp

nobase_include_HEADERS = \
        ../include/dht.h \
        ../include/dhtcpp/dht.h \
        ../include/dhtcpp/infohash.h \
        ../include/dhtcpp/value.h \
        ../include/dhtcpp/crypto.h \
        ../include/dhtcpp/securedht.h \
        ../include/dhtcpp/dhtrunner.h \
        ../include/dhtcpp/serialize.h
