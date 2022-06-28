lib_LTLIBRARIES = libopendht-c.la
noinst_HEADERS = opendht_c.h

AM_CPPFLAGS = -DOPENDHT_C_BUILD -isystem @top_srcdir@/include @JsonCpp_CFLAGS@ @MsgPack_CFLAGS@
if OPENDHT_SHARED
AM_CPPFLAGS += -Dopendht_c_EXPORTS
endif

libopendht_c_la_LIBADD = $(LIBOBJS) ../src/.libs/libopendht.la

libopendht_c_la_SOURCES  = \
        opendht.cpp

nobase_include_HEADERS = \
        opendht_c.h
