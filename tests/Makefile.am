if OPENDHT_TESTS
bin_PROGRAMS = opendht_unit_tests

AM_CPPFLAGS = -I../include

opendht_unit_tests_SOURCES = tests_runner.cpp infohashtester.cpp
opendht_unit_tests_HEADERS = infohashtester.h
opendht_unit_tests_LDFLAGS = -lopendht -lcppunit  -L@top_builddir@/src/.libs @Argon2_LDFLAGS@ @GnuTLS_LIBS@
endif
