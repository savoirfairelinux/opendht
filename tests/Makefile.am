if ENABLE_TESTS
bin_PROGRAMS = opendht_unit_tests

AM_CPPFLAGS = -I../include

nobase_include_HEADERS = infohashtester.h
opendht_unit_tests_SOURCES = tests_runner.cpp infohashtester.cpp
opendht_unit_tests_LDFLAGS = -lopendht -lcppunit -L@top_builddir@/src/.libs @GnuTLS_LIBS@
endif
