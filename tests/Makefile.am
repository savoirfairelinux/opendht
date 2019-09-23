if ENABLE_TESTS
bin_PROGRAMS = opendht_unit_tests

AM_CPPFLAGS = -I../include -DOPENDHT_JSONCPP

nobase_include_HEADERS = infohashtester.h valuetester.h cryptotester.h dhtrunnertester.h httptester.h dhtproxytester.h
opendht_unit_tests_SOURCES = tests_runner.cpp cryptotester.cpp infohashtester.cpp valuetester.cpp dhtrunnertester.cpp httptester.cpp dhtproxytester.cpp
opendht_unit_tests_LDFLAGS = -lopendht -lcppunit -ljsoncpp -L@top_builddir@/src/.libs @GnuTLS_LIBS@
endif
