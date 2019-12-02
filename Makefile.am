AM_CXXFLAGS = -pthread

SUBDIRS =

SUBDIRS += src

if ENABLE_TOOLS
SUBDIRS += tools
endif

if USE_CYTHON
SUBDIRS += python
endif

if ENABLE_TESTS
SUBDIRS += tests
endif

SUBDIRS += doc

ACLOCAL_AMFLAGS = -I m4

DOC_FILES = \
			README.md \
			COPYING

EXTRA_DIST = \
			$(DOC_FILES)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = opendht.pc
