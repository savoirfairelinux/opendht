SUBDIRS = src
if ENABLE_TOOLS
SUBDIRS += tools
endif

ACLOCAL_AMFLAGS = -I m4

DOC_FILES = \
			README.md \
			LICENSE

EXTRA_DIST = \
			$(DOC_FILES)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = opendht.pc
