dist_man1_MANS = dhtnode.1

noinst_HEADERS = \
	Doxyfile

if HAVE_DOXYGEN
doxyfile.stamp: Doxyfile
	$(DOXYGEN) Doxyfile
	echo stamp > doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/doc/man $(top_srcdir)/doc/html
endif
