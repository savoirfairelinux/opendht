doxyfile.stamp:
	$(DOXYGEN) Doxyfile
	echo stamp > doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/doc/man $(top_srcdir)/doc/html
