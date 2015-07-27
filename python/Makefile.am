if USE_CYTHON

pybuild.stamp:
	LDFLAGS="-L$(top_srcdir)/src/.libs" $(PYTHON) setup.py build_ext --inplace
	echo stamp > pybuild.stamp

CLEANFILES = pybuild.stamp

all-local: pybuild.stamp
clean-local:
	rm -rf $(builddir)/build $(builddir)/*.so

endif