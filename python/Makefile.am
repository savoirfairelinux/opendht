if USE_CYTHON

noinst_HEADERS = \
	opendht.pyx \
	opendht_cpp.pxd

PYTHON_INSTALL_RECORD = $(builddir)/install_record.txt

pybuild.stamp:
	LDFLAGS="-L$(top_srcdir)/src/.libs" $(PYTHON) setup.py build_ext --inplace
	echo stamp > pybuild.stamp

CLEANFILES = pybuild.stamp

all-local: pybuild.stamp
clean-local:
	rm -rf $(builddir)/build $(builddir)/*.so $(PYTHON_INSTALL_RECORD)

install-exec-local:
	$(PYTHON) setup.py install --root=$(DESTDIR)/ --record $(PYTHON_INSTALL_RECORD)
	rm -rf $(builddir)/build

if HAVE_PIP
uninstall-local:
	/usr/bin/yes | $(PIP) uninstall $(PACKAGE)
endif

endif

