
set(CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CURRENT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

configure_file(setup.py.in setup.py)

add_custom_target(python ALL
    COMMAND python3 setup.py build
    DEPENDS opendht opendht_cpp.pxd opendht.pyx)

install(CODE "execute_process(COMMAND python3 setup.py install --root=\$ENV{DESTDIR}/ WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})")
if (OPENDHT_TOOLS)
	install(PROGRAMS tools/dhtcluster.py DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME dhtcluster)
endif()