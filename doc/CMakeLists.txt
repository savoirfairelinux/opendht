if (OPENDHT_TOOLS)
	INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/dhtnode.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1)
endif ()

if (OPENDHT_DOCUMENTATION)
    if (NOT DOXYGEN_FOUND)
         message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif()
    configure_file (Doxyfile.in Doxyfile @ONLY)
    add_custom_target(doc ALL
                      COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
                      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                      COMMENT "Generating API documentation with Doxygen"
                      VERBATIM)
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc/opendht)
endif()
