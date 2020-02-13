
add_executable (dhtnode dhtnode.cpp tools_common.h)
add_executable (dhtscanner dhtscanner.cpp tools_common.h)
add_executable (dhtchat dhtchat.cpp tools_common.h)
add_executable (perftest perftest.cpp tools_common.h)

target_link_libraries (dhtnode LINK_PUBLIC ${READLINE_LIBRARIES})
target_link_libraries (dhtscanner LINK_PUBLIC ${READLINE_LIBRARIES})
target_link_libraries (dhtchat LINK_PUBLIC ${READLINE_LIBRARIES})
target_link_libraries (perftest LINK_PUBLIC ${READLINE_LIBRARIES})

if (OPENDHT_SHARED)
	target_link_libraries (dhtnode LINK_PUBLIC opendht)
	target_link_libraries (dhtscanner LINK_PUBLIC opendht)
	target_link_libraries (dhtchat LINK_PUBLIC opendht)
	target_link_libraries (perftest LINK_PUBLIC opendht)
else ()
	target_link_libraries (dhtnode LINK_PUBLIC opendht-static)
	target_link_libraries (dhtscanner LINK_PUBLIC opendht-static)
	target_link_libraries (dhtchat LINK_PUBLIC opendht-static)
	target_link_libraries (perftest LINK_PUBLIC opendht-static)
endif ()

if (OPENDHT_HTTP)
	add_executable (durl durl.cpp)
	if (OPENDHT_SHARED)
		target_link_libraries (durl LINK_PUBLIC opendht)
	else ()
		target_link_libraries (durl LINK_PUBLIC opendht-static)
	endif ()
endif()

if (OPENDHT_C)
	add_executable (dhtcnode dhtcnode.c)
	target_link_libraries (dhtcnode LINK_PUBLIC opendht-c ${READLINE_LIBRARIES})
endif ()

if (NOT DEFINED CMAKE_INSTALL_BINDIR)
    set(CMAKE_INSTALL_BINDIR bin)
endif ()

install (TARGETS dhtnode dhtscanner dhtchat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if (OPENDHT_SYSTEMD)
	execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} systemd --variable=systemdsystemunitdir
					OUTPUT_VARIABLE SYSTEMD_UNIT_INSTALL_DIR)
	string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNIT_INSTALL_DIR "${SYSTEMD_UNIT_INSTALL_DIR}")
	set (systemdunitdir "${SYSTEMD_UNIT_INSTALL_DIR}")

	configure_file (
		systemd/dhtnode.service.in
		systemd/dhtnode.service
		@ONLY
	)
	install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dhtnode.service DESTINATION ${systemdunitdir})
	install (FILES systemd/dhtnode.conf DESTINATION ${sysconfdir})
	if (OPENDHT_PYTHON)
		configure_file (
			systemd/dhtcluster.service.in
			systemd/dhtcluster.service
			@ONLY
		)
		install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dhtcluster.service DESTINATION ${systemdunitdir})
		install (FILES systemd/dhtcluster.conf DESTINATION ${sysconfdir})
	endif()
endif ()
