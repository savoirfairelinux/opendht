
add_executable (dhtnode dhtnode.cpp tools_common.h)
add_executable (dhtscanner dhtscanner.cpp tools_common.h)
add_executable (dhtchat dhtchat.cpp tools_common.h)

target_link_libraries (dhtnode LINK_PUBLIC readline)
target_link_libraries (dhtscanner LINK_PUBLIC readline)
target_link_libraries (dhtchat LINK_PUBLIC readline)

if (OPENDHT_SHARED)
	target_link_libraries (dhtnode LINK_PUBLIC opendht)
	target_link_libraries (dhtscanner LINK_PUBLIC opendht)
	target_link_libraries (dhtchat LINK_PUBLIC opendht)
else ()
	target_link_libraries (dhtnode LINK_PUBLIC opendht-static)
	target_link_libraries (dhtscanner LINK_PUBLIC opendht-static)
	target_link_libraries (dhtchat LINK_PUBLIC opendht-static)
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
endif ()
