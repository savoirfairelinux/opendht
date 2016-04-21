
add_executable (dhtnode dhtnode.cpp tools_common.h)
add_executable (dhtscanner dhtscanner.cpp tools_common.h)
add_executable (dhtchat dhtchat.cpp tools_common.h)

target_link_libraries (dhtnode LINK_PUBLIC gnutls readline)
target_link_libraries (dhtscanner LINK_PUBLIC gnutls readline)
target_link_libraries (dhtchat LINK_PUBLIC gnutls readline)

if (OPENDHT_SHARED)
	target_link_libraries (dhtnode LINK_PUBLIC opendht)
	target_link_libraries (dhtscanner LINK_PUBLIC opendht)
	target_link_libraries (dhtchat LINK_PUBLIC opendht)
else ()
	target_link_libraries (dhtnode LINK_PUBLIC opendht-static)
	target_link_libraries (dhtscanner LINK_PUBLIC opendht-static)
	target_link_libraries (dhtchat LINK_PUBLIC opendht-static)
endif ()

if (NOT DEFINED CMAKE_INSTALL_BINDIR)
    set(CMAKE_INSTALL_BINDIR bin)
endif ()

install (TARGETS dhtnode dhtscanner dhtchat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
