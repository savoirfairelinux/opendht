
add_executable (dhtnode dhtnode.cpp tools_common.h)
add_executable (dhtscanner dhtscanner.cpp tools_common.h)
add_executable (dhtchat dhtchat.cpp tools_common.h)

target_link_libraries (dhtnode LINK_PUBLIC opendht gnutls)
target_link_libraries (dhtscanner LINK_PUBLIC opendht gnutls)
target_link_libraries (dhtchat LINK_PUBLIC opendht gnutls)
