cmake_minimum_required (VERSION 2.8.6)
project (opendht)
set (opendht_VERSION_MAJOR 0)
set (opendht_VERSION_MINOR 1)
set (opendht_VERSION ${opendht_VERSION_MAJOR}.${opendht_VERSION_MINOR})
set (PACKAGE_VERSION ${opendht_VERSION})

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix "\${prefix}")
set (libdir "\${exec_prefix}/lib")
set (includedir "\${prefix}/include")

option (OPENDHT_PYTHON "Build Python bindings" OFF)
option (OPENDHT_TOOLS "Build DHT tools" ON)
option (OPENDHT_DEBUG "Build with debug flags" OFF)

set (CMAKE_CXX_FLAGS "-std=c++11 -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor ${CMAKE_CXX_FLAGS}")

find_package (GnuTLS 3.1 REQUIRED)
find_package (Msgpack 1.1 REQUIRED)
if (OPENDHT_TOOLS)
	find_package (Readline 6 REQUIRED)
endif ()

list (APPEND opendht_SOURCES
	src/infohash.cpp
	src/crypto.cpp
	src/default_types.cpp
	src/value.cpp
	src/dht.cpp
	src/securedht.cpp
	src/dhtrunner.cpp
)

list (APPEND opendht_HEADERS
	include/opendht/rng.h
	include/opendht/crypto.h
	include/opendht/infohash.h
	include/opendht/default_types.h
	include/opendht/value.h
	include/opendht/dht.h
	include/opendht/securedht.h
	include/opendht.h
)

configure_file (
	opendht.pc.in
	opendht.pc
	@ONLY
)

include_directories (
	./
	include/
	include/opendht/
	${CMAKE_CURRENT_BINARY_DIR}/include/
)

if (OPENDHT_DEBUG)
	set(CMAKE_BUILD_TYPE Debug)
else ()
	set(CMAKE_BUILD_TYPE Release)
endif ()

add_library (opendht SHARED
	${opendht_SOURCES}
	${opendht_HEADERS}
)
set_target_properties (opendht PROPERTIES IMPORT_SUFFIX "_import.lib")
#set_target_properties (opendht PROPERTIES SOVERSION 1 VERSION 1.0.0)

add_library (opendht-static STATIC
	${opendht_SOURCES}
	${opendht_HEADERS}
)
set_target_properties (opendht-static PROPERTIES OUTPUT_NAME "opendht")

if (NOT DEFINED CMAKE_INSTALL_LIBDIR)
	set(CMAKE_INSTALL_LIBDIR lib)
endif ()

if (OPENDHT_TOOLS)
	add_subdirectory(tools)
endif ()

if (OPENDHT_PYTHON)
	add_subdirectory(python)
endif ()

install (TARGETS opendht opendht-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (DIRECTORY include DESTINATION ${CMAKE_INSTALL_PREFIX})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendht.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
