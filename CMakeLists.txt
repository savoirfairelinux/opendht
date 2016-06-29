cmake_minimum_required (VERSION 2.8.6)
project (opendht)
set (opendht_VERSION_MAJOR 0)
set (opendht_VERSION_MINOR 6.1)
set (opendht_VERSION ${opendht_VERSION_MAJOR}.${opendht_VERSION_MINOR})
set (PACKAGE_VERSION ${opendht_VERSION})
set (VERSION "${opendht_VERSION}")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix "\${prefix}")
set (libdir "\${exec_prefix}/lib")
set (includedir "\${prefix}/include")

option (OPENDHT_DEBUG "Build with debug flags" OFF)
option (OPENDHT_STATIC "Build static library" ON)
option (OPENDHT_SHARED "Build shared library" ON)
option (OPENDHT_LTO "Build with LTO" OFF)

option (OPENDHT_PYTHON "Build Python bindings" OFF)
option (OPENDHT_TOOLS "Build DHT tools" ON)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++11 -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT")
if (OPENDHT_LTO)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto -fuse-linker-plugin")
    if (CMAKE_COMPILER_IS_GNUCC)
        SET (CMAKE_AR        "gcc-ar")
        SET (CMAKE_NM        "gcc-nm")
        SET (CMAKE_RANLIB    "gcc-ranlib")
    endif ()
endif ()

find_package (GnuTLS 3.1 REQUIRED)
find_package (Msgpack 1.2 REQUIRED)
if (OPENDHT_TOOLS)
    find_package (Readline 6 REQUIRED)
endif ()

list (APPEND opendht_SOURCES
    src/utils.cpp
    src/infohash.cpp
    src/crypto.cpp
    src/default_types.cpp
    src/node.cpp
    src/value.cpp
    src/dht.cpp
    src/callbacks.cpp
    src/routing_table.cpp
    src/node_cache.cpp
    src/network_engine.cpp
    src/securedht.cpp
    src/dhtrunner.cpp
    src/argon2/argon2.c
    src/argon2/core.c
    src/argon2/blake2/blake2b.c
    src/argon2/thread.c
    src/argon2/encoding.c
    src/argon2/ref.c
)

list (APPEND opendht_HEADERS
    include/opendht/utils.h
    include/opendht/rng.h
    include/opendht/crypto.h
    include/opendht/infohash.h
    include/opendht/default_types.h
    include/opendht/node.h
    include/opendht/value.h
    include/opendht/dht.h
    include/opendht/callbacks.h
    include/opendht/routing_table.h
    include/opendht/node_cache.h
    include/opendht/network_engine.h
    include/opendht/scheduler.h
    include/opendht/securedht.h
    include/opendht/log.h
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

if (NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR lib)
endif ()

if (OPENDHT_STATIC)
    add_library (opendht-static STATIC
        ${opendht_SOURCES}
        ${opendht_HEADERS}
    )
    set_target_properties (opendht-static PROPERTIES OUTPUT_NAME "opendht")
    if (OPENDHT_LTO)
        target_link_libraries(opendht-static -flto -fuse-linker-plugin)
    endif ()
    target_link_libraries(opendht-static gnutls nettle)
    install (TARGETS opendht-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

if (OPENDHT_SHARED)
    add_library (opendht SHARED
        ${opendht_SOURCES}
        ${opendht_HEADERS}
    )
    set_target_properties (opendht PROPERTIES IMPORT_SUFFIX "_import.lib")
    set_target_properties (opendht PROPERTIES SOVERSION ${opendht_VERSION_MAJOR} VERSION ${opendht_VERSION})
    if (OPENDHT_LTO)
        target_link_libraries(opendht -flto -fuse-linker-plugin)
    endif ()
    target_link_libraries(opendht gnutls nettle)
    install (TARGETS opendht DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

if (OPENDHT_TOOLS)
    add_subdirectory(tools)
endif ()
add_subdirectory(doc)

if (OPENDHT_PYTHON)
    add_subdirectory(python)
endif ()

install (DIRECTORY include DESTINATION ${CMAKE_INSTALL_PREFIX})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendht.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
