cmake_minimum_required (VERSION 2.8.6)
project (opendht)
set (opendht_VERSION_MAJOR 1)
set (opendht_VERSION_MINOR 2.1)
set (opendht_VERSION ${opendht_VERSION_MAJOR}.${opendht_VERSION_MINOR})
set (PACKAGE_VERSION ${opendht_VERSION})
set (VERSION "${opendht_VERSION}")

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix "\${prefix}")
set (libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
set (includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")

option (OPENDHT_STATIC "Build static library" ON)
option (OPENDHT_SHARED "Build shared library" ON)
option (OPENDHT_LOG "Build with logs" ON)
option (OPENDHT_PYTHON "Build Python bindings" OFF)
option (OPENDHT_TOOLS "Build DHT tools" ON)
option (OPENDHT_LTO "Build with LTO" OFF)

find_package (GnuTLS 3.3 REQUIRED)
find_package (Msgpack 1.2 REQUIRED)
if (OPENDHT_TOOLS)
    find_package (Readline 6 REQUIRED)
endif ()

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++11 -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -pedantic-errors -fvisibility=hidden")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()
if (OPENDHT_LOG)
    add_definitions(-DOPENDHT_LOG=true)
else ()
    add_definitions(-DOPENDHT_LOG=false)
endif()
if (OPENDHT_LTO)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto")
    if (CMAKE_COMPILER_IS_GNUCC)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fuse-linker-plugin")
        set (CMAKE_AR        "gcc-ar")
        set (CMAKE_NM        "gcc-nm")
        set (CMAKE_RANLIB    "gcc-ranlib")
    endif ()
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
    src/indexation/pht.cpp
    src/log.cpp
)

list (APPEND opendht_HEADERS
    include/opendht/def.h
    include/opendht/utils.h
    include/opendht/sockaddr.h
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
    include/opendht/net.h
    include/opendht/scheduler.h
    include/opendht/rate_limiter.h
    include/opendht/securedht.h
    include/opendht/log.h
    include/opendht/log_enable.h
    include/opendht.h
    include/opendht/indexation/pht.h
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
    install (TARGETS opendht-static DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT opendht)
endif ()

if (OPENDHT_SHARED)
    add_library (opendht SHARED
        ${opendht_SOURCES}
        ${opendht_HEADERS}
    )
    set_target_properties (opendht PROPERTIES IMPORT_SUFFIX "_import.lib")
    set_target_properties (opendht PROPERTIES SOVERSION ${opendht_VERSION_MAJOR} VERSION ${opendht_VERSION})
    target_compile_definitions(opendht PRIVATE OPENDHT_BUILD)
    if (OPENDHT_LTO)
        target_link_libraries(opendht -flto -fuse-linker-plugin)
    endif ()
    target_link_libraries(opendht gnutls nettle)
    install (TARGETS opendht DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT opendht)
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
install (EXPORT opendht DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/opendht FILE opendhtConfig.cmake)
