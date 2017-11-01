cmake_minimum_required (VERSION 3.1)
project (opendht)
set (opendht_VERSION_MAJOR 1)
set (opendht_VERSION_MINOR 4.1)
set (opendht_VERSION ${opendht_VERSION_MAJOR}.${opendht_VERSION_MINOR})
set (PACKAGE_VERSION ${opendht_VERSION})
set (VERSION "${opendht_VERSION}")

# Options
option (OPENDHT_STATIC "Build static library" ON)
option (OPENDHT_SHARED "Build shared library" ON)
option (OPENDHT_LOG "Build with logs" ON)
option (OPENDHT_PYTHON "Build Python bindings" OFF)
option (OPENDHT_TOOLS "Build DHT tools" ON)
option (OPENDHT_SYSTEMD "Install systemd module" OFF)
option (OPENDHT_ARGON2 "Use included argon2 sources" OFF)
option (OPENDHT_LTO "Build with LTO" OFF)
option (OPENDHT_SANITIZE "Build with address sanitizer and stack protector" OFF)
option (OPENDHT_PROXY_SERVER "Enable DHT proxy server, use Restbed and jsoncpp" OFF)
option (OPENDHT_PROXY_SERVER_OPTIONAL "Enable sign and encrypt endpoints" OFF)
option (OPENDHT_PROXY_CLIENT "Enable DHT proxy client, use Restbed and jsoncpp" OFF)

find_package(Doxygen)
option (OPENDHT_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})

# Dependencies
list (APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package (Threads)
find_package (PkgConfig)
find_package (GnuTLS 3.3 REQUIRED)
pkg_search_module (Nettle nettle)
find_package (Msgpack 1.2 REQUIRED)
if (OPENDHT_TOOLS)
    find_package (Readline 6 REQUIRED)
endif ()
if (NOT OPENDHT_ARGON2)
    find_package(PkgConfig)
    pkg_search_module(argon2 libargon2)
    if (argon2_FOUND)
        message("Argon2 found " ${argon2_req})
        set(argon2_lib ", libargon2")
    else ()
        message("Argon2 not found, using included version.")
        set(OPENDHT_ARGON2 ON)
    endif()
endif ()
if (OPENDHT_PROXY_SERVER OR OPENDHT_PROXY_CLIENT)
    find_package(Restbed REQUIRED)
    find_package(Jsoncpp REQUIRED)
endif()

# Build flags
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED on)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -pedantic-errors -fvisibility=hidden")
if (OPENDHT_SANITIZE)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fstack-protector-strong")
endif ()
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

if (MSGPACK_INCLUDE_DIRS)
    include_directories (SYSTEM "${MSGPACK_INCLUDE_DIRS}")
endif ()
if (GNUTLS_INCLUDE_DIRS)
    include_directories (SYSTEM "${GNUTLS_INCLUDE_DIRS}")
endif ()
if (Nettle_INCLUDE_DIRS)
    include_directories (SYSTEM "${Nettle_INCLUDE_DIRS}")
endif ()
if (Restbed_INCLUDE_DIRS)
    include_directories (SYSTEM "${Restbed_INCLUDE_DIRS}")
endif ()
if (Jsoncpp_INCLUDE_DIRS)
    include_directories (SYSTEM "${Jsoncpp_INCLUDE_DIRS}")
endif ()
link_directories (${Nettle_LIBRARY_DIRS})
include_directories (
    ./
    include/
    include/opendht/
    ${CMAKE_CURRENT_BINARY_DIR}/include/
    /usr/include/jsoncpp
)

# Install dirs
include (GNUInstallDirs)
set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix "\${prefix}")
set (libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
set (includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set (bindir "${CMAKE_INSTALL_FULL_BINDIR}")
set (sysconfdir "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
set (top_srcdir "${CMAKE_CURRENT_SOURCE_DIR}")

# Sources
list (APPEND opendht_SOURCES
    src/utils.cpp
    src/infohash.cpp
    src/crypto.cpp
    src/default_types.cpp
    src/node.cpp
    src/value.cpp
    src/dht.cpp
    src/storage.h
    src/listener.h
    src/search.h
    src/net.h
    src/parsed_message.h
    src/request.h
    src/callbacks.cpp
    src/routing_table.cpp
    src/node_cache.cpp
    src/network_engine.cpp
    src/securedht.cpp
    src/dhtrunner.cpp
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
    include/opendht/scheduler.h
    include/opendht/rate_limiter.h
    include/opendht/securedht.h
    include/opendht/log.h
    include/opendht/log_enable.h
    include/opendht.h
    include/opendht/indexation/pht.h
)

if (OPENDHT_PROXY_SERVER)
  add_definitions(-DOPENDHT_PROXY_SERVER=true)
  if (OPENDHT_PROXY_SERVER_OPTIONAL)
    add_definitions(-DOPENDHT_PROXY_SERVER_OPTIONAL=true)
  else ()
    add_definitions(-DOPENDHT_PROXY_SERVER_OPTIONAL=false)
  endif()
  list (APPEND opendht_HEADERS
    include/opendht/dhtproxyserver.h
    include/opendht/base64.h
  )
  list (APPEND opendht_SOURCES
    src/dhtproxyserver.cpp
    src/base64.cpp
  )
else ()
    add_definitions(-DENABLE_PROXY_SERVER=false)
endif ()

if(OPENDHT_ARGON2)
    # make sure argon2 submodule is up to date and initialized
    message("Initializing Argon2 submodule")
    execute_process(COMMAND git submodule update --init)

    # add local argon2 files to build
    list (APPEND opendht_SOURCES
        argon2/src/argon2.c
        argon2/src/core.c
        argon2/src/blake2/blake2b.c
        argon2/src/thread.c
        argon2/src/ref.c
        argon2/src/encoding.c
    )
    include_directories(argon2/include/)
endif()

# Targets
if (OPENDHT_STATIC)
    add_library (opendht-static STATIC
        ${opendht_SOURCES}
        ${opendht_HEADERS}
    )
    set_target_properties (opendht-static PROPERTIES OUTPUT_NAME "opendht")
    if (OPENDHT_LTO)
        target_link_libraries(opendht-static -flto -fuse-linker-plugin)
    endif ()
    if (OPENDHT_ARGON2)
        target_include_directories(opendht-static SYSTEM PRIVATE argon2)
    else ()
        target_link_libraries(opendht-static ${argon2_LIBRARIES})
        target_include_directories(opendht-static SYSTEM PRIVATE ${argon2_INCLUDE_DIRS})
    endif ()
    target_link_libraries(opendht-static ${CMAKE_THREAD_LIBS_INIT} ${GNUTLS_LIBRARIES} ${Nettle_LIBRARIES} ${Restbed_LIBRARIES} ${Jsoncpp_LIBRARIES})
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
        target_link_libraries(opendht PRIVATE -flto -fuse-linker-plugin)
    endif ()
    if (OPENDHT_ARGON2)
        target_include_directories(opendht SYSTEM PRIVATE argon2)
    else ()
        target_link_libraries(opendht PRIVATE ${argon2_LIBRARIES})
        target_include_directories(opendht SYSTEM PRIVATE ${argon2_INCLUDE_DIRS})
    endif ()
    target_link_libraries(opendht PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${GNUTLS_LIBRARIES} ${Nettle_LIBRARIES} ${Restbed_LIBRARIES} ${Jsoncpp_LIBRARIES})
    install (TARGETS opendht DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT opendht)
endif ()

if (OPENDHT_TOOLS)
    add_subdirectory(tools)
endif ()
add_subdirectory(doc)

if (OPENDHT_PYTHON)
    add_subdirectory(python)
endif ()

# CMake module
include(CMakePackageConfigHelpers)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/opendhtConfigVersion.cmake"
  VERSION ${opendht_VERSION}
  COMPATIBILITY AnyNewerVersion
)
# PkgConfig module
configure_file (
    opendht.pc.in
    opendht.pc
    @ONLY
)

# Install targets
install (DIRECTORY include DESTINATION ${CMAKE_INSTALL_PREFIX})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendht.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install (EXPORT opendht DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/opendht FILE opendhtConfig.cmake)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendhtConfigVersion.cmake DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/opendht)
