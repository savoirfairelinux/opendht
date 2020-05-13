cmake_minimum_required (VERSION 3.1)
include(CMakePackageConfigHelpers)
include(CMakeDependentOption)

project (opendht)
set (opendht_VERSION_MAJOR 2)
set (opendht_VERSION_MINOR 1.0)
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
option (OPENDHT_PROXY_SERVER "Enable DHT proxy server, use Restinio and jsoncpp" OFF)
option (OPENDHT_PUSH_NOTIFICATIONS "Enable push notifications support" OFF)
option (OPENDHT_PROXY_SERVER_IDENTITY "Allow clients to use the node identity" OFF)
option (OPENDHT_PROXY_CLIENT "Enable DHT proxy client, use Restinio and jsoncpp" OFF)
option (OPENDHT_PROXY_OPENSSL "Build DHT proxy with OpenSSL" ON)
option (OPENDHT_PROXY_HTTP_PARSER_FORK "Build DHT proxy with custom http_parser to support old API" OFF)
CMAKE_DEPENDENT_OPTION(OPENDHT_HTTP "Build embedded http(s) client" OFF "NOT OPENDHT_PROXY_SERVER;NOT OPENDHT_PROXY_CLIENT" ON)
option (OPENDHT_PEER_DISCOVERY "Enable multicast peer discovery" ON)
option (OPENDHT_INDEX "Build DHT indexation feature" OFF)
option (OPENDHT_TESTS "Add unit tests executable" OFF)
option (OPENDHT_C "Build C bindings" OFF)

find_package(Doxygen)
option (OPENDHT_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})

# Dependencies
list (APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package (Threads)
find_package (PkgConfig REQUIRED)
find_package (GnuTLS 3.3 REQUIRED)
pkg_search_module (Nettle nettle)
find_package (Msgpack 1.2 REQUIRED)
if (OPENDHT_TOOLS)
    find_package (Readline 6 REQUIRED)
endif ()
if (NOT OPENDHT_ARGON2)
    pkg_search_module(argon2 libargon2)
    if (argon2_FOUND)
        message("-- Found Argon2: " ${argon2_LIBRARY_DIRS} " (found version \"" ${argon2_VERSION} "\")")
        link_directories (${argon2_LIBRARY_DIRS})
    else ()
        message("Argon2 not found, using included version.")
        set(OPENDHT_ARGON2 ON)
    endif()
endif ()

pkg_search_module(Jsoncpp jsoncpp)
if (Jsoncpp_FOUND)
    add_definitions(-DOPENDHT_JSONCPP)
    list (APPEND opendht_SOURCES
      src/base64.h
      src/base64.cpp
    )
endif()

if (OPENDHT_HTTP)
    find_package(Restinio REQUIRED)
    if (Restinio_FOUND)
        find_library(FMT_LIBRARY fmt)
        add_library(fmt SHARED IMPORTED)
        find_library(HTTP_PARSER_LIBRARY http_parser)
        add_library(http_parser SHARED IMPORTED)
    endif()
    if (NOT Jsoncpp_FOUND)
        message(SEND_ERROR "Jsoncpp is required for DHT proxy support")
    endif()
    if (OPENDHT_PROXY_OPENSSL)
        # https://cmake.org/cmake/help/latest/module/FindOpenSSL.html
        pkg_search_module(OPENSSL REQUIRED openssl)
        if (OPENSSL_FOUND)
            message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
            include_directories(${OPENSSL_INCLUDE_DIRS})
        else ()
            message(SEND_ERROR "OpenSSL is required for DHT proxy as specified")
        endif()
    endif()
    if (OPENDHT_PROXY_HTTP_PARSER_FORK)
        add_definitions(-DOPENDHT_PROXY_HTTP_PARSER_FORK)
    endif()
else()
    set(OPENDHT_PROXY_OPENSSL OFF)
endif()
if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
    add_definitions(-DASIO_STANDALONE)
endif()

# Build flags
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED on)
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-return-type -Wall -Wextra -Wnon-virtual-dtor -pedantic-errors -fvisibility=hidden")
if (OPENDHT_SANITIZE)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fstack-protector-strong")
endif ()
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()
add_definitions(-DPACKAGE_VERSION="${opendht_VERSION}")
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
if (Restinio_INCLUDE_DIR)
    include_directories (SYSTEM "${Restinio_INCLUDE_DIR}")
endif ()
if (Jsoncpp_INCLUDE_DIRS)
    include_directories (SYSTEM "${Jsoncpp_INCLUDE_DIRS}")
endif ()
if (OpenSSL_INCLUDE_DIR)
    include_directories (SYSTEM "${OpenSSL_INCLUDE_DIR}")
endif ()
link_directories (${Nettle_LIBRARY_DIRS})
link_directories (${Jsoncpp_LIBRARY_DIRS})
include_directories (
    ./
    include/
    include/opendht/
    ${CMAKE_CURRENT_BINARY_DIR}/include/
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
    src/op_cache.cpp
    src/storage.h
    src/listener.h
    src/search.h
    src/value_cache.h
    src/op_cache.h
    src/net.h
    src/parsed_message.h
    src/request.h
    src/callbacks.cpp
    src/routing_table.cpp
    src/node_cache.cpp
    src/network_engine.cpp
    src/securedht.cpp
    src/dhtrunner.cpp
    src/log.cpp
    src/network_utils.cpp
    src/thread_pool.cpp
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
    include/opendht/dht_interface.h
    include/opendht/callbacks.h
    include/opendht/routing_table.h
    include/opendht/node_cache.h
    include/opendht/network_engine.h
    include/opendht/scheduler.h
    include/opendht/rate_limiter.h
    include/opendht/securedht.h
    include/opendht/log.h
    include/opendht/log_enable.h
    include/opendht/thread_pool.h
    include/opendht/network_utils.h
    include/opendht.h
)

if (OPENDHT_PEER_DISCOVERY)
    list (APPEND opendht_SOURCES src/peer_discovery.cpp)
    list (APPEND opendht_HEADERS include/opendht/peer_discovery.h)
    add_definitions(-DOPENDHT_PEER_DISCOVERY)
endif()

if (OPENDHT_PYTHON)
    message("Indexation enabled since it is required for Python support")
    set(OPENDHT_INDEX ON)
endif()
if (OPENDHT_INDEX)
    list (APPEND opendht_SOURCES src/indexation/pht.cpp)
    list (APPEND opendht_HEADERS include/opendht/indexation/pht.h)
    add_definitions(-DOPENDHT_INDEXATION)
endif()

if (OPENDHT_PROXY_SERVER)
  add_definitions(-DOPENDHT_PROXY_SERVER)
  if (OPENDHT_PROXY_SERVER_IDENTITY)
    add_definitions(-DOPENDHT_PROXY_SERVER_IDENTITY)
  endif()
  list (APPEND opendht_HEADERS
    include/opendht/dht_proxy_server.h
  )
  list (APPEND opendht_SOURCES
    src/dht_proxy_server.cpp
  )
endif ()

if (OPENDHT_PROXY_CLIENT)
  add_definitions(-DOPENDHT_PROXY_CLIENT)
  list (APPEND opendht_HEADERS
    include/opendht/dht_proxy_client.h
  )
  list (APPEND opendht_SOURCES
    src/dht_proxy_client.cpp
  )
endif ()

if (OPENDHT_HTTP)
  if (OPENDHT_PUSH_NOTIFICATIONS)
    message("Using push notification")
    add_definitions(-DOPENDHT_PUSH_NOTIFICATIONS)
  endif ()
  list (APPEND opendht_HEADERS
    include/opendht/proxy.h
    include/opendht/http.h
  )
  list (APPEND opendht_SOURCES
    src/http.cpp
  )
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
    if (OPENDHT_ARGON2)
        target_include_directories(opendht-static SYSTEM PRIVATE argon2)
    else ()
        target_include_directories(opendht-static SYSTEM PRIVATE ${argon2_INCLUDE_DIRS})
    endif ()
    target_link_libraries(opendht-static
        PRIVATE  ${argon2_LIBRARIES}
        PUBLIC ${CMAKE_THREAD_LIBS_INIT} ${GNUTLS_LIBRARIES} ${Nettle_STATIC_LIBRARIES}
               ${Jsoncpp_STATIC_LIBRARIES} ${FMT_LIBRARY} ${HTTP_PARSER_LIBRARY}
               ${OPENSSL_STATIC_LIBRARIES})
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
    if (OPENDHT_ARGON2)
        target_include_directories(opendht SYSTEM PRIVATE argon2)
    else ()
        target_link_libraries(opendht PRIVATE ${argon2_LIBRARIES})
        target_include_directories(opendht SYSTEM PRIVATE ${argon2_INCLUDE_DIRS})
    endif ()
    target_link_libraries(opendht
        PUBLIC ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES}
        PRIVATE ${GNUTLS_LIBRARIES} ${Nettle_LIBRARIES}
                ${Jsoncpp_LIBRARIES}
                ${FMT_LIBRARY} ${HTTP_PARSER_LIBRARY})

    install (TARGETS opendht DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT opendht)
endif ()

if (OPENDHT_C)
    add_library (opendht-c SHARED
        c/opendht.cpp
        c/opendht_c.h
    )
    target_compile_definitions(opendht-c PRIVATE OPENDHT_C_BUILD)
    if (OPENDHT_SHARED)
        target_link_libraries(opendht-c opendht)
    else ()
        target_link_libraries(opendht-c opendht-static)
    endif ()

    # PkgConfig module
    configure_file (
        opendht-c.pc.in
        opendht-c.pc
        @ONLY
    )
    install (TARGETS opendht-c DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT opendht-c)
    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendht-c.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif ()

if (OPENDHT_TOOLS)
    add_subdirectory(tools)
endif ()
add_subdirectory(doc)

if (OPENDHT_PYTHON)
    add_subdirectory(python)
endif ()

# CMake module
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

# Unit tests
if (OPENDHT_TESTS)
    pkg_search_module(Cppunit REQUIRED cppunit)
    # unit testing
    list (APPEND test_FILES
        tests/infohashtester.h
        tests/infohashtester.cpp
        tests/valuetester.h
        tests/valuetester.cpp
        tests/cryptotester.h
        tests/cryptotester.cpp
        tests/dhtrunnertester.h
        tests/dhtrunnertester.cpp
        tests/threadpooltester.h
        tests/threadpooltester.cpp
    )
    if (OPENDHT_PROXY_SERVER AND OPENDHT_PROXY_CLIENT)
        list (APPEND test_FILES
            tests/httptester.h
            tests/httptester.cpp
            tests/dhtproxytester.h
            tests/dhtproxytester.cpp
        )
    endif()
    if (OPENDHT_PEER_DISCOVERY)
        list (APPEND test_FILES
            tests/peerdiscoverytester.h
            tests/peerdiscoverytester.cpp
        )
    endif()
    add_executable(opendht_unit_tests
        tests/tests_runner.cpp
        ${test_FILES}
    )
    target_include_directories(opendht_unit_tests SYSTEM PRIVATE ${Cppunit_INCLUDE_DIR})
    target_link_directories(opendht_unit_tests PRIVATE ${Cppunit_LIBRARY_DIRS})
    if (OPENDHT_SHARED)
        target_link_libraries(opendht_unit_tests opendht)
    else ()
        target_link_libraries(opendht_unit_tests opendht-static)
    endif ()
    target_link_libraries(opendht_unit_tests
       ${CMAKE_THREAD_LIBS_INIT}
       ${Cppunit_LIBRARIES}
       ${GNUTLS_LIBRARIES}
       ${Jsoncpp_LIBRARIES}
    )
    if (OPENDHT_PROXY_OPENSSL)
        target_link_libraries(opendht_unit_tests ${OPENSSL_LIBRARIES})
    endif()
    enable_testing()
    add_test(TEST opendht_unit_tests)
endif()
