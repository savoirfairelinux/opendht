cmake_minimum_required (VERSION 3.16..3.28)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
project (opendht)

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckIncludeFileCXX)
include(FindPkgConfig)
include(cmake/CheckAtomic.cmake)
include(CTest)
include(FetchContent)

set (opendht_VERSION_MAJOR 3)
set (opendht_VERSION_MINOR 3.0)
set (opendht_VERSION ${opendht_VERSION_MAJOR}.${opendht_VERSION_MINOR})
set (PACKAGE_VERSION ${opendht_VERSION})
set (VERSION "${opendht_VERSION}")

# Options
option (BUILD_SHARED_LIBS "Build shared library" ON)
option (OPENDHT_PYTHON "Build Python bindings" OFF)
option (OPENDHT_TOOLS "Build DHT tools" ON)
option (OPENDHT_SYSTEMD "Install systemd module" OFF)
option (OPENDHT_SYSTEMD_UNIT_FILE_LOCATION "Where to install systemd unit file")
option (OPENDHT_SANITIZE "Build with address sanitizer and stack protector" OFF)
option (OPENDHT_PROXY_SERVER "Enable DHT proxy server, use Restinio and jsoncpp" OFF)
option (OPENDHT_PUSH_NOTIFICATIONS "Enable push notifications support" OFF)
option (OPENDHT_PROXY_SERVER_IDENTITY "Allow clients to use the node identity" OFF)
option (OPENDHT_PROXY_CLIENT "Enable DHT proxy client, use Restinio and jsoncpp" OFF)
option (OPENDHT_PROXY_OPENSSL "Build DHT proxy with OpenSSL" ON)
CMAKE_DEPENDENT_OPTION(OPENDHT_HTTP "Build embedded http(s) client" OFF "NOT OPENDHT_PROXY_SERVER;NOT OPENDHT_PROXY_CLIENT" ON)
option (OPENDHT_PEER_DISCOVERY "Enable multicast peer discovery" ON)
option (OPENDHT_IO_URING "Use io_uring if available on the system (Linux only)" OFF)
option (OPENDHT_INDEX "Build DHT indexation feature" OFF)
option (OPENDHT_TESTS_NETWORK "Enable unit tests that require network access" ON)
option (OPENDHT_C "Build C bindings" OFF)

find_package(Doxygen)
option (OPENDHT_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})

# Build flags
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED on)

# Dependencies
if (NOT HAVE_CXX_ATOMICS_WITHOUT_LIB
        # For ARM EABI (armel), little-endian MIPS (mipsel), etc.
        OR NOT HAVE_CXX_ATOMICS64_WITHOUT_LIB)
    link_libraries (atomic)
endif ()

list (APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
if (NOT MSVC)
    set (THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package (Threads)
    find_package (PkgConfig REQUIRED)
    pkg_search_module (GnuTLS REQUIRED IMPORTED_TARGET gnutls)
    pkg_search_module (Nettle REQUIRED IMPORTED_TARGET nettle)
    check_include_file_cxx(msgpack.hpp HAVE_MSGPACKCXX)
    if (NOT HAVE_MSGPACKCXX)
        find_package(msgpack QUIET CONFIG NAMES msgpack msgpackc-cxx)
        if (NOT msgpack_FOUND)
            find_package(msgpack REQUIRED CONFIG NAMES msgpack-cxx)
            set(MSGPACK_TARGET "msgpack-cxx")
        else()
            set(MSGPACK_TARGET "msgpackc-cxx")
        endif()
    endif()
    if (OPENDHT_TOOLS)
        find_package (Readline 6 REQUIRED)
    endif ()
    pkg_search_module(argon2 REQUIRED IMPORTED_TARGET libargon2)
    set(argon2_lib ", libargon2")
    pkg_search_module(Jsoncpp IMPORTED_TARGET jsoncpp)
    if (Jsoncpp_FOUND)
        add_definitions(-DOPENDHT_JSONCPP)
        set(jsoncpp_lib ", jsoncpp")
        list (APPEND opendht_SOURCES
          src/base64.h
          src/base64.cpp
        )
    endif()

    if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
        find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED)
        message(STATUS "Found ASIO ${ASIO_INCLUDE_DIR}")
    else()
        message(STATUS "ASIO not required")
    endif ()

    find_package(fmt)

    if (OPENDHT_HTTP)
        find_package(Restinio REQUIRED)

        # llhttp
        find_path(LLHTTP_INCLUDE_DIR llhttp.h)
        find_library(LLHTTP_LIBRARY NAMES llhttp libllhttp)
        if (LLHTTP_INCLUDE_DIR AND LLHTTP_LIBRARY)
            message(STATUS "Found llhttp ${LLHTTP_INCLUDE_DIR} ${LLHTTP_LIBRARY}")
            add_library(llhttp_static STATIC IMPORTED)
            set_target_properties(llhttp_static PROPERTIES
                IMPORTED_LOCATION ${LLHTTP_LIBRARY}
                INTERFACE_INCLUDE_DIRECTORIES ${LLHTTP_INCLUDE_DIR}
            )
            set(llhttp_target llhttp_static)
        else()
            FetchContent_Declare(llhttp-local URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.tar.gz")
            if (BUILD_SHARED_LIBS)
                set(BUILD_SHARED_LIBS ON CACHE INTERNAL "")
            else()
                set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
                set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")
            endif()
            FetchContent_MakeAvailable(llhttp-local)
            if (BUILD_SHARED_LIBS)
                set(llhttp_target llhttp_shared)
            else()
                set(llhttp_target llhttp_static)
            endif()
        endif()
        set(http_lib "-lllhttp")

        if (NOT Jsoncpp_FOUND)
            message(SEND_ERROR "Jsoncpp is required for DHT proxy support")
        endif()
        if (OPENDHT_PROXY_OPENSSL)
            # https://cmake.org/cmake/help/latest/module/FindOpenSSL.html
            pkg_search_module(OPENSSL REQUIRED IMPORTED_TARGET openssl)
            if (OPENSSL_FOUND)
                message(STATUS "Found OpenSSL ${OPENSSL_VERSION} ${OPENSSL_INCLUDE_DIRS}")
                set(openssl_lib ", openssl")
            else ()
                message(SEND_ERROR "OpenSSL is required for DHT proxy as specified")
            endif()
        endif()
    else ()
        set(OPENDHT_PROXY_OPENSSL OFF)
    endif ()
else ()
    include_directories(src/compat/msvc)

    set(CMAKE_MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE)

    pkg_search_module(GnuTLS REQUIRED IMPORTED_TARGET GnuTLS)
    include_directories(${GnuTLS_INCLUDEDIR})
    link_directories(${GnuTLS_LIBDIR})

    pkg_search_module(nettle REQUIRED IMPORTED_TARGET nettle)
    include_directories(${nettle_INCLUDEDIR})
    link_directories(${nettle_LIBDIR})

    find_package(msgpack-cxx CONFIG REQUIRED)
    get_target_property(MSGPACK_INCLUDEDIR msgpack-cxx INTERFACE_INCLUDE_DIRECTORIES)
    include_directories(${MSGPACK_INCLUDEDIR})

    find_package(unofficial-argon2 CONFIG REQUIRED)
    get_target_property(ARGON2_INCLUDEDIR unofficial::argon2::libargon2 INTERFACE_INCLUDE_DIRECTORIES)
    include_directories(${ARGON2_INCLUDEDIR})

    set(argon2_lib ", libargon2")

    find_package(jsoncpp CONFIG REQUIRED)
    get_target_property(JSONCPP_LIB JsonCpp::JsonCpp INTERFACE_LINK_LIBRARIES)
    get_target_property(JSONCPP_INCLUDEDIR ${JSONCPP_LIB} INTERFACE_INCLUDE_DIRECTORIES)
    include_directories(${JSONCPP_INCLUDEDIR})

    set(jsoncpp_lib ", jsoncpp")

    find_package(fmt CONFIG REQUIRED)
    get_target_property(FMT_INCLUDEDIR fmt::fmt-header-only INTERFACE_INCLUDE_DIRECTORIES)
    include_directories(${FMT_INCLUDEDIR})

    list (APPEND opendht_SOURCES
        src/base64.h
        src/base64.cpp
    )
    add_definitions(-DOPENDHT_JSONCPP)
    
    if(OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
        find_package(asio CONFIG REQUIRED)
        get_target_property(ASIO_INCLUDEDIR asio INTERFACE_INCLUDE_DIRECTORIES)
        include_directories(${ASIO_INCLUDEDIR})
    endif()

    if (OPENDHT_HTTP)
        find_package(restinio CONFIG REQUIRED)
        get_target_property(RESTINIO_INCLUDEDIR restinio::restinio INTERFACE_INCLUDE_DIRECTORIES)
        include_directories(${RESTINIO_INCLUDEDIR})

        find_package(llhttp CONFIG REQUIRED)
        get_target_property(LLHTTP_INCLUDEDIR llhttp::llhttp_static INTERFACE_INCLUDE_DIRECTORIES)
        include_directories(${LLHTTP_INCLUDEDIR})
        set(http_lib "-lllhttp")

        if (OPENDHT_PROXY_OPENSSL)
            find_package(OpenSSL REQUIRED)
            get_target_property(OPENSSL_INCLUDEDIR OpenSSL::SSL INTERFACE_INCLUDE_DIRECTORIES)
            include_directories(${OPENSSL_INCLUDEDIR})
            set(openssl_lib ", openssl")
        endif()
    else()
        set(OPENDHT_PROXY_OPENSSL OFF)
    endif()
endif ()

if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
    add_definitions(-DASIO_STANDALONE)
    if (OPENDHT_IO_URING AND UNIX AND NOT APPLE)
        pkg_search_module(liburing IMPORTED_TARGET liburing)
    endif ()
endif()

if (NOT MSVC)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-return-type -Wno-deprecated -Wall -Wextra -Wnon-virtual-dtor -pedantic-errors -fvisibility=hidden")
    if (OPENDHT_SANITIZE)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fstack-protector-strong")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fstack-protector-strong")
    endif ()
else ()
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS
                    -D_CRT_SECURE_NO_WARNINGS
                    -DWIN32_LEAN_AND_MEAN
                    -DSTATIC_GETOPT
                    -DGNUTLS_INTERNAL_BUILD)
    set(DISABLE_MSC_WARNINGS "/wd4101 /wd4244 /wd4267 /wd4273 /wd4804 /wd4834 /wd4996")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DISABLE_MSC_WARNINGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /bigobj")
endif ()
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMSGPACK_NO_BOOST -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT")

add_definitions(-DPACKAGE_VERSION="${opendht_VERSION}")

if (ASIO_INCLUDE_DIR)
    include_directories (SYSTEM "${ASIO_INCLUDE_DIR}")
endif ()
if (Restinio_INCLUDE_DIR)
    include_directories (SYSTEM "${Restinio_INCLUDE_DIR}")
endif ()
include_directories (
    ./
    include/
    include/opendht/
    ${CMAKE_CURRENT_BINARY_DIR}/include/
)

# Install dirs
include (GNUInstallDirs)
set (prefix ${CMAKE_INSTALL_PREFIX})
set (exec_prefix "${prefix}")
set (libdir "${CMAKE_INSTALL_FULL_LIBDIR}")
set (includedir "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set (bindir "${CMAKE_INSTALL_FULL_BINDIR}")
set (sysconfdir "${CMAKE_INSTALL_FULL_SYSCONFDIR}")
set (top_srcdir "${CMAKE_CURRENT_SOURCE_DIR}")

# Sources
list (APPEND opendht_SOURCES
    src/utils.cpp
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
    include/opendht.h
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
    include/opendht/logger.h
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
    src/compat/os_cert.h
  )
  list (APPEND opendht_SOURCES
    src/http.cpp
    src/compat/os_cert.cpp
  )
endif ()

if (MSVC)
    list (APPEND opendht_HEADERS src/compat/msvc/unistd.h)
endif ()

# Targets

add_library(opendht ${opendht_SOURCES} ${opendht_HEADERS})

target_include_directories(opendht
                           PUBLIC
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
                           "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

set_target_properties(opendht PROPERTIES OUTPUT_NAME "opendht")

if (MSVC)
    target_link_libraries(opendht PUBLIC PkgConfig::GnuTLS JsonCpp::JsonCpp fmt::fmt-header-only PRIVATE PkgConfig::nettle unofficial::argon2::libargon2)
    if (OPENDHT_HTTP)
        target_link_libraries(opendht PUBLIC llhttp::llhttp_static)
        if (OPENDHT_PROXY_OPENSSL)
            target_link_libraries(opendht PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        endif()
    endif()
    if (NOT BUILD_SHARED_LIBS)
        target_link_libraries(opendht PUBLIC ${Win32_STATIC_LIBRARIES} ${Win32_IMPORT_LIBRARIES})
        set_target_properties(opendht PROPERTIES OUTPUT_NAME "libopendht")
    endif()
else()
    if (APPLE)
        target_link_libraries(opendht PRIVATE "-framework CoreFoundation" "-framework Security")
    endif ()
    if (NOT HAVE_MSGPACKCXX)
        target_link_libraries(opendht PUBLIC ${MSGPACK_TARGET})
    endif()
    target_link_libraries(opendht
        PRIVATE
            PkgConfig::argon2
            PkgConfig::Nettle
        PUBLIC
            ${CMAKE_THREAD_LIBS_INIT}
            PkgConfig::GnuTLS
            fmt::fmt
    )
    if (OPENDHT_HTTP)
        target_link_libraries(opendht PUBLIC ${llhttp_target})
    endif()
    if (Jsoncpp_FOUND)
        target_link_libraries(opendht PUBLIC PkgConfig::Jsoncpp)
    endif()
    if (OPENDHT_PROXY_OPENSSL)
        target_link_libraries(opendht PUBLIC PkgConfig::OPENSSL)
    endif()
    if (OPENDHT_IO_URING AND liburing_FOUND)
        set(iouring_lib ", liburing")
        target_link_libraries(opendht PUBLIC PkgConfig::liburing)
        target_compile_definitions(opendht PUBLIC ASIO_HAS_IO_URING ASIO_DISABLE_EPOLL)
    endif()
endif()

if (BUILD_SHARED_LIBS)
    set_target_properties (opendht PROPERTIES SOVERSION ${opendht_VERSION_MAJOR} VERSION ${opendht_VERSION})
    target_compile_definitions(opendht PRIVATE opendht_EXPORTS)
else ()
    target_compile_definitions(opendht PRIVATE OPENDHT_STATIC) # to build library with default class attributes
endif ()
install (TARGETS opendht DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT opendht)

if (OPENDHT_C)
    add_library (opendht-c
        c/opendht.cpp
        c/opendht_c.h
    )
    target_compile_definitions(opendht-c PRIVATE OPENDHT_C_BUILD)
    target_link_libraries(opendht-c PRIVATE opendht)
    set_target_properties (opendht-c PROPERTIES SOVERSION ${opendht_VERSION_MAJOR} VERSION ${opendht_VERSION})
    install (TARGETS opendht-c DESTINATION ${CMAKE_INSTALL_LIBDIR} EXPORT opendht-c)

    # PkgConfig module
    configure_file (
        opendht-c.pc.in
        opendht-c.pc
        @ONLY
    )
    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendht-c.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    install (FILES c/opendht_c.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/opendht)
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
if(MSVC AND BUILD_SHARED_LIBS)
    install(FILES $<TARGET_PDB_FILE:opendht> CONFIGURATIONS "RelWithDebInfo" "Debug" DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

# Unit tests
if (BUILD_TESTING AND NOT MSVC)
    pkg_search_module(Cppunit REQUIRED IMPORTED_TARGET cppunit)
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
    if (OPENDHT_TESTS_NETWORK)
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
    endif()
    add_executable(opendht_unit_tests
        tests/tests_runner.cpp
        ${test_FILES}
    )
    target_link_libraries(opendht_unit_tests PRIVATE
       opendht
       ${CMAKE_THREAD_LIBS_INIT}
       PkgConfig::Cppunit
    )
    add_test(TEST opendht_unit_tests)
endif()
