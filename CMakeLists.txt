cmake_minimum_required (VERSION 3.10..3.20)
if(POLICY CMP0073)
  cmake_policy(SET CMP0073 NEW)
endif()
if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()
project (opendht)

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckIncludeFileCXX)
include(FindPkgConfig)
include(cmake/CheckAtomic.cmake)
include(CTest)

set (opendht_VERSION_MAJOR 2)
set (opendht_VERSION_MINOR 5.0)
set (opendht_VERSION ${opendht_VERSION_MAJOR}.${opendht_VERSION_MINOR})
set (PACKAGE_VERSION ${opendht_VERSION})
set (VERSION "${opendht_VERSION}")

# Options
option (BUILD_SHARED_LIBS "Build shared library" ON)
CMAKE_DEPENDENT_OPTION (OPENDHT_STATIC "Build static library" OFF BUILD_SHARED_LIBS ON)
option (OPENDHT_LOG "Build with logs" ON)
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
option (OPENDHT_INDEX "Build DHT indexation feature" OFF)
option (OPENDHT_TESTS_NETWORK "Enable unit tests that require network access" ON)
option (OPENDHT_C "Build C bindings" OFF)

find_package(Doxygen)
option (OPENDHT_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})

# Build flags
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED on)

# Dependencies
if (NOT HAVE_CXX_ATOMICS_WITHOUT_LIB)
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
        find_package (msgpack REQUIRED CONFIG)
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
    endif ()

    if (OPENDHT_HTTP)
        find_package(Restinio REQUIRED)
        find_library(FMT_LIBRARY fmt)
        add_library(fmt SHARED IMPORTED)
        find_library(HTTP_PARSER_LIBRARY http_parser)
        add_library(http_parser SHARED IMPORTED)
        set(http_parser_lib "-lhttp_parser")
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
    set (WIN32_DEP_DIR ${PROJECT_SOURCE_DIR}/../)
    include_directories(${WIN32_DEP_DIR}/../msvc/include) # SMP gnutls
    include_directories(${WIN32_DEP_DIR}/argon2/include)
    include_directories(${WIN32_DEP_DIR}/jsoncpp/include)
    list (APPEND opendht_SOURCES
        src/base64.h
        src/base64.cpp
    )
    add_definitions(-DOPENDHT_JSONCPP)
    include_directories(${WIN32_DEP_DIR}/msgpack-c/include)
    if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
        include_directories(
            ${WIN32_DEP_DIR}/asio/asio/include
            ${WIN32_DEP_DIR}/openssl/include
            ${WIN32_DEP_DIR}/restinio/dev
            ${WIN32_DEP_DIR}/fmt/include
            ${WIN32_DEP_DIR}/http_parser
        )
    endif ()
endif ()

if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
    add_definitions(-DASIO_STANDALONE)
endif()

if (NOT MSVC)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-return-type -Wno-deprecated -Wall -Wextra -Wnon-virtual-dtor -pedantic-errors -fvisibility=hidden")
    if (OPENDHT_SANITIZE)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fstack-protector-strong")
    endif ()
else ()
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS
                    -D_CRT_SECURE_NO_WARNINGS
                    -DWIN32_LEAN_AND_MEAN
                    -DSTATIC_GETOPT
                    -DGNUTLS_INTERNAL_BUILD)
    set(DISABLE_MSC_WARNINGS "/wd4101 /wd4244 /wd4267 /wd4273 /wd4804 /wd4834 /wd4996")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DISABLE_MSC_WARNINGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
endif ()
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMSGPACK_NO_BOOST -DMSGPACK_DISABLE_LEGACY_NIL -DMSGPACK_DISABLE_LEGACY_CONVERT")

add_definitions(-DPACKAGE_VERSION="${opendht_VERSION}")
if (OPENDHT_LOG)
    add_definitions(-DOPENDHT_LOG=true)
else ()
    add_definitions(-DOPENDHT_LOG=false)
endif()

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
set (exec_prefix "\${prefix}")
set (libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
set (includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
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
if (MSVC)
    if (OPENDHT_STATIC)
        if (OPENDHT_TOOLS)
            function (add_obj_lib name libfile)
                add_library(${name} OBJECT IMPORTED)
                set_property(TARGET ${name} PROPERTY IMPORTED_OBJECTS ${libfile})
            endfunction ()
            add_obj_lib (win32_json ${WIN32_DEP_DIR}/../msvc/lib/x64/lib_json.lib)
            add_obj_lib (win32_gnutls ${WIN32_DEP_DIR}/../msvc/lib/x64/libgnutls.lib)
            add_obj_lib (win32_argon2 ${WIN32_DEP_DIR}/argon2/vs2015/Argon2Ref/vs2015/build/Argon2Ref.lib)
            list (APPEND obj_libs
                $<TARGET_OBJECTS:win32_json>
                $<TARGET_OBJECTS:win32_gnutls>
                $<TARGET_OBJECTS:win32_argon2>
            )
            if (OPENDHT_HTTP)
                add_obj_lib (win32_fmt ${WIN32_DEP_DIR}/fmt/msvc/Release/fmt.lib)
                add_obj_lib (win32_http_parser ${WIN32_DEP_DIR}/http_parser/x64/Release/http-parser.lib)
                add_obj_lib (win32_ssl ${WIN32_DEP_DIR}/openssl/libssl_static.lib)
                add_obj_lib (win32_crypto ${WIN32_DEP_DIR}/openssl/libcrypto_static.lib)
                list (APPEND obj_libs
                    $<TARGET_OBJECTS:win32_fmt>
                    $<TARGET_OBJECTS:win32_http_parser>
                    $<TARGET_OBJECTS:win32_ssl>
                    $<TARGET_OBJECTS:win32_crypto>
                )
            endif ()
        else ()
            list (APPEND win32_Libs
                ${PROJECT_SOURCE_DIR}/../../msvc/lib/x64/libgnutls.lib
                ${PROJECT_SOURCE_DIR}/../../msvc/lib/x64/lib_json.lib
                ${PROJECT_SOURCE_DIR}/../argon2/vs2015/Argon2Ref/vs2015/build/Argon2Ref.lib
            )
            list (APPEND win32_Libs
                ${PROJECT_SOURCE_DIR}/../fmt/msvc/Release/fmt.lib
                ${PROJECT_SOURCE_DIR}/../http_parser/x64/Release/http-parser.lib
                ${PROJECT_SOURCE_DIR}/../openssl/libssl.lib
                ${PROJECT_SOURCE_DIR}/../openssl/libcrypto.lib
            )
        endif ()
        set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /ignore:4006")
    endif()
endif ()

add_library (opendht
    ${opendht_SOURCES}
    ${opendht_HEADERS}
    ${obj_libs}
)
set_target_properties (opendht PROPERTIES OUTPUT_NAME "opendht")
target_link_libraries(opendht
    PRIVATE
        PkgConfig::argon2
        PkgConfig::Nettle
        ${HTTP_PARSER_LIBRARY}
    PUBLIC
        ${CMAKE_THREAD_LIBS_INIT}
        PkgConfig::GnuTLS
        ${FMT_LIBRARY}
)
if (NOT HAVE_MSGPACKCXX)
    target_link_libraries(opendht PUBLIC msgpackc-cxx)
endif()
if (Jsoncpp_FOUND)
    target_link_libraries(opendht PUBLIC PkgConfig::Jsoncpp)
endif()
if (OPENDHT_PROXY_OPENSSL)
    target_link_libraries(opendht PUBLIC PkgConfig::OPENSSL)
endif()
if (APPLE)
    target_link_libraries(opendht PRIVATE SYSTEM "-framework CoreFoundation" "-framework Security")
endif()
if (MSVC)
    if (OPENDHT_STATIC)
        target_link_libraries(opendht PUBLIC ${Win32_STATIC_LIBRARIES} ${Win32_IMPORT_LIBRARIES})
        set_target_properties (opendht PROPERTIES OUTPUT_NAME "libopendht")
    endif()
endif ()

if (BUILD_SHARED_LIBS)
    set_target_properties (opendht PROPERTIES IMPORT_SUFFIX "_import.lib")
    set_target_properties (opendht PROPERTIES SOVERSION ${opendht_VERSION_MAJOR} VERSION ${opendht_VERSION})
    target_compile_definitions(opendht PRIVATE OPENDHT_BUILD)
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

# Unit tests
if (BUILD_TESTING)
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
