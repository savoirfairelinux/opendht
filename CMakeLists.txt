cmake_minimum_required (VERSION 3.21..3.31)
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif() # MSVC build workaround for STATIC mode
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set (opendht_VERSION_MAJOR 3)
set (opendht_VERSION_MINOR 4.0)
set (opendht_VERSION ${opendht_VERSION_MAJOR}.${opendht_VERSION_MINOR})
set (PACKAGE_VERSION ${opendht_VERSION})
set (VERSION "${opendht_VERSION}")
project (opendht
    VERSION ${opendht_VERSION}
    DESCRIPTION "OpenDHT: A lightweight C++17 Distributed Hash Table library."
    HOMEPAGE_URL "https://opendht.net/"
)


include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckIncludeFileCXX)
include(FindPkgConfig)
include(cmake/CheckAtomic.cmake)
include(FetchContent)
include(CTest)

# Options
option (BUILD_SHARED_LIBS "Build shared library" ON)
CMAKE_DEPENDENT_OPTION (OPENDHT_STATIC "Build static library" OFF BUILD_SHARED_LIBS ON)
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
option (OPENDHT_CPACK "Add CPack support" OFF)

find_package(Doxygen)
option (OPENDHT_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})

# Build flags
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED on)
if(MSVC AND NOT BUILD_SHARED_LIBS AND NOT CMAKE_MSVC_RUNTIME_LIBRARY)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if (OPENDHT_C)
    set (CMAKE_C_STANDARD 11)
    set (CMAKE_C_STANDARD_REQUIRED ON)
    if (MSVC)
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /experimental:c11atomics")
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /experimental:c11atomics")
    endif()
endif()

if (NOT HAVE_CXX_ATOMICS_WITHOUT_LIB
        # For ARM EABI (armel), little-endian MIPS (mipsel), etc.
        OR NOT HAVE_CXX_ATOMICS64_WITHOUT_LIB)
    link_libraries (atomic)
endif ()

if (WIN32)
    if(CMAKE_SYSTEM_VERSION AND CMAKE_SYSTEM_VERSION VERSION_LESS_EQUAL "6.3")
        set(WINVER 0x0603) # Minimum supported is Windows 8.1
    else()
        set(WINVER 0x0A00) # Windows 10/11 by default
    endif()
    add_definitions(-DWINVER=${WINVER} -D_WIN32_WINNT=${WINVER})
endif()

# Dependencies
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
        set(readline_LIBRARIES ${READLINE_LIBRARIES})
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
        pkg_search_module(LLHTTP IMPORTED_TARGET llhttp libllhttp)
        if (LLHTTP_FOUND)
            message(STATUS "Found llhttp ${LLHTTP_INCLUDE_DIRS}")
            set(llhttp_target PkgConfig::LLHTTP)
        else()
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
    # MSVC build - check if using vcpkg first
    if (DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
        # Using vcpkg - use find_package for dependencies
        find_package(msgpack-cxx CONFIG REQUIRED)
        find_package(fmt CONFIG REQUIRED)
        find_package(jsoncpp CONFIG REQUIRED)
        
        # Find GnuTLS and Nettle libraries (vcpkg doesn't provide CMake targets for these)
        find_library(GNUTLS_LIBRARY NAMES gnutls REQUIRED)
        find_library(NETTLE_LIBRARY NAMES nettle REQUIRED)
        find_library(HOGWEED_LIBRARY NAMES hogweed REQUIRED)
        find_library(TASN_LIBRARY NAMES tasn1 REQUIRED)
        find_library(ARGON2_LIBRARY NAMES argon2 REQUIRED)
        find_path(GNUTLS_INCLUDE_DIR gnutls/gnutls.h REQUIRED)
        find_path(NETTLE_INCLUDE_DIR nettle/aes.h REQUIRED)
        find_path(ARGON2_INCLUDE_DIR argon2.h REQUIRED)
        
        # Create imported targets for these libraries
        add_library(gnutls_lib STATIC IMPORTED)
        set_target_properties(gnutls_lib PROPERTIES
            IMPORTED_LOCATION ${GNUTLS_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${GNUTLS_INCLUDE_DIR}
        )
        
        add_library(nettle_lib STATIC IMPORTED)
        set_target_properties(nettle_lib PROPERTIES
            IMPORTED_LOCATION ${NETTLE_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${NETTLE_INCLUDE_DIR}
        )
        
        add_library(hogweed_lib STATIC IMPORTED)
        set_target_properties(hogweed_lib PROPERTIES
            IMPORTED_LOCATION ${HOGWEED_LIBRARY}
        )

        add_library(tasn1_lib STATIC IMPORTED)
        set_target_properties(tasn1_lib PROPERTIES
            IMPORTED_LOCATION ${TASN_LIBRARY}
        )
        
        add_library(argon2_lib STATIC IMPORTED)
        set_target_properties(argon2_lib PROPERTIES
            IMPORTED_LOCATION ${ARGON2_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${ARGON2_INCLUDE_DIR}
        )
        
        add_definitions(-DOPENDHT_JSONCPP)
        list (APPEND opendht_SOURCES
            src/base64.h
            src/base64.cpp
        )
        
        if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
            find_package(asio CONFIG REQUIRED)
            find_package(llhttp CONFIG REQUIRED)
            find_package(restinio CONFIG REQUIRED)
            if (OPENDHT_PROXY_OPENSSL)
                find_package(OpenSSL REQUIRED)
            endif ()
        endif ()

        if (OPENDHT_TOOLS)
            find_package(unofficial-readline-win32 CONFIG)
            if (unofficial-readline-win32_FOUND)
                set(readline_LIBRARIES unofficial::readline-win32::readline) 
            else()
                set (readline_LIBRARIES "readline")
                message(WARNING "unofficial-readline-win32 not found, trying to use system readline")
            endif()
        endif ()
    else()
        # Traditional MSVC dependency path
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
                ${WIN32_DEP_DIR}/llhttp/include
            )
        endif ()
    endif()
endif ()

if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
    add_definitions(-DASIO_STANDALONE)
    if (OPENDHT_IO_URING AND UNIX AND NOT APPLE)
        pkg_search_module(liburing IMPORTED_TARGET liburing)
    endif ()
endif()

if (NOT MSVC)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated -Wall -Wextra -Wnon-virtual-dtor -pedantic-errors -fvisibility=hidden")
    if (OPENDHT_SANITIZE)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fstack-protector-strong")
        set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fstack-protector-strong")
    endif ()
else ()
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS
                    -D_CRT_SECURE_NO_WARNINGS
                    -DWIN32_LEAN_AND_MEAN
                    -DSTATIC_GETOPT)
    set(DISABLE_MSC_WARNINGS "/wd4101 /wd4244 /wd4267 /wd4273 /wd4804 /wd4834 /wd4996")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${DISABLE_MSC_WARNINGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /bigobj /utf-8 /EHsc")
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
set (exec_prefix "\${prefix}")
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
# if (MSVC)
#     if (OPENDHT_STATIC)
#         if (OPENDHT_TOOLS)
#             function (add_obj_lib name libfile)
#                 add_library(${name} OBJECT IMPORTED)
#                 set_property(TARGET ${name} PROPERTY IMPORTED_OBJECTS ${libfile})
#             endfunction ()
#             add_obj_lib (win32_json ${WIN32_DEP_DIR}/../msvc/lib/x64/lib_json.lib)
#             add_obj_lib (win32_gnutls ${WIN32_DEP_DIR}/../msvc/lib/x64/libgnutls.lib)
#             add_obj_lib (win32_argon2 ${WIN32_DEP_DIR}/argon2/vs2015/Argon2Ref/vs2015/build/Argon2Ref.lib)
#             list (APPEND obj_libs
#                 $<TARGET_OBJECTS:win32_json>
#                 $<TARGET_OBJECTS:win32_gnutls>
#                 $<TARGET_OBJECTS:win32_argon2>
#             )
#             if (OPENDHT_HTTP)
#                 add_obj_lib (win32_fmt ${WIN32_DEP_DIR}/fmt/msvc/Release/fmt.lib)
#                 add_obj_lib (win32_llhttp ${WIN32_DEP_DIR}/llhttp/build/Release/llhttp.lib)
#                 add_obj_lib (win32_ssl ${WIN32_DEP_DIR}/openssl/libssl_static.lib)
#                 add_obj_lib (win32_crypto ${WIN32_DEP_DIR}/openssl/libcrypto_static.lib)
#                 list (APPEND obj_libs
#                     $<TARGET_OBJECTS:win32_fmt>
#                     $<TARGET_OBJECTS:win32_llhttp>
#                     $<TARGET_OBJECTS:win32_ssl>
#                     $<TARGET_OBJECTS:win32_crypto>
#                 )
#             endif ()
#         else ()
#             list (APPEND win32_Libs
#                 ${PROJECT_SOURCE_DIR}/../../msvc/lib/x64/libgnutls.lib
#                 ${PROJECT_SOURCE_DIR}/../../msvc/lib/x64/lib_json.lib
#                 ${PROJECT_SOURCE_DIR}/../argon2/vs2015/Argon2Ref/vs2015/build/Argon2Ref.lib
#             )
#             list (APPEND win32_Libs
#                 ${PROJECT_SOURCE_DIR}/../fmt/msvc/Release/fmt.lib
#                 ${PROJECT_SOURCE_DIR}/../llhttp/build/Release/llhttp.lib
#                 ${PROJECT_SOURCE_DIR}/../openssl/libssl.lib
#                 ${PROJECT_SOURCE_DIR}/../openssl/libcrypto.lib
#             )
#         endif ()
#         set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /ignore:4006")
#     endif()
# endif ()

add_library (opendht
    ${opendht_SOURCES}
    ${opendht_HEADERS}
    ${obj_libs}
)
set_target_properties (opendht PROPERTIES OUTPUT_NAME "opendht")

if (NOT HAVE_MSGPACKCXX)
    target_link_libraries(opendht PUBLIC ${MSGPACK_TARGET})
endif()
if (APPLE)
    target_link_libraries(opendht PRIVATE "-framework CoreFoundation" "-framework Security")
endif()
if (WIN32)
    target_link_libraries(opendht PUBLIC ws2_32 wsock32)
    if (OPENDHT_HTTP)
        target_link_libraries(opendht PRIVATE crypt32)
    endif()
endif()
if (MSVC)
    if (DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
        # Using vcpkg - link with vcpkg targets
        target_link_libraries(opendht
            PUBLIC
                msgpack-cxx
                fmt::fmt
                JsonCpp::JsonCpp
                gnutls_lib
            PRIVATE
                argon2_lib
                nettle_lib
                hogweed_lib
                tasn1_lib
        )
        if (OPENDHT_HTTP)
            target_link_libraries(opendht
                PUBLIC restinio::restinio
                PRIVATE llhttp::llhttp_static)
            if (OPENDHT_PROXY_OPENSSL)
                target_link_libraries(opendht PUBLIC OpenSSL::SSL OpenSSL::Crypto)
            endif()
        endif()
    endif()
    if (OPENDHT_STATIC)
        target_link_libraries(opendht PUBLIC ${Win32_STATIC_LIBRARIES} ${Win32_IMPORT_LIBRARIES})
    endif()
else()
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
    set_target_properties (opendht PROPERTIES IMPORT_SUFFIX "_import.lib")
    set_target_properties (opendht PROPERTIES SOVERSION ${opendht_VERSION_MAJOR} VERSION ${opendht_VERSION})
    target_compile_definitions(opendht PRIVATE OPENDHT_BUILD)
    target_compile_definitions(opendht PUBLIC opendht_EXPORTS)
endif ()


install (TARGETS opendht
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME_DEPENDENCY_SET opendht_rdeps
    EXPORT opendht
)
if (WIN32 AND DEFINED CMAKE_TOOLCHAIN_FILE AND CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg")
    install(RUNTIME_DEPENDENCY_SET opendht_rdeps
        PRE_EXCLUDE_REGEXES
            "api-ms-win-.*\\.dll"
            "ext-ms-.*\\.dll"
            "d3d.*\\.dll"
            "dxgi.*\\.dll"
            "uxtheme\\.dll"
            "dwmapi\\.dll"
            "crypt32\\.dll"
            "bcrypt\\.dll"
            "ncrypt\\.dll"
            "sechost\\.dll"
            "user32\\.dll"
            "kernel32\\.dll"
            "gdi32\\.dll"
            "shell32\\.dll"
            "advapi32\\.dll"
            "ole32\\.dll"
            "oleaut32\\.dll"
            "shlwapi\\.dll"
            "comdlg32\\.dll"
            "winspool\\.drv"
            "mpr\\.dll"
            "version\\.dll"
            "ws2_32\\.dll" 
            "vcruntime.*\\.dll"
            "msvcp.*\\.dll"
            "wpax.*\\.dll"
            "azure.*\\.dll"
    )
endif()

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
    install (FILES c/opendht_c.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/opendht)
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
install (DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendht.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install (EXPORT opendht DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/opendht FILE opendhtConfig.cmake)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/opendhtConfigVersion.cmake DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/opendht)

# Unit tests
if (BUILD_TESTING)
    if (NOT MSVC)
        pkg_search_module(Cppunit REQUIRED IMPORTED_TARGET cppunit)
        set(cppunit_LIBRARIES PkgConfig::Cppunit)
    else()
        find_package(CppUnit CONFIG REQUIRED)
        set(cppunit_LIBRARIES CppUnit)
    endif()
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
        ${cppunit_LIBRARIES}
    )
    add_test(TEST opendht_unit_tests)
endif()

if (OPENDHT_CPACK)
    set(CPACK_PACKAGE_NAME "OpenDHT")
    set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_PACKAGE_VENDOR "Savoir-faire Linux, Inc.")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "OpenDHT: A lightweight C++17 Distributed Hash Table library.")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://opendht.net/")
    set(CPACK_PACKAGE_CONTACT "support@savoirfairelinux.com") # Or a relevant contact/mailing list
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING.txt")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "OpenDHT")

    if(WIN32)
        # WiX specific settings
        set(CPACK_GENERATOR "WIX") # Can be overridden by -G on the command line
        set(CPACK_WIX_VERSION 4)
        set(CPACK_WIX_PRODUCT_GUID "5e2faa2b-a4f4-4431-ba15-ed94e732a949")
        set(CPACK_WIX_UPGRADE_GUID "cbff4222-9b41-48a2-94ea-6f8a228c5936")
        set(CPACK_WIX_PRODUCT_ICON "${CMAKE_CURRENT_SOURCE_DIR}/resources/opendht_logo_512.ico")
        set(CPACK_WIX_UI_BANNER "${CMAKE_CURRENT_SOURCE_DIR}/resources/opendht_install_banner.bmp")
        set(CPACK_WIX_UI_DIALOG "${CMAKE_CURRENT_SOURCE_DIR}/resources/opendht_install_bg.bmp")
        set(CPACK_WIX_PROGRAM_MENU_FOLDER "${PROJECT_NAME}")
        set(CPACK_WIX_INSTALL_SCOPE "perMachine")
    endif()

    set(CPACK_PACKAGE_EXECUTABLES "dhtnode;DHT Node")
    set(CPACK_CREATE_DESKTOP_LINKS "dhtnode")
    include(CPack)
endif()
