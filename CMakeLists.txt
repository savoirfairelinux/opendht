cmake_minimum_required (VERSION 3.21..3.31)
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
if(NOT CMAKE_VERSION VERSION_LESS 3.30 AND NOT POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()
if(CMAKE_VERSION VERSION_GREATER_EQUAL 4)
	set(CMAKE_POLICY_VERSION_MINIMUM "3.5")
endif() # CMake 4.0 and later: version handler workaround

project (opendht)

include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(CheckIncludeFileCXX)
if(NOT WIN32)
    include(FindPkgConfig)
endif()
include(cmake/CheckAtomic.cmake)
include(CTest)
include(FetchContent)

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
if (DOXYGEN_FOUND)
    option (OPENDHT_DOCUMENTATION "Create and install the HTML based API documentation (requires Doxygen)" ${DOXYGEN_FOUND})
endif ()
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

if(WIN32) # https://stackoverflow.com/a/40217291/9560245
    macro(get_WIN32_WINNT version)
        if(CMAKE_SYSTEM_VERSION)
            set(ver ${CMAKE_SYSTEM_VERSION})
            string(REGEX MATCH "^([0-9]+).([0-9])" ver ${ver})
            string(REGEX MATCH "^([0-9]+)" verMajor ${ver})
            # Check for Windows 10, b/c we'll need to convert to hex 'A'.
            if("${verMajor}" MATCHES "10")
                set(verMajor "A")
                string(REGEX REPLACE "^([0-9]+)" ${verMajor} ver ${ver})
            endif()
            # Remove all remaining '.' characters.
            string(REPLACE "." "" ver ${ver})
            # Prepend each digit with a zero.
            string(REGEX REPLACE "([0-9A-Z])" "0\\1" ver ${ver})
            set(${version} "0x${ver}")
        endif()
    endmacro()

    get_WIN32_WINNT(WINNT_VERSION)
    message(STATUS "Windows NT version detection: ${WINNT_VERSION}")
    if(NOT MSVC)
        add_definitions(-D_WIN32_WINNT=${WINNT_VERSION} -DWINVER=${WINNT_VERSION})
    endif()

    set(CMAKE_DEBUG_POSTFIX "")
endif()

# Dependencies
list (APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
if (NOT MSVC)
    if (WIN32 AND MINGW) # MSYS2
        set (THREADS_PREFER_PTHREAD_FLAG TRUE)
        find_package (Threads)
        set(CMAKE_MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE)

        # Workaround for msgpack-cxx
        set(FETCHCONTENT_QUIET FALSE)
        FetchContent_Declare(msgpack-c
            GIT_REPOSITORY "https://github.com/msgpack/msgpack-c.git"
            GIT_TAG        "cpp-7.0.0"
            FIND_PACKAGE_ARGS NAMES msgpack-c 
        )
        set(MSGPACK_USE_BOOST OFF CACHE INTERNAL "Workaround for Boost")
        FetchContent_MakeAvailable(msgpack-c)
        
        find_package(msgpack-c CONFIG REQUIRED)
        include_directories(${MSGPACK_INCLUDEDIR} ${msgpack-c_SOURCE_DIR}/include)
        
        find_path(ARGON2_INCLUDE_DIR argon2.h REQUIRED)
        include_directories(${ARGON2_INCLUDE_DIR})
        
        find_package(GnuTLS REQUIRED)
        include_directories(${GNUTLS_INCLUDE_DIR})
        
        set(argon2_lib ", libargon2")
        
        find_package(jsoncpp CONFIG REQUIRED)
        if (BUILD_SHARED_LIBS)
            get_target_property(JSONCPP_INCLUDE_DIRS jsoncpp_lib INTERFACE_INCLUDE_DIRECTORIES)
        else ()
            get_target_property(JSONCPP_INCLUDE_DIRS jsoncpp_static INTERFACE_INCLUDE_DIRECTORIES)
        endif ()
        include_directories(${JSONCPP_INCLUDE_DIRS})
        
        find_package(fmt CONFIG REQUIRED)
        include_directories(${FMT_INCLUDEDIR})
        
        if (OPENDHT_TOOLS)
            find_package (Readline 6 REQUIRED)
        endif ()

        add_definitions(-DOPENDHT_JSONCPP)
        set(jsoncpp_lib ", jsoncpp")
        list (APPEND opendht_SOURCES
            src/base64.h
            src/base64.cpp
        )
        
        if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
            find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED HINTS ${asio_SOURCE_DIR}/asio/include)
            message(STATUS "Found ASIO ${ASIO_INCLUDE_DIR}")
            include_directories(${ASIO_INCLUDE_DIR})
            add_definitions(-DASIO_STANDALONE) 
        else()
            message(STATUS "ASIO not required")
        endif ()
        
        find_package(fmt)
        
        if (OPENDHT_HTTP)
            find_package(restinio CONFIG REQUIRED)
            find_package(llhttp CONFIG REQUIRED)
            set(http_lib "-lllhttp")

            if (NOT jsoncpp_FOUND)
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
    else () # UNIX
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
            find_library(LLHTTP_LIBRARY libllhttp)
            if (LLHTTP_INCLUDE_DIR AND LLHTTP_LIBRARY)
                message(STATUS "Found llhttp ${LLHTTP_INCLUDE_DIR} ${LLHTTP_LIBRARY}")
                add_library(llhttp_static STATIC IMPORTED)
                set_target_properties(llhttp_static PROPERTIES
                    IMPORTED_LOCATION ${LLHTTP_LIBRARY}
                    INTERFACE_INCLUDE_DIRECTORIES ${LLHTTP_INCLUDE_DIR}
                )
                set(llhttp_target llhttp_static)
            else()
                FetchContent_Declare(llhttp-local URL "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.0.tar.gz")
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
    endif ()
else () # MSVC
    set(CMAKE_CXX_FLAGS "/utf-8 /EHsc") # Unicode workaround
    if (BUILD_SHARED_LIBS)
        message(STATUS "Building shared library")
        set(VCPKG_TARGET_TRIPLET "x64-windows")
        set(VCPKG_OVERLAY_TRIPLETS "x64-windows-release;x64-windows")
    else ()
        message(STATUS "Building static library")
        set(VCPKG_TARGET_TRIPLET "x64-windows-static")
        set(VCPKG_OVERLAY_TRIPLETS "x64-windows-static-release;x64-windows-static-rel;x64-windows-static")
    endif ()

    include_directories(src/compat/msvc)
    include_directories(src/compat/win32)
    set(CMAKE_MAP_IMPORTED_CONFIG_RELWITHDEBINFO RELEASE)
    
    find_package(unofficial-argon2 CONFIG REQUIRED)
    include_directories(${ARGON2_INCLUDEDIR})
    set(argon2_lib ", libargon2")

    find_package(GnuTLS REQUIRED)
    include_directories(${GNUTLS_INCLUDE_DIR})

    find_library(NETTLE_LIBRARY NAMES nettle libnettle HINTS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib" REQUIRED)
    
    find_package(msgpack-cxx CONFIG REQUIRED)
    get_target_property(MSGPACK_INCLUDEDIR msgpack-cxx INTERFACE_INCLUDE_DIRECTORIES)
    include_directories(${MSGPACK_INCLUDEDIR})
    
    find_package(jsoncpp REQUIRED)
    include_directories(${JSONCPP_INCLUDE_DIRS})
    
    find_package(fmt CONFIG REQUIRED)
    include_directories(${FMT_INCLUDEDIR})
    
    find_package(unofficial-readline-win32 CONFIG REQUIRED)
    include_directories(${READLINE_INCLUDEDIR})

    if (OPENDHT_HTTP OR OPENDHT_PEER_DISCOVERY)
        find_package(asio CONFIG REQUIRED)
        find_path(ASIO_INCLUDE_DIR asio.hpp REQUIRED HINTS ${ASIO_INCLUDE_DIRS}/asio/include)
        message(STATUS "Found ASIO ${ASIO_INCLUDE_DIR}")
        include_directories(${ASIO_INCLUDE_DIR})
        add_definitions(-DASIO_STANDALONE) 
    else()
        message(STATUS "ASIO not required")
    endif ()

    list (APPEND opendht_SOURCES
        src/base64.h
        src/base64.cpp
    )
    add_definitions(-DOPENDHT_JSONCPP)

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
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-attributes -Wno-return-type -Wno-deprecated -Wno-deprecated-declarations -Wno-unknown-pragmas -Wall -Wextra -Wnon-virtual-dtor -pedantic-errors -fvisibility=hidden")
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
    include/opendht/rng.h
    include/opendht/infohash.h
    include/opendht/utils.h
    include/opendht/sockaddr.h
    include/opendht/crypto.h
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
if(BUILD_SHARED_LIBS)
    message(STATUS "Building SHARED opendht library")
    add_library(opendht SHARED ${opendht_SOURCES} ${opendht_HEADERS})
else()
    message(STATUS "Building STATIC opendht library")
    add_library(opendht STATIC ${opendht_SOURCES} ${opendht_HEADERS})
endif()
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

target_include_directories(opendht
                           PUBLIC
                           "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
                           "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

set_target_properties(opendht PROPERTIES OUTPUT_NAME "opendht")

if (MSVC)
    message(STATUS "Used GnuTLS library: ${GNUTLS_LIBRARIES}")
    message(STATUS "Used NETTLE library: ${NETTLE_LIBRARY}")
    if(BUILD_SHARED_LIBS)
        target_link_libraries(opendht PRIVATE ${NETTLE_LIBRARY} unofficial::argon2::libargon2 msgpack-cxx PUBLIC jsoncpp_lib ${GNUTLS_LIBRARIES} unofficial::readline-win32::readline fmt::fmt wsock32 ws2_32)
    else()
        find_library(TASN1_LIBRARY NAMES tasn1 libtasn1 tasn1d REQUIRED) # Workaround for vcpkg directory misplacement
        target_link_libraries(opendht PUBLIC ${Win32_STATIC_LIBRARIES} ${Win32_IMPORT_LIBRARIES} ${GNUTLS_LIBRARIES} ${NETTLE_LIBRARY} ${TASN1_LIBRARY} unofficial::argon2::libargon2 jsoncpp_static fmt::fmt-header-only wsock32 ws2_32)
        set_target_properties(opendht PROPERTIES 
			OUTPUT_NAME "libopendht"
			MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
		)
    endif()
    if (OPENDHT_HTTP)
        target_link_libraries(opendht
            PUBLIC restinio::restinio
            PRIVATE llhttp::llhttp_static)
        if (OPENDHT_PROXY_OPENSSL)
            target_link_libraries(opendht PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        endif()
        target_link_libraries(opendht PUBLIC llhttp::llhttp_static)
    endif()
else()
    if (APPLE)
        target_link_libraries(opendht PRIVATE "-framework CoreFoundation" "-framework Security")
    endif ()
    if (NOT HAVE_MSGPACKCXX)
        target_link_libraries(opendht PUBLIC ${MSGPACK_TARGET})
    endif()
    if (WIN32 AND MINGW) # MSYS2
        if (BUILD_SHARED_LIBS)
            target_link_libraries(opendht PRIVATE argon2 nettle msgpack-cxx PUBLIC ${CMAKE_THREAD_LIBS_INIT} fmt::fmt ${GNUTLS_LIBRARIES} jsoncpp wsock32 ws2_32)
        else ()
            target_link_libraries(opendht PRIVATE argon2 nettle msgpack-cxx PUBLIC ${Win32_STATIC_LIBRARIES} ${Win32_IMPORT_LIBRARIES} jsoncpp fmt::fmt-header-only ${GNUTLS_LIBRARIES} wsock32 ws2_32)
        endif ()
        if (OPENDHT_HTTP)
            target_link_libraries(opendht
                PUBLIC restinio::restinio)
            if (OPENDHT_PROXY_OPENSSL)
                target_link_libraries(opendht PUBLIC ${OPENSSL_LIBRARIES})
            endif()
            if(BUILD_SHARED_LIBS)
                target_link_libraries(opendht PRIVATE llhttp_shared)
            else()
                target_link_libraries(opendht PRIVATE llhttp_static)
            endif()
        endif()
    else ()
        target_link_libraries(opendht
            PRIVATE
            PkgConfig::argon2
            PkgConfig::Nettle
            PUBLIC
            ${CMAKE_THREAD_LIBS_INIT}
            PkgConfig::GnuTLS
            fmt::fmt
        )
    if(OPENDHT_TOOLS)
        target_link_libraries(opendht PUBLIC ${READLINE_LIBRARIES})
    endif()
    endif()
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
else ()
    target_compile_definitions(opendht PRIVATE OPENDHT_STATIC) # to build library with default class attributes
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
    if(OPENDHT_TOOLS)
        target_link_libraries(opendht-c PUBLIC ${READLINE_LIBRARIES})
    endif()
    if (BUILD_SHARED_LIBS)
        target_compile_definitions(opendht-c PRIVATE OPENDHT_C_BUILD)
        target_compile_definitions(opendht-c PUBLIC opendht_c_EXPORTS)
        set_target_properties (opendht-c PROPERTIES SOVERSION ${opendht_VERSION_MAJOR} VERSION ${opendht_VERSION})
    endif()
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
if(MSVC AND BUILD_SHARED_LIBS)
    install(FILES $<TARGET_PDB_FILE:opendht> CONFIGURATIONS "RelWithDebInfo" "Debug" DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

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
