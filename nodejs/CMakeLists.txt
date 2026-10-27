cmake_minimum_required(VERSION 3.21)
project(opendht_node LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(OPENDHT_TOOLS OFF CACHE BOOL "Build DHT tools")
set(OPENDHT_PYTHON OFF CACHE BOOL "Build Python bindings")
set(OPENDHT_PEER_DISCOVERY OFF CACHE BOOL "Enable multicast peer discovery")
set(OPENDHT_DOCUMENTATION OFF CACHE BOOL "Build documentation")
set(BUILD_TESTING OFF CACHE BOOL "Build native tests")
add_subdirectory(.. native EXCLUDE_FROM_ALL)

find_program(NODE_EXECUTABLE node REQUIRED)
execute_process(
    COMMAND "${NODE_EXECUTABLE}" --input-type=module -e "import addon from 'node-addon-api'; process.stdout.write(addon.include_dir)"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE NODE_ADDON_API_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)

add_library(opendht_node MODULE addon.cpp crypto.cpp ${CMAKE_JS_SRC})
target_compile_definitions(opendht_node PRIVATE NAPI_VERSION=8 NAPI_CPP_EXCEPTIONS)
target_include_directories(opendht_node PRIVATE
    ${CMAKE_JS_INC}
    "${CMAKE_CURRENT_SOURCE_DIR}/${NODE_ADDON_API_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_BINARY_DIR}/native/include"
)
target_link_libraries(opendht_node PRIVATE opendht ${CMAKE_JS_LIB})
if(OPENDHT_SANITIZE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(opendht_node PRIVATE -fsanitize=address -fstack-protector-strong)
    target_link_options(opendht_node PRIVATE -fsanitize=address)
endif()
set_target_properties(opendht_node PROPERTIES
    PREFIX ""
    SUFFIX ".node"
    OUTPUT_NAME "opendht"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/$<CONFIG>"
)
if(APPLE)
    target_link_options(opendht_node PRIVATE "-undefined" "dynamic_lookup")
endif()
if(WIN32)
    add_custom_command(TARGET opendht_node POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:opendht_node> $<TARGET_FILE_DIR:opendht_node>
        COMMAND_EXPAND_LISTS
    )
endif()
if(MSVC)
    target_compile_options(opendht_node PRIVATE /EHsc)
    target_include_directories(opendht_node PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/compat/msvc"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src/compat/win32"
    )
    if(CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
        execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF}
            /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
    endif()
endif()