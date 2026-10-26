cmake_minimum_required(VERSION 3.21)

if(NOT EXISTS "${ADDON}" OR NOT DEFINED OUTPUT)
    message(FATAL_ERROR "ADDON and OUTPUT are required")
endif()

set(pre_exclude)
set(post_exclude)
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND pre_exclude "^/usr/lib/" "^/System/Library/")
    list(APPEND post_exclude "^/usr/lib/" "^/System/Library/")
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND pre_exclude "^ld-linux" "^lib(c|m|dl|rt|pthread|resolv|util|gcc_s|stdc\\+\\+)\\.so")
elseif(CMAKE_HOST_WIN32)
    list(APPEND pre_exclude "[Nn][Oo][Dd][Ee]\\.exe" "[Aa][Pp][Ii]-[Mm][Ss]-.*" "[Ee][Xx][Tt]-[Mm][Ss]-.*")
    list(APPEND post_exclude ".*[Ss][Yy][Ss][Tt][Ee][Mm]32[/\\\\].*")
endif()

file(GET_RUNTIME_DEPENDENCIES
    MODULES "${ADDON}"
    DIRECTORIES ${SEARCH_DIRECTORIES}
    RESOLVED_DEPENDENCIES_VAR dependencies
    UNRESOLVED_DEPENDENCIES_VAR unresolved
    CONFLICTING_DEPENDENCIES_PREFIX conflicts
    PRE_EXCLUDE_REGEXES ${pre_exclude}
    POST_EXCLUDE_REGEXES ${post_exclude}
)
if(unresolved OR conflicts_FILENAMES)
    message(FATAL_ERROR "Unresolved dependencies: ${unresolved}; conflicting dependencies: ${conflicts_FILENAMES}")
endif()

set(result "[]")
set(index 0)
foreach(dependency IN LISTS dependencies)
    file(TO_CMAKE_PATH "${dependency}" dependency)
    string(JSON result SET "${result}" ${index} "\"${dependency}\"")
    math(EXPR index "${index} + 1")
endforeach()
file(WRITE "${OUTPUT}" "${result}\n")