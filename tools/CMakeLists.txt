if (MSVC)
    set (MSC_COMPAT_DIR ../src/compat/msvc)
    set (MSC_COMPAT_SOURCES ${MSC_COMPAT_DIR}/wingetopt.c)
    find_library(ws2_32_LIB ws2_32)
endif()

function (configure_tool name extra_files)
    add_executable (${name} ${name}.cpp ${extra_files})
    add_dependencies(${name} opendht)
    target_link_libraries (${name} LINK_PUBLIC opendht ${READLINE_LIBRARIES})
    if (NOT BUILD_SHARED_LIBS)
        target_compile_definitions(${name} PRIVATE OPENDHT_STATIC) # to define proper attributes for the opendht classes
    endif()
    if (MSVC)
        target_sources(${name} PRIVATE ${MSC_COMPAT_SOURCES})
        target_link_libraries (${name} LINK_PUBLIC ${ws2_32_LIB})
        target_include_directories (${name} PRIVATE ${MSC_COMPAT_DIR})
    endif ()
endfunction ()

configure_tool (dhtnode tools_common.h)
configure_tool (dhtscanner tools_common.h)
configure_tool (dhtchat tools_common.h)
if (NOT MSVC)
    configure_tool (perftest tools_common.h)
endif ()
if (OPENDHT_HTTP)
    configure_tool (durl tools_common.h)
endif ()

if (OPENDHT_C)
    add_executable (dhtcnode dhtcnode.c)
    add_dependencies(dhtcnode opendht-c)
    target_link_libraries (dhtcnode LINK_PUBLIC opendht-c ${READLINE_LIBRARIES})
    target_include_directories (dhtcnode SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/c)
endif ()

if (NOT DEFINED CMAKE_INSTALL_BINDIR)
    set(CMAKE_INSTALL_BINDIR bin)
endif ()

install (TARGETS dhtnode dhtscanner dhtchat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(MSVC)
    install(FILES $<TARGET_PDB_FILE:dhtnode> $<TARGET_PDB_FILE:dhtscanner> $<TARGET_PDB_FILE:dhtchat> CONFIGURATIONS "Debug" "RelWithDebInfo" DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if (OPENDHT_SYSTEMD)
    if (NOT DEFINED OPENDHT_SYSTEMD_UNIT_FILE_LOCATION OR NOT OPENDHT_SYSTEMD_UNIT_FILE_LOCATION)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} systemd --variable=systemdsystemunitdir
                        OUTPUT_VARIABLE SYSTEMD_UNIT_INSTALL_DIR)
        message("-- Using Systemd unit installation directory by pkg-config: " ${SYSTEMD_UNIT_INSTALL_DIR})
    else()
        message("-- Using Systemd unit installation directory requested: " ${OPENDHT_SYSTEMD_UNIT_FILE_LOCATION})
        set(SYSTEMD_UNIT_INSTALL_DIR ${OPENDHT_SYSTEMD_UNIT_FILE_LOCATION})
    endif()

    configure_file (
        systemd/dhtnode.service.in
        systemd/dhtnode.service
        @ONLY
    )
    if (SYSTEMD_UNIT_INSTALL_DIR)
        string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNIT_INSTALL_DIR "${SYSTEMD_UNIT_INSTALL_DIR}")
        set (systemdunitdir "${SYSTEMD_UNIT_INSTALL_DIR}")
        install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dhtnode.service DESTINATION ${systemdunitdir})
        install (FILES systemd/dhtnode.conf DESTINATION ${sysconfdir})
    else()
        message(WARNING "Systemd unit installation directory not found. The systemd unit won't be installed.")
    endif()

    if (OPENDHT_PYTHON)
        configure_file (
            systemd/dhtcluster.service.in
            systemd/dhtcluster.service
            @ONLY
        )
        if (SYSTEMD_UNIT_INSTALL_DIR)
            install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dhtcluster.service DESTINATION ${systemdunitdir})
            install (FILES systemd/dhtcluster.conf DESTINATION ${sysconfdir})
        endif()
    endif()
endif ()
