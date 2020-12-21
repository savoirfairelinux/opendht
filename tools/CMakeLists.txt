if (OPENDHT_SHARED)
    set (OPENDHT_LIBS opendht)
else ()
    set (OPENDHT_LIBS opendht-static)
    if (MSVC)
        set (MSC_COMPAT_SOURCES ${MSC_COMPAT_DIR}/wingetopt.c)
    endif ()
endif ()

function (configure_tool name extra_files)
    add_executable (${name} ${name}.cpp ${extra_files})
    target_link_libraries (${name} LINK_PUBLIC ${READLINE_LIBRARIES})
    target_link_libraries (${name} LINK_PUBLIC ${OPENDHT_LIBS})
    if (MSVC)
        target_sources(${name} PRIVATE ${MSC_COMPAT_SOURCES})
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
    target_link_libraries (dhtcnode LINK_PUBLIC opendht-c ${READLINE_LIBRARIES})
endif ()

if (NOT DEFINED CMAKE_INSTALL_BINDIR)
    set(CMAKE_INSTALL_BINDIR bin)
endif ()

install (TARGETS dhtnode dhtscanner dhtchat RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if (OPENDHT_SYSTEMD)
    if (NOT DEFINED OPENDHT_SYSTEMD_UNIT_FILE_LOCATION)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} systemd --variable=systemdsystemunitdir
                        OUTPUT_VARIABLE SYSTEMD_UNIT_INSTALL_DIR)
        message("-- Using Systemd unit installation directory by pkg-config: " ${SYSTEMD_UNIT_INSTALL_DIR})
    else()
        message("-- Using Systemd unit installation directory requested: " ${OPENDHT_SYSTEMD_UNIT_FILE_LOCATION})
        set(SYSTEMD_UNIT_INSTALL_DIR ${OPENDHT_SYSTEMD_UNIT_FILE_LOCATION})
    endif()
    string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNIT_INSTALL_DIR "${SYSTEMD_UNIT_INSTALL_DIR}")
    set (systemdunitdir "${SYSTEMD_UNIT_INSTALL_DIR}")

    configure_file (
        systemd/dhtnode.service.in
        systemd/dhtnode.service
        @ONLY
    )
    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dhtnode.service DESTINATION ${systemdunitdir})
    install (FILES systemd/dhtnode.conf DESTINATION ${sysconfdir})
    if (OPENDHT_PYTHON)
        configure_file (
            systemd/dhtcluster.service.in
            systemd/dhtcluster.service
            @ONLY
        )
        install (FILES ${CMAKE_CURRENT_BINARY_DIR}/systemd/dhtcluster.service DESTINATION ${systemdunitdir})
        install (FILES systemd/dhtcluster.conf DESTINATION ${sysconfdir})
    endif()
endif ()
