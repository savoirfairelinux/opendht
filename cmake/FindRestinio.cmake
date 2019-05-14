# header-only does not produce a library
if(NOT Restinio_FOUND)
    find_path (Restinio_INCLUDE_DIR restinio
               HINTS
               "/usr/include"
               "/usr/local/include"
               "/opt/local/include")
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Restinio DEFAULT_MSG Restinio_INCLUDE_DIR)
    if (Restinio_INCLUDE_DIR)
        set(Restinio_FOUND TRUE)
        set(Restinio_INCLUDE_DIRS ${Restinio_INCLUDE_DIR})
    endif()
endif()
