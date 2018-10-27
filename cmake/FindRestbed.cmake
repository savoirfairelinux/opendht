if(NOT Restbed_FOUND)
    find_path (Restbed_INCLUDE_DIR restbed
               HINTS
               "/usr/include"
               "/usr/local/include"
               "/opt/local/include")
    find_library(Restbed_LIBRARY restbed
                 HINTS ${Restbed_ROOT_DIR} PATH_SUFFIXES lib)
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Restbed DEFAULT_MSG Restbed_LIBRARY Restbed_INCLUDE_DIR)
    if (Restbed_INCLUDE_DIR)
        set(Restbed_FOUND TRUE)
        set(Restbed_LIBRARIES ${Restbed_LIBRARY})
        set(Restbed_INCLUDE_DIRS ${Restbed_INCLUDE_DIR})
    endif()
endif()
