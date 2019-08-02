if (NOT OpenSSL_FOUND)
    find_path (OpenSSL_INCLUDE_DIR openssl
               HINTS
               "/usr/include"
               "/usr/local/include"
               "/opt/local/include")
    find_library (OpenSSL_LIBRARY
                  NAMES ssl openssl
                  HINTS ${OpenSSL_ROOT_DIR}
                        ${CMAKE_INSTALL_PREFIX}/lib
                        ${CMAKE_INSTALL_PREFIX}/lib64
                  PATHS /usr/local/lib
                        /usr/lib
    )
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(OpenSSL DEFAULT_MSG OpenSSL_INCLUDE_DIR OpenSSL_LIBRARY)
    if (OpenSSL_INCLUDE_DIR AND OpenSSL_LIBRARY)
        message("Found OpenSSL library: " ${OpenSSL_LIBRARY})
        message("Found OpenSSL includes: " ${OpenSSL_INCLUDE_DIR})
        set(OpenSSL_FOUND TRUE)
    endif()
endif()
