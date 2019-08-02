if (NOT Crypto_FOUND)
    find_package(PkgConfig)
    if (PKG_CONFIG_FOUND)
        pkg_search_module(Crypto REQUIRED libcrypto)
    endif()
    find_library (Crypto_LIBRARY
                  NAMES crypto
                  HINTS ${Crypto_ROOT_DIR}
                        ${CMAKE_INSTALL_PREFIX}/lib
                        ${CMAKE_INSTALL_PREFIX}/lib64
                  PATHS /usr/local/lib
                        /usr/lib
    )
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Crypto DEFAULT_MSG Crypto_LIBRARY)
    if (Crypto_LIBRARY)
        set(Crypto_LIBRARIES ${Crypto_LIBRARY})
        message("Found libcrypto library: " ${Crypto_LIBRARIES})
        set(Crypto_FOUND TRUE)
    endif()
endif()
