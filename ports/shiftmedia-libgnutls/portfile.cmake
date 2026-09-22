set(GNULIB_REF "1cc0125a28cba4e8503d853bf99b854fe4dd454c")

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO savoirfairelinux/gnutls
    REF f76d780a64830ab8298128f340a64996c272694c
    SHA512 2cc8868fcdaa5650aa0d58329a97e3a5a35574a3148eef182151b507d0abf549d5e9510af2739c2171ba5e4d51240a088c58e5be29bb392a2b752818dd9a93f4
    HEAD_REF fix/ci-msvc
    PATCHES
        external-libtasn1.patch
        pkgconfig.patch
)

file(REMOVE_RECURSE "${SOURCE_PATH}/devel/perlasm")

vcpkg_download_distfile(
    GNULIB_SNAPSHOT
    URLS "https://gitlab.com/libidn/gnulib-mirror/-/archive/${GNULIB_REF}/gnulib-mirror-${GNULIB_REF}.tar.gz"
    FILENAME "gnulib-mirror-${GNULIB_REF}.tar.gz"
    SHA512 340539bd7b8e30b1e0f81a15fb207960e9ae3c4ef515f39f1d1bdb43ed52ad94a29c6a6ce8bbca3484ba5392e1dae7447c2f6b58124209614e884345e13914f5
)

vcpkg_extract_source_archive(
    GNULIB_SOURCE_PATH
    ARCHIVE "${GNULIB_SNAPSHOT}"
    SOURCE_BASE ${GNULIB_REF}
)

file(REMOVE_RECURSE "${SOURCE_PATH}/gnulib")
file(RENAME "${GNULIB_SOURCE_PATH}" "${SOURCE_PATH}/gnulib")

include("${CURRENT_HOST_INSTALLED_DIR}/share/yasm-tool-helper/yasm-tool-helper.cmake")
yasm_tool_helper(OUT_VAR YASM)
file(TO_NATIVE_PATH "${YASM}" YASM)

if(VCPKG_LIBRARY_LINKAGE STREQUAL "dynamic")
    set(CONFIGURATION_RELEASE ReleaseDLL)
    set(CONFIGURATION_DEBUG DebugDLL)
else()
    set(CONFIGURATION_RELEASE Release)
    set(CONFIGURATION_DEBUG Debug)
endif()

if(VCPKG_TARGET_IS_UWP)
    string(APPEND CONFIGURATION_RELEASE WinRT)
    string(APPEND CONFIGURATION_DEBUG WinRT)
endif()

set(_gnutlsproject "${SOURCE_PATH}/SMP/libgnutls.vcxproj")
file(READ "${_gnutlsproject}" _contents)
string(REPLACE  [[<Import Project="$(VCTargetsPath)\BuildCustomizations\yasm.props" />]]
                    "<Import Project=\"${CURRENT_HOST_INSTALLED_DIR}/share/vs-yasm/yasm.props\" />"
                _contents "${_contents}")
string(REPLACE  [[<Import Project="$(VCTargetsPath)\BuildCustomizations\yasm.targets" />]]
                    "<Import Project=\"${CURRENT_HOST_INSTALLED_DIR}/share/vs-yasm/yasm.targets\" />"
                _contents "${_contents}")
string(REGEX REPLACE "${VCPKG_ROOT_DIR}/installed/[^/]+/share" "${CURRENT_HOST_INSTALLED_DIR}/share" _contents "${_contents}") # Above already
file(WRITE "${_gnutlsproject}" "${_contents}")

if(VCPKG_CRT_LINKAGE STREQUAL "static")
    set(RuntimeLibraryExt "")
else()
    set(RuntimeLibraryExt "DLL")
endif()

# patch output library file path and name
foreach(PROPS IN ITEMS
"${SOURCE_PATH}/SMP/smp_deps.props"
"${SOURCE_PATH}/SMP/smp_winrt_deps.props")
vcpkg_replace_string(
    "${PROPS}"
    [=[_winrt</TargetName>]=]
    [=[</TargetName>]=]
    IGNORE_UNCHANGED
)
vcpkg_replace_string(
    "${PROPS}"
    [=[<TargetName>lib$(RootNamespace)]=]
    [=[<TargetName>$(RootNamespace)]=]
)
endforeach()

# patch hogweed, gmp, nettle, zlib libraries file names; inject RuntimeLibrary property to control CRT linkage 
foreach(VCXPROJ IN ITEMS
"${SOURCE_PATH}/SMP/libgnutls.vcxproj"
"${SOURCE_PATH}/SMP/libgnutls_winrt.vcxproj")
vcpkg_replace_string(
    "${VCXPROJ}"
    "_winrt.lib"
    ".lib"
    IGNORE_UNCHANGED
)
vcpkg_replace_string(
    "${VCXPROJ}"
    "libhogweed"
    "hogweed"
)
vcpkg_replace_string(
    "${VCXPROJ}"
    "hogweedd"
    "hogweed"
)
vcpkg_replace_string(
    "${VCXPROJ}"
    "libgmp"
    "gmp"
)
vcpkg_replace_string(
    "${VCXPROJ}"
    "gmpd"
    "gmp"
)
vcpkg_replace_string(
    "${VCXPROJ}"
    "libnettle"
    "nettle"
)
vcpkg_replace_string(
    "${VCXPROJ}"
    "nettled"
    "nettle"
)
set(zlib_basename "zlib")
if(EXISTS "${CURRENT_INSTALLED_DIR}/lib/zs.lib")
    set(zlib_basename "zs")
elseif(EXISTS "${CURRENT_INSTALLED_DIR}/lib/z.lib")
    set(zlib_basename "z")
endif()
vcpkg_replace_string(
    "${VCXPROJ}"
    "libzlib"
    "${zlib_basename}"
)
vcpkg_replace_string(
    "${VCXPROJ}"
    "zlib"
    "${zlib_basename}"
)
vcpkg_replace_string(
    "${VCXPROJ}"
    [=[</DisableSpecificWarnings>]=]
    [=[</DisableSpecificWarnings><ForcedIncludeFiles>gnutls_msvc_fixes.h;%(ForcedIncludeFiles)</ForcedIncludeFiles><RuntimeLibrary>$(RuntimeLibrary)</RuntimeLibrary>]=]
)
endforeach()

vcpkg_install_msbuild(
    USE_VCPKG_INTEGRATION
    SOURCE_PATH "${SOURCE_PATH}"
    PROJECT_SUBPATH SMP/libgnutls.sln
    PLATFORM ${TRIPLET_SYSTEM_ARCH}
    LICENSE_SUBPATH LICENSE
    RELEASE_CONFIGURATION ${CONFIGURATION_RELEASE}
    DEBUG_CONFIGURATION ${CONFIGURATION_DEBUG}
    SKIP_CLEAN
    OPTIONS /p:YasmPath="${YASM}" /p:OutDir=..\\msvc
    OPTIONS_DEBUG /p:RuntimeLibrary=MultiThreadedDebug${RuntimeLibraryExt}
    OPTIONS_RELEASE /p:RuntimeLibrary=MultiThreaded${RuntimeLibraryExt}
)

get_filename_component(SOURCE_PATH_SUFFIX "${SOURCE_PATH}" NAME)
if(VCPKG_TARGET_IS_UWP)
    set(WINRT_SUBFOLDER libgnutls_winrt)
endif()
file(INSTALL "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel/${SOURCE_PATH_SUFFIX}/msvc/${WINRT_SUBFOLDER}/include" DESTINATION "${CURRENT_PACKAGES_DIR}")

set(GNUTLS_REQUIRES_PRIVATE "Requires.private: gmp, nettle, hogweed, libtasn1, zlib")
set(GNUTLS_LIBS_PRIVATE "-lcrypt32 -lws2_32 -lkernel32 -lncrypt")

set(prefix "${CURRENT_INSTALLED_DIR}")
set(exec_prefix "\${prefix}")
set(libdir "\${prefix}/lib")
set(includedir "\${prefix}/include")
set(GNUTLS_LIBS "-lgnutls")
configure_file("${SOURCE_PATH}/lib/gnutls.pc.in" "${CURRENT_PACKAGES_DIR}/lib/pkgconfig/gnutls.pc" @ONLY)

if(NOT VCPKG_BUILD_TYPE)
  set(prefix "${CURRENT_INSTALLED_DIR}/debug")
  set(exec_prefix "\${prefix}")
  set(libdir "\${prefix}/lib")
  set(includedir "\${prefix}/../include")
  set(GNUTLS_LIBS "-lgnutlsd")
  configure_file("${SOURCE_PATH}/lib/gnutls.pc.in" "${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig/gnutls.pc" @ONLY)
endif()

vcpkg_fixup_pkgconfig()
vcpkg_copy_pdbs()
file(COPY "${CURRENT_PORT_DIR}/vcpkg-cmake-wrapper.cmake" DESTINATION "${CURRENT_PACKAGES_DIR}/share/gnutls")
