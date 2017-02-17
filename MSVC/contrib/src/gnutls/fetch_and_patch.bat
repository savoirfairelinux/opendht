set BUILD=%SRC%..\build

set GNUTLS_VERSION=f2d0ade53ff644da55244aed79d05eca78d11a2f
set GNUTLS_URL=https://github.com/ShiftMediaProject/gnutls/archive/%GNUTLS_VERSION%.tar.gz

mkdir %BUILD%

if %USE_CACHE%==1 (
    copy %CACHE_DIR%\%GNUTLS_VERSION%.tar.gz %cd%
) else (
    wget %GNUTLS_URL%
)

7z -y x %GNUTLS_VERSION%.tar.gz && 7z -y x %GNUTLS_VERSION%.tar -o%BUILD%
del %GNUTLS_VERSION%.tar && del %GNUTLS_VERSION%.tar.gz && del %BUILD%\pax_global_header
rename %BUILD%\gnutls-%GNUTLS_VERSION% gnutls

cd %BUILD%\gnutls

git apply --reject --whitespace=fix %SRC%\gnutls\gnutls-no-egd.patch
git apply --reject --whitespace=fix %SRC%\gnutls\read-file-limits.h.patch
git apply --reject --whitespace=fix %SRC%\gnutls\gnutls-uwp.patch

cd %SRC%