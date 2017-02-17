set BUILD=%SRC%..\build

set ZLIB_VERSION=3a062eb61d0c3d4aa30851cd1a6597b977b56597
set ZLIB_URL=https://github.com/ShiftMediaProject/zlib/archive/%ZLIB_VERSION%.tar.gz

mkdir %BUILD%

if %USE_CACHE%==1 (
    copy %CACHE_DIR%\%ZLIB_VERSION%.tar.gz %cd%
) else (
    wget %ZLIB_URL%
)

7z -y x %ZLIB_VERSION%.tar.gz && 7z -y x %ZLIB_VERSION%.tar -o%BUILD%
del %ZLIB_VERSION%.tar && del %ZLIB_VERSION%.tar.gz && del %BUILD%\pax_global_header
rename %BUILD%\zlib-%ZLIB_VERSION% zlib

cd %BUILD%\zlib

git apply --reject --whitespace=fix %SRC%\zlib\zlib-uwp.patch

cd %SRC%