set BUILD=%SRC%..\build

set MSGPACK_VERSION=1df97bc37b363a340c5ad06c5cbcc53310aaff80
set MSGPACK_URL=https://github.com/msgpack/msgpack-c/archive/%MSGPACK_VERSION%.tar.gz

mkdir %BUILD%

if %USE_CACHE%==1 (
    copy %CACHE_DIR%\%MSGPACK_VERSION%.tar.gz %cd%
) else (
    wget %MSGPACK_URL%
)

7z -y x %MSGPACK_VERSION%.tar.gz && 7z -y x %MSGPACK_VERSION%.tar -o%BUILD%
del %MSGPACK_VERSION%.tar && del %MSGPACK_VERSION%.tar.gz && del %BUILD%\pax_global_header
rename %BUILD%\msgpack-c-%MSGPACK_VERSION% msgpack-c

cd %BUILD%\msgpack-c

git apply --reject --whitespace=fix %SRC%\msgpack\msgpack-uwp.patch

cd %SRC%