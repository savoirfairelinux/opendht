set BUILD=%SRC%..\build

set NETTLE_VERSION=4e0b2723b76d4163fa37b2b456d41534154ec97c
set NETTLE_URL=https://github.com/ShiftMediaProject/nettle/archive/%NETTLE_VERSION%.tar.gz

mkdir %BUILD%

if %USE_CACHE%==1 (
    copy %CACHE_DIR%\%NETTLE_VERSION%.tar.gz %cd%
) else (
    wget %NETTLE_URL%
)

7z -y x %NETTLE_VERSION%.tar.gz && 7z -y x %NETTLE_VERSION%.tar -o%BUILD%
del %NETTLE_VERSION%.tar && del %NETTLE_VERSION%.tar.gz && del %BUILD%\pax_global_header
rename %BUILD%\nettle-%NETTLE_VERSION% nettle

cd %BUILD%\nettle

git apply --reject --whitespace=fix %SRC%\nettle\nettle-uwp.patch

cd %SRC%