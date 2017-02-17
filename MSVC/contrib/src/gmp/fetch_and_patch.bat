set BUILD=%SRC%..\build

set GMP_VERSION=3c8f5a0ae0c2ac9ff0ea31b27f71b152979b556d
set GMP_URL=https://github.com/ShiftMediaProject/gmp/archive/%GMP_VERSION%.tar.gz

mkdir %BUILD%

if %USE_CACHE%==1 (
    copy %CACHE_DIR%\%GMP_VERSION%.tar.gz %cd%
) else (
    wget %GMP_URL%
)

7z -y x %GMP_VERSION%.tar.gz && 7z -y x %GMP_VERSION%.tar -o%BUILD%
del %GMP_VERSION%.tar && del %GMP_VERSION%.tar.gz && del %BUILD%\pax_global_header
rename %BUILD%\gmp-%GMP_VERSION% gmp

cd %BUILD%\gmp

git apply --reject --whitespace=fix %SRC%\gmp\gmp-uwp.patch

cd %SRC%