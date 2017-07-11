set BUILD=%SRC%..\build

set ARGON2_VERSION=1eea0104e7cb2a38c617cf90ffa46ce5db6aceda
set ARGON2_URL=https://github.com/P-H-C/phc-winner-argon2/archive/%ARGON2_VERSION%.tar.gz

mkdir %BUILD%

if %USE_CACHE%==1 (
    copy %CACHE_DIR%\%ARGON2_VERSION%.tar.gz %cd%
) else (
    wget %ARGON2_URL%
)

7z -y x %ARGON2_VERSION%.tar.gz && 7z -y x %ARGON2_VERSION%.tar -o%BUILD%
del %ARGON2_VERSION%.tar && del %ARGON2_VERSION%.tar.gz && del %BUILD%\pax_global_header
rename %BUILD%\phc-winner-argon2-%ARGON2_VERSION% argon2

cd %BUILD%\argon2

git apply --reject --whitespace=fix %SRC%\argon2\argon2-uwp.patch

cd %SRC%