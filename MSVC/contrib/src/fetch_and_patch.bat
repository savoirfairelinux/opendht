@echo OFF
SETLOCAL EnableDelayedExpansion

set SRC=%~dp0

if "%USE_CACHE%"=="" (
    set USE_CACHE=0
)

set DEPENDENCIES=( ^
argon2, ^
gmp, ^
gnutls, ^
iconv, ^
msgpack, ^
nettle, ^
opendht, ^
zlib ^
)

for %%I in %DEPENDENCIES% do (
    call %SRC%\%%I\fetch_and_patch.bat
)