@echo on
SETLOCAL EnableDelayedExpansion

set SRC=%~dp0

set PATH=%PATH%;%ProgramFiles(x86)%\MSBuild\14.0\Bin\

set MSBUILD_ARGS=/nologo /p:Configuration=Release /p:Platform=x64 /verbosity:normal /maxcpucount:%NUMBER_OF_PROCESSORS%

set TOBUILD=( ^
contrib\build\argon2\vs2015\Argon2Ref\Argon2Ref.vcxproj, ^
contrib\build\gmp\SMP\libgmp.vcxproj, ^
contrib\build\nettle\SMP\libnettle.vcxproj, ^
contrib\build\nettle\SMP\libhogweed.vcxproj, ^
contrib\build\libiconv\SMP\libiconv.vcxproj, ^
contrib\build\nettle\SMP\libiconv.vcxproj, ^
contrib\build\zlib\SMP\libzlib.vcxproj, ^
contrib\build\gnutls\SMP\libgnutls.vcxproj, ^
contrib\build\msgpack-c\msgpack_vc8.vcxproj, ^
opendht.vcxproj, ^
dhtchat.vcxproj, ^
dhtscanner.vcxproj, ^
dhtnode.vcxproj ^
)

for %%I in %TOBUILD% do (
    call :build "%SRC%%%I"
)

exit /B %ERRORLEVEL%

:build
echo "Building project: " %*
msbuild %* %MSBUILD_ARGS%
exit /B 0