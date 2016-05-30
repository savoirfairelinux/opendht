@ECHO OFF
SETLOCAL EnableDelayedExpansion

SET UPSTREAMURL=https://github.com/ShiftMediaProject
SET DEPENDENCIES=( ^
gmp, ^
gnutls, ^
nettle ^
)

SET PASSDEPENDENCIES=%~1

git status >NUL 2>&1
IF %ERRORLEVEL% EQU 128 (
    git init
) ELSE (
    IF %ERRORLEVEL% EQU 9009 (
        ECHO git not installed.
        EXIT /B 1
    )
)

SET CURRDIR=%~dp1

cd ..\..
FOR %%I IN %DEPENDENCIES% DO (
    ECHO !PASSDEPENDENCIES! | FINDSTR /C:"%%I" >NUL 2>&1 || (
        CALL :cloneOrUpdateRepo "%%I" )
)
cd %CURRDIR% >NUL
GOTO exit

:cloneOrUpdateRepo
SET REPONAME=%~1
IF NOT EXIST "%REPONAME%" (
    ECHO %REPONAME%: Existing folder not found. Cloning repository...
    SET REPOURL=%UPSTREAMURL%/%REPONAME%.git
    git clone !REPOURL! --quiet
    cd %REPONAME%
    git config --local core.autocrlf false
    git rm --cached -r . --quiet
    git reset --hard --quiet
    cd ..\
)

SET PASSDEPENDENCIES=%PASSDEPENDENCIES% %REPONAME%

IF EXIST "%REPONAME%\SMP\project_get_dependencies.bat" (
    ECHO %REPONAME%: Found additional dependencies...
    ECHO.
    cd %REPONAME%\SMP
    project_get_dependencies.bat "!PASSDEPENDENCIES!" || GOTO exitOnError
    cd ..\..
)
ECHO.
EXIT /B %ERRORLEVEL%

:exitOnError
cd %CURRDIR%

:exit
(
    ENDLOCAL
    SET PASSDEPENDENCIES=%PASSDEPENDENCIES%
)
    
ECHO %CMDCMDLINE% | FINDSTR /L %COMSPEC% >NUL 2>&1
IF %ERRORLEVEL% == 0 IF "%~1"=="" PAUSE

cd ..\..
IF NOT EXIST "msgpack-c" (
    ECHO msgpack-c: Existing folder not found. Cloning repository...
    git clone https://github.com/atraczyk/msgpack-c.git --quiet
    cd msgpack-c
    git config --local core.autocrlf false
    git rm --cached -r . --quiet
    git reset --hard --quiet
    cd ..\
)

EXIT /B 0