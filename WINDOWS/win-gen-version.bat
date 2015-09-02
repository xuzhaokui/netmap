echo off

set PROG_LABEL=win-gen-version:

echo %PROG_LABEL% GENERATING netmap_version.h...
IF NOT "%1"=="" cd %1

echo %PROG_LABEL% Testing for 32bit Cygwin directory...
set _CYGBIN=C:\cygwin\bin
if exist "%_CYGBIN%" goto checking_executables

echo %PROG_LABEL% 32bit Cygwin not found, checking for 64 bits...
set _CYGBIN=C:\cygwin64\bin
if exist "%_CYGBIN%" goto checking_executables

echo %PROG_LABEL% 64bits not found, checking for common Cygwin directories...
IF "%CYGHOME%"=="" goto err_cygwin_not_found
set _CYGBIN="%CYGHOME%"

:checking_executables
echo %PROG_LABEL% Cygwin found! Checking for executables...
if not exist "%_CYGBIN%"\dos2unix.exe goto err_dos2unix_not_found
if not exist "%_CYGBIN%"\bash.exe goto err_bash_not_found

:main_procedure
if not exist ..\sys\modules\netmap\gen-version goto err_gen-version_not_found
echo %PROG_LABEL% Copying temp files...
copy  ..\sys\modules\netmap\gen-version  gen-version-dos

echo %PROG_LABEL% Executing scripts...
%_CYGBIN%\dos2unix gen-version-dos
%_CYGBIN%\bash ./win-script.sh

goto clean

:err_cygwin_not_found
echo %PROG_LABEL% Couldn't find Cygwin in standard paths. Aborting!!!
exit 1

:err_dos2unix_not_found
echo %PROG_LABEL% Couldn't find Dos2Unix executable. Aborting!!!
exit 2

:err_bash_not_found
echo %PROG_LABEL% Couldn't find Bash executable. Aborting!!!
exit 3

:err_gen-version_not_found
echo %PROG_LABEL% Couldn't find gen-version under sys\modules\netmap. Aborting!!!
exit 4

:clean
echo %PROG_LABEL% Cleaning directory...
del gen-version-dos
del netmap_version.h.tmp
 
