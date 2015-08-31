echo off
IF NOT "%1"=="" cd %1

set _CYGBIN=C:\cygwin64\bin
if not exist "%_CYGBIN%" goto errNotFoundDir

echo Copying temp files...
copy  ..\sys\modules\netmap\gen-version  gen-version-dos

echo Executing scripts...
%_CYGBIN%\dos2unix gen-version-dos
%_CYGBIN%\bash ./win-script.sh

:clear
echo Cleaning directory...
del gen-version-dos
del netmap_version.h.tmp
goto last

:errNotFoundDir
 echo Couldn't find Cygwin at "%_CYGBIN%"

:last
 