@echo off
setlocal

set NO_TEST=0

:parse_args
set ARG=%1
if /i "%ARG%" == "-NoTest" set NO_TEST=1
if not "%ARG%" == "" shift & goto :parse_args

set STEP=Building security_utilities_rust_ffi for x64
echo %STEP%...
pushd .\src\security_utilities_rust_ffi\
call cargo build --release --target x86_64-pc-windows-msvc
if %ERRORLEVEL% neq 0 goto :exit
popd

set STEP=Building security_utilities_rust_ffi for x86
echo %STEP%...
pushd .\src\security_utilities_rust_ffi\
call cargo build --release --target i686-pc-windows-msvc 
if %ERRORLEVEL% neq 0 goto :exit
popd

set STEP=Deploying security_utilities_rust_ffi
echo %STEP%...
xcopy /y .\src\security_utilities_rust_ffi\target\x86_64-pc-windows-msvc\release\microsoft_security_utilities_core.dll .\refs\win-x64\
if %ERRORLEVEL% neq 0 goto :exit
xcopy /y .\src\security_utilities_rust_ffi\target\x86_64-pc-windows-msvc\release\microsoft_security_utilities_core.pdb .\refs\win-x64\
if %ERRORLEVEL% neq 0 goto :exit
xcopy /y .\src\security_utilities_rust_ffi\target\i686-pc-windows-msvc\release\microsoft_security_utilities_core.dll .\refs\win-x86\
if %ERRORLEVEL% neq 0 goto :exit
xcopy /y .\src\security_utilities_rust_ffi\target\i686-pc-windows-msvc\release\microsoft_security_utilities_core.pdb .\refs\win-x86\
if %ERRORLEVEL% neq 0 goto :exit

set STEP=Testing security_utilities_rust
if %NO_TEST% neq 1 (
  echo %STEP%...
  pushd .\src\security_utilities_rust\
  call cargo test --release 
  if %ERRORLEVEL% neq 0 goto :exit
  popd
)

:exit
if %ERRORLEVEL% neq 0 (
  echo ERROR: %STEP% failed.
)
exit /b %ERRORLEVEL%
