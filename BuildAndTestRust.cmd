@echo off
setlocal

set NO_TEST=0

:parse_args
set ARG=%1
if /i "%ARG%" == "-NoTest" set NO_TEST=1
if not "%ARG%" == "" shift & goto :parse_args

set STEP=Building security_utilities_rust for x64
echo %STEP%...
pushd .\src\security_utilities_rust\
call cargo build --release --target x86_64-pc-windows-msvc
if %ERRORLEVEL% neq 0 goto :exit
popd

set STEP=Building security_utilities_rust for x86
echo %STEP%...
pushd .\src\security_utilities_rust\
call cargo build --release --target i686-pc-windows-msvc 
if %ERRORLEVEL% neq 0 goto :exit
popd

set STEP=Testing security_utilities_rust for x64
if %NO_TEST% neq 1 (
  echo %STEP%...
  pushd .\src\security_utilities_rust\
  call cargo test --release --target x86_64-pc-windows-msvc
  if %ERRORLEVEL% neq 0 goto :exit
  popd
)

set STEP=Testing security_utilities_rust for x86
if %NO_TEST% neq 1 (
  echo %STEP%...
  pushd .\src\security_utilities_rust\
  call cargo test --release --target i686-pc-windows-msvc
  if %ERRORLEVEL% neq 0 goto :exit
  popd
)

:exit
if %ERRORLEVEL% neq 0 (
  echo ERROR: %STEP% failed.
)
exit /b %ERRORLEVEL%
