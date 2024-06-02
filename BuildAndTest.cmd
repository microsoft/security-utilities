@echo off
time /T

pushd .\src\security_utilities_rust\
call cargo clean --release
call cargo test --release
if "%ERRORLEVEL%" NEQ "0" (
  echo "security_utilities_rust testing failed..."
  exit /b %ERRORLEVEL%
)
popd

pushd .\src\security_utilities_rust_ffi\
call cargo clean --release
call cargo test --release
if "%ERRORLEVEL%" NEQ "0" (
  echo "security_utilities_rust_ffi testing failed..."
  exit /b %ERRORLEVEL%
)
popd


pushd .\src\security_utilities_rust_ffi\
call cargo clean --release
call cargo build --release
if "%ERRORLEVEL%" NEQ "0" (
  echo "security_utilities_rust_ffi build failed..."
  exit /b %ERRORLEVEL%
)
popd

xcopy /Y .\src\security_utilities_rust_ffi\target\release\microsoft_security_utilities_core.dll .\refs
xcopy /Y .\src\security_utilities_rust_ffi\target\release\microsoft_security_utilities_core.pdb .\refs

call powershell -ExecutionPolicy RemoteSigned -File %~dp0\scripts\BuildAndTest.ps1 %*
set result=%ERRORLEVEL%
time /T
echo %RESULT%

exit /b %RESULT%