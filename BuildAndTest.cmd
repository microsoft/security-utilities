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
call cargo build --release --target x86_64-pc-windows-msvc
if "%ERRORLEVEL%" NEQ "0" (
  echo "security_utilities_rust_ffi build failed for x86_64-pc-windows-msvc target..."
  exit /b %ERRORLEVEL%
)
call cargo build --release --target i686-pc-windows-msvc
if "%ERRORLEVEL%" NEQ "0" (
  echo "security_utilities_rust_ffi build failed for i686-pc-windows-msvc target..."
  exit /b %ERRORLEVEL%
)

popd

xcopy /Y .\src\security_utilities_rust_ffi\target\i686-pc-windows-msvc\release\microsoft_security_utilities_core.dll .\refs\win-x86\
xcopy /Y .\src\security_utilities_rust_ffi\target\i686-pc-windows-msvc\release\microsoft_security_utilities_core.pdb .\refs\win-x86\
xcopy /Y .\src\security_utilities_rust_ffi\target\x86_64-pc-windows-msvc\release\microsoft_security_utilities_core.dll .\refs\win-x64\
xcopy /Y .\src\security_utilities_rust_ffi\target\x86_64-pc-windows-msvc\release\microsoft_security_utilities_core.pdb .\refs\win-x64\

call powershell -ExecutionPolicy RemoteSigned -File %~dp0\scripts\BuildAndTest.ps1 %*
set result=%ERRORLEVEL%
time /T
echo %RESULT%

exit /b %RESULT%