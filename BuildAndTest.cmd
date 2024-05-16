@echo off
time /T

pushd .\src\security_utilities_rust_ffi\
call cargo build --release
popd
xcopy /Y .\src\security_utilities_rust_ffi\target\release\microsoft_security_utilities_core.dll .\refs
xcopy /Y .\src\security_utilities_rust_ffi\target\release\microsoft_security_utilities_core.pdb .\refs

powershell -ExecutionPolicy RemoteSigned -File %~dp0\scripts\BuildAndTest.ps1 %*
set result=%ERRORLEVEL%
time /T
echo %RESULT%

exit /b %RESULT%