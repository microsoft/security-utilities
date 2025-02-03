@echo off
setlocal

time /t
set RESULT=1

call "%~dp0BuildAndTestRust.cmd" %*
set RESULT=%ERRORLEVEL%
if %RESULT% neq 0 goto :exit

call powershell -ExecutionPolicy RemoteSigned -File "%~dp0scripts\BuildAndTest.ps1" %*
set RESULT=%ERRORLEVEL%
if %RESULT% neq 0 goto :exit

:exit
time /t
echo %RESULT%
exit /b %RESULT%
