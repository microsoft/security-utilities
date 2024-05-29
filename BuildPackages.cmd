@echo off
powershell -ExecutionPolicy RemoteSigned -File %~dp0\scripts\BuildPackages.ps1 %*
