@echo off
REM Wraps a command in the VS 18 x64 developer environment so ninja/cl can find
REM the MSVC headers and libs. Usage: tools\build-env.cmd ninja -C build slop_tests
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
%*
