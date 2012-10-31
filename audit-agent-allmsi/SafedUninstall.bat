@echo off
IF "%PROCESSOR_ARCHITECTURE%"=="x86" goto is32
for /f %%a in ('dir/b Safed_64*.msi') do (
set str=%%a
)
msiexec /x %str%
goto EOF
:is32
for /f %%a in ('dir/b Safed_32*.msi') do (
set str=%%a
)
msiexec /x %str%
:EOF


