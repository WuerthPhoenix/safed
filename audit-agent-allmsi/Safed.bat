@echo off
IF "%PROCESSOR_ARCHITECTURE%"=="x86" goto is32
del Safed_32*.msi
for /f %%a in ('dir/b Safed_64*.msi') do (
set str=%%a
)
msiexec /i %str
goto EOF
:is32
del Safed_64*.msi
for /f %%a in ('dir/b Safed_32*.msi') do (
set str=%%a
echo %str
)
msiexec /i %str
:EOF


