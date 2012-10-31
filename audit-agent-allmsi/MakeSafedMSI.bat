@echo off

rem if NOT EXIST Safed.reg goto ERROR
if EXIST Safed.wixobj del Safed.wixobj
candle -v Safed.wxs %* -out Safed32.wixobj
candle -v Safed.wxs -dwin64 %* -out Safed64.wixobj



if NOT EXIST Safed32.wixobj goto ERROR
if NOT EXIST Safed64.wixobj goto ERROR
if EXIST Safed32.msi del Safed32.msi
if EXIST Safed64.msi del Safed64.msi
light -v Safed32.wixobj "\Program Files\wix\wixca.wixlib" -out Safed32.msi
if ERRORLEVEL 1 goto ERROR
light -v Safed64.wixobj "\Program Files\wix\wixca.wixlib" -out Safed64.msi
if ERRORLEVEL 1 goto ERROR
echo MSI build completed successfully
goto EOF
:ERROR
if EXIST Safed32.msi del Safed32.msi
if EXIST Safed64.msi del Safed64.msi
echo.
echo FAILED to create MSI
echo.
:EOF
