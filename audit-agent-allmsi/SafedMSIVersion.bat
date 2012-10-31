@echo off
if EXIST Safed32.msi move Safed32.msi Safed_32_%1.msi 
if EXIST Safed64.msi move Safed64.msi Safed_64_%1.msi 
if EXIST Safed_%1 rmdir/S/Q Safed_%1
mkdir Safed_%1
if EXIST Safed_32_%1.msi copy Safed_32_%1.msi Safed_%1
if EXIST Safed_64_%1.msi copy Safed_64_%1.msi Safed_%1
if EXIST SafedInstall.bat copy SafedInstall.bat Safed_%1
if EXIST SafedUninstall.bat copy SafedUninstall.bat Safed_%1
