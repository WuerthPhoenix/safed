echo off

net stop Safed

rem #################### SET FIREWALL #############
ver | findstr /i "[Version\ 5" > nul
IF %ERRORLEVEL% EQU 0 goto ver_xp
ver | findstr /i "[Version\ 6" > nul
IF %ERRORLEVEL% EQU 0 goto ver_vista
ver | findstr /i "[Version\ 10" > nul
IF %ERRORLEVEL% EQU 0 goto ver_vista
goto warn

:ver_xp
netsh firewall add allowedprogram "%ProgramFiles%\Safed\Safed.exe" Safed ENABLE
goto endfirewall

:ver_vista
netsh advfirewall firewall add rule name="Safed" dir=in profile=any action=allow program="%ProgramFiles%\Safed\Safed.exe" enable=yes protocol=any
netsh advfirewall firewall add rule name="Safed" dir=out profile=any action=allow program="%ProgramFiles%\Safed\Safed.exe" enable=yes protocol=any
goto endfirewall



:warn
echo "MACHINE OS CANNOT BE DETERMINED!"

:endfirewall  
rem #################### SET FIREWALL - END #############

cd %~dp0

IF "%PROCESSOR_ARCHITECTURE%"=="x86" goto is32
del Safed_32*.msi 2> NUL
for /f %%a in ('dir/b Safed_64*.msi') do (
set str=%%a
)

goto INSTALL
:is32
del Safed_64*.msi 2> NUL
for /f %%a in ('dir/b Safed_32*.msi') do (
set str=%%a
)




:INSTALL

rem BACKUP REG VALUES
regedit.exe /e safedtmp.reg "HKEY_LOCAL_MACHINE\SOFTWARE\Wuerth Phoenix"


rem CHECK IF THE FILE IS EMPTY
set /a cnt=0
for /f %%a in ('type "safedtmp.reg"^|find "" /v /c') do set /a cnt=%%a
rem echo safedtmp.reg has %cnt% lines
rem CONTINUE ANYWAY?
IF %cnt% GTR 0 (
	rem #################### UPDATE WITH REGISTRY CFG BACKUP #############
	msiexec /i %str%
	net stop Safed
	regedit /s safedtmp.reg
	net start Safed
	goto EOF

)



echo "NO REG VALUES FOUND FOR SAFED"
set /P continue=NEW INSTALLATION OR CONTINUE ANYWAY? [y/n]
IF NOT "%continue%"=="y" goto EOF
rem #################### UPDATE WITH NO REGISTRY CFG BACKUP #############3
msiexec /i %str%

:EOF
rem del /P safedtmp.reg 2> NUL



