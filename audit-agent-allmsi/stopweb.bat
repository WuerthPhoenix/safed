@echo off
echo WARNING: This will disable the Remote Control Interface.
echo ****************
echo Please exit now if you do NOT want to go ahead!
echo ****************
pause
reg add "HKLM\Software\Wuerth Phoenix\AuditService\Remote" /v Allow /t REG_DWORD /d 0 /f
net stop safed
net start safed
