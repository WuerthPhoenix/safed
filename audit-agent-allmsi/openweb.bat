@echo off
echo WARNING: This will open unauthenticated access to this agent, you should change the access rights immediately.
echo ****************
echo Please exit now if you do NOT want to go ahead!
echo ****************
pause
reg add "HKLM\Software\Wuerth Phoenix\AuditService\Remote" /v Allow /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Wuerth Phoenix\AuditService\Remote" /v Restrict /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Wuerth Phoenix\AuditService\Remote" /v AccessKey /t REG_DWORD /d 0 /f
net stop safed
net start safed
