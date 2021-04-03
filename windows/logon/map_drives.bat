@echo off

NET USE /DELETE S:

SET REG_KEY=HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\
REG ADD "%REG_KEY%##192.168.200.3#Shared" /v _LabelFromReg /t REG_SZ /d SHARED /f

NET USE S: \\192.168.200.3\Shared /PERSISTENT:YES