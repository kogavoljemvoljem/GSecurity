@echo off

:: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Perms
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r
icacls "%systemdrive%\Users" /remove "Everyone"
takeown /f "%USERPROFILE%\Desktop" /A /R /D y
icacls "%USERPROFILE%\Desktop" /reset
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c
takeown /f "C:\Users\Public\Desktop" /A /R /D y
icacls "C:\Users\Public\Desktop" /reset
icacls "C:\Users\Public\Desktop" /inheritance:r
icacls "C:\Users\Public\Desktop" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c
takeown /f "C:\Windows\System32\wbem" /A
icacls "C:\Windows\System32\wbem" /reset
icacls "C:\Windows\System32\wbem" /inheritance:r
takeown /f "C:\Program Files (x86)\Common Files\Microsoft Shared" /A /R /D y
icacls "C:\Program Files (x86)\Common Files\Microsoft Shared" /reset
icacls "C:\Program Files (x86)\Common Files\Microsoft Shared" /inheritance:r
icacls "C:\Program Files (x86)\Common Files\Microsoft Shared" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c
takeown /f "C:\Program Files\Common Files\Microsoft Shared" /A /R /D y
icacls "C:\Program Files\Common Files\Microsoft Shared" /reset
icacls "C:\Program Files\Common Files\Microsoft Shared" /inheritance:r
icacls "C:\Program Files\Common Files\Microsoft Shared" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c

:: Services
sc config seclogon start= disabled
sc stop seclogon

:: Users
net user defaultuser0 /delete

:: Script dir
cd /d %~dp0

:: Registry
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    reg import "%%C"
)

:: Ram Cleaner
copy /y emptystandbylist.exe %windir%\Setup\Scripts\Bin\emptystandbylist.exe
copy /y RamCleaner.bat %windir%\Setup\Scripts\Bin\RamCleaner.bat
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"

:: Restart
shutdown /r /t 0



