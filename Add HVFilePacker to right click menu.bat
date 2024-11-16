@echo off
:: Check if the script is running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM Get the folder where the script is located
set "ScriptDir=%~dp0"

REM Define the name of the executable (must exist in the same folder)
set "ExeName=HVFilePacker.exe"

REM Define menu names
set "FileMenuName=Unpack with HVFilePacker"
set "FolderMenuName=Repack with HVFilePacker"

REM Check if the executable exists
if not exist "%ScriptDir%%ExeName%" (
    echo Error: "%ExeName%" not found in "%ScriptDir%"
    pause
    exit /b 1
)

REM Add registry entry for files
reg add "HKEY_CLASSES_ROOT\*\shell\%FileMenuName%" /ve /d "%FileMenuName%" /f
reg add "HKEY_CLASSES_ROOT\*\shell\%FileMenuName%\command" /ve /d "\"%ScriptDir%%ExeName%\" \"File: %%1\"" /f

REM Add registry entry for folders
reg add "HKEY_CLASSES_ROOT\Folder\shell\%FolderMenuName%" /ve /d "%FolderMenuName%" /f
reg add "HKEY_CLASSES_ROOT\Folder\shell\%FolderMenuName%\command" /ve /d "\"%ScriptDir%%ExeName%\" \"Folder: %%1\"" /f

echo Context menu for files and folders added successfully.
pause
