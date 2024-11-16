@echo off
:: Check if the script is running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM Define the menu names to remove
set "FileMenuName=Unpack with HVFilePacker"
set "FolderMenuName=Repack with HVFilePacker"

REM Remove registry entries for files
reg delete "HKEY_CLASSES_ROOT\*\shell\%FileMenuName%" /f

REM Remove registry entries for folders
reg delete "HKEY_CLASSES_ROOT\Folder\shell\%FolderMenuName%" /f

echo Context menu for files and folders removed successfully.
pause
