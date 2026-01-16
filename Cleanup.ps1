# =============================================================================
# SYSINTERNALS DEMO CLEANUP
# Description: Removes all artifacts, files, and settings created for the demo.
# Usage: Run as Administrator.
# =============================================================================

# --- Configuration ---
$SysinternalsPath = "C:\Sysinternals"   # <--- Must match your install path
$DemoRoot         = "C:\Demo_Workspace"
$SensitiveDir     = "C:\Sensitive"

# --- Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] This script must be run as Administrator."
    break
}

Write-Host "[:] Starting Cleanup..." -ForegroundColor Cyan

# =============================================================================
# CLEANUP 1: PROCESS EXPLORER (Unlock Files)
# =============================================================================
Write-Host "`n[1] Stopping Demo Processes..." -ForegroundColor Yellow

# Find the specific Notepad instance holding our secret file
$HiddenNotepad = Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like "*SecretPlans.txt*" }

if ($HiddenNotepad) {
    try {
        Stop-Process -Id $HiddenNotepad.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Host "    [+] Killed Notepad process (PID: $($HiddenNotepad.ProcessId)) locking 'SecretPlans.txt'." -ForegroundColor Green
    } catch {
        Write-Warning "    [-] Found process but failed to kill it."
    }
} else {
    Write-Host "    [-] No locked Notepad process found." -ForegroundColor DarkGray
}

# =============================================================================
# CLEANUP 2: FILES & DIRECTORIES
# =============================================================================
Write-Host "`n[2] Removing Files and Folders..." -ForegroundColor Yellow

# Delete C:\Demo_Workspace
if (Test-Path $DemoRoot) {
    Remove-Item $DemoRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "    [+] Deleted workspace: $DemoRoot" -ForegroundColor Green
}

# Delete C:\Sensitive
if (Test-Path $SensitiveDir) {
    Remove-Item $SensitiveDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "    [+] Deleted folder: $SensitiveDir" -ForegroundColor Green
}

# =============================================================================
# CLEANUP 3: REGISTRY (Autoruns)
# =============================================================================
Write-Host "`n[3] Removing Registry Persistence..." -ForegroundColor Yellow
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RegName = "EvilNotepad"

if (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $RegPath -Name $RegName -Force
    Write-Host "    [+] Removed Registry Key: $RegName" -ForegroundColor Green
} else {
    Write-Host "    [-] Registry Key not found." -ForegroundColor DarkGray
}

# =============================================================================
# CLEANUP 4: SYSMON (Uninstall)
# =============================================================================
Write-Host "`n[4] Uninstalling Sysmon..." -ForegroundColor Yellow
$SysmonExe = "$SysinternalsPath\sysmon64.exe"

if (Test-Path $SysmonExe) {
    if (Get-Service "Sysmon64" -ErrorAction SilentlyContinue) {
        # Uninstall Sysmon
        Start-Process -FilePath $SysmonExe -ArgumentList "-u" -Wait -WindowStyle Hidden
        Write-Host "    [+] Sysmon Uninstalled successfully." -ForegroundColor Green
    } else {
        Write-Host "    [-] Sysmon service is not running (already uninstalled?)." -ForegroundColor DarkGray
    }
} else {
    Write-Warning "    [-] Sysmon executable not found at $SysmonExe. Cannot uninstall automatically."
    Write-Warning "    [-] Please run 'sysmon64.exe -u' manually if needed."
}

# =============================================================================
# FINAL SUMMARY
# =============================================================================
Write-Host "`n========================================================" -ForegroundColor Magenta
Write-Host " CLEANUP COMPLETE " -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Magenta