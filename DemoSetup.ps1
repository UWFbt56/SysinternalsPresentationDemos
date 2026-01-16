# =============================================================================
# FIXED SYSINTERNALS DEMO SETUP (Final Version)
# Usage: Run as Administrator.
# =============================================================================

$SysinternalsPath = "C:\Sysinternals"  # <--- Verify this path matches yours
$DemoRoot         = "C:\Demo_Workspace"

# --- Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Script must be run as Administrator."
    break
}

# --- Init Workspace ---
Write-Host "[:] Setting up Workspace..." -ForegroundColor Cyan
if (Test-Path $DemoRoot) { Remove-Item $DemoRoot -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $DemoRoot | Out-Null

# =============================================================================
# DEMO 1: AUTORUNS (Persistence)
# =============================================================================
Write-Host "`n[1] Setting up Autoruns..." -ForegroundColor Yellow
$EvilFile = "$DemoRoot\BotnetLauncher.bat"
"start calc.exe" | Out-File $EvilFile -Encoding ASCII
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RegName = "BotnetLauncher"

if (!(Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name $RegName -Value $EvilFile -Force
Write-Host "    [+] Created HKLM Run Key: $RegName" -ForegroundColor Green

# =============================================================================
# DEMO 2: PROCESS EXPLORER (File Lock)
# =============================================================================
Write-Host "`n[2] Setting up Process Explorer (Hard Lock)..." -ForegroundColor Yellow
$LockFile = "$DemoRoot\SecretPlans.txt"
"Top Secret Project Info" | Out-File $LockFile

# We use PowerShell to open a file stream with 'None' share mode.
# This makes it IMPOSSIBLE to delete the file while this script is running.
$LockScript = @"
    `$f = [System.IO.File]::Open('$LockFile', 'Open', 'ReadWrite', 'None');
    Start-Sleep -Seconds 3600;
    `$f.Close();
"@

# Start this locker script in a hidden background window
Start-Process "powershell.exe" -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-Command", $LockScript
Write-Host "    [+] Launched Hidden PowerShell process to HARD LOCK '$LockFile'" -ForegroundColor Green

# =============================================================================
# FIXED DEMO 3 SETUP (ProcMon)
# =============================================================================
$DemoRoot = "C:\Demo_Workspace"
$BatchFile = "$DemoRoot\BrokenScript.bat"

# We add 'pause' so the window stays open, letting you see the error physically.
$Content = @"
@echo off
echo Attempting to read critical file...
type "$DemoRoot\MissingFile.txt"
pause
"@

$Content | Out-File $BatchFile -Encoding ASCII
Write-Host "[+] Updated BrokenScript.bat with a 'pause' command." -ForegroundColor Green

# =============================================================================
# FIXED DEMO 4 SETUP (Sysmon)
# =============================================================================
$SysinternalsPath = "C:\Sysinternals"
$SysmonExe = "$SysinternalsPath\sysmon64.exe"

Write-Host "[4] Setting up Sysmon..." -ForegroundColor Yellow

# 1. Ensure Sysmon is installed
if (Get-Service "Sysmon64" -ErrorAction SilentlyContinue) {
    Write-Host "    [+] Sysmon is running." -ForegroundColor Green
} else {
    Write-Host "    [*] Installing Sysmon..."
    Start-Process -FilePath $SysmonExe -ArgumentList "-i -n -accepteula" -Wait -WindowStyle Hidden
}

# 2. Clear the logs so your "Malware" command is the FIRST thing you see
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
Write-Host "    [+] Sysmon logs cleared. Ready for demo." -ForegroundColor Green
# =============================================================================
# DEMO 5: ACCESSCHK
# =============================================================================
Write-Host "`n[5] Setting up AccessChk..." -ForegroundColor Yellow
$DropBox = "$DemoRoot\PublicDropBox"
New-Item -ItemType Directory -Force -Path $DropBox | Out-Null
$Acl = Get-Acl $DropBox
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Ar)
Set-Acl $DropBox $Acl
Write-Host "    [+] Created vulnerable folder: $DropBox" -ForegroundColor Green

Write-Host "`n[!] SETUP COMPLETE." -ForegroundColor Magenta