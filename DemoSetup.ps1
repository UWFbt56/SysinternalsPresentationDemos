# =============================================================================
# FIXED SYSINTERNALS DEMO SETUP
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
# DEMO 1: AUTORUNS (FIXED)
# =============================================================================
Write-Host "`n[1] Setting up Autoruns Demo (Persistence)..." -ForegroundColor Yellow

# 1. Create a dummy "malicious" file so Autoruns sees it as UNSIGNED (Pink)
$EvilFile = "$DemoRoot\BotnetLauncher.bat"
"start calc.exe" | Out-File $EvilFile -Encoding ASCII

# 2. Use HKLM (System-wide) so it appears for ANY user
$RegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RegName = "BotnetLauncher"

try {
    Set-ItemProperty -Path $RegPath -Name $RegName -Value $EvilFile -Force
    Write-Host "    [+] Created Malware File: $EvilFile" -ForegroundColor Green
    Write-Host "    [+] Created HKLM Run Key: $RegName" -ForegroundColor Green
} catch {
    Write-Error "    [-] Failed to create registry key."
}

# =============================================================================
# DEMO 2: PROCESS EXPLORER
# =============================================================================
Write-Host "`n[2] Setting up Process Explorer Demo..." -ForegroundColor Yellow
$LockFile = "$DemoRoot\SecretPlans.txt"
"Top Secret Project Info" | Out-File $LockFile

# Start Notepad minimized to lock the file
Start-Process "notepad.exe" -ArgumentList $LockFile -WindowStyle Minimized
Write-Host "    [+] Launched Notepad (Minimized) to lock '$LockFile'" -ForegroundColor Green

# =============================================================================
# DEMO 3: PROCESS MONITOR
# =============================================================================
Write-Host "`n[3] Setting up ProcMon Demo..." -ForegroundColor Yellow
$BatchFile = "$DemoRoot\BrokenScript.bat"
# Script tries to read a file that doesn't exist
"type $DemoRoot\MissingFile.txt" | Out-File $BatchFile -Encoding ASCII
Write-Host "    [+] Created broken script: $BatchFile" -ForegroundColor Green

# =============================================================================
# DEMO 4: SYSMON
# =============================================================================
Write-Host "`n[4] Setting up Sysmon..." -ForegroundColor Yellow
$SysmonExe = "$SysinternalsPath\sysmon64.exe"

if (Test-Path $SysmonExe) {
    if (Get-Service "Sysmon64" -ErrorAction SilentlyContinue) {
        Write-Host "    [!] Sysmon already running." -ForegroundColor Cyan
    } else {
        Start-Process -FilePath $SysmonExe -ArgumentList "-i -n -accepteula" -Wait -WindowStyle Hidden
        Write-Host "    [+] Sysmon Installed." -ForegroundColor Green
    }
    # Clear logs for a clean demo
    wevtutil cl "Microsoft-Windows-Sysmon/Operational"
} else {
    Write-Warning "    [-] Sysmon exe not found at $SysmonExe."
}

# =============================================================================
# DEMO 5: ACCESSCHK
# =============================================================================
Write-Host "`n[5] Setting up AccessChk..." -ForegroundColor Yellow
$DropBox = "$DemoRoot\PublicDropBox"
New-Item -ItemType Directory -Force -Path $DropBox | Out-Null

# Grant "Users" Full Control (The vulnerability)
$Acl = Get-Acl $DropBox
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Ar)
Set-Acl $DropBox $Acl
Write-Host "    [+] Created vulnerable folder: $DropBox" -ForegroundColor Green

Write-Host "`n[!] SETUP COMPLETE. YOU ARE READY TO PRESENT." -ForegroundColor Magenta