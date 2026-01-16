# =============================================================================
# SYSINTERNALS DEMO SETUP AUTOMATION
# Description: Prepares a Windows machine for 6 specific Sysinternals demos.
# Usage: Run as Administrator.
# =============================================================================

# --- Configuration ---
$SysinternalsPath = "C:\Sysinternals"  # <--- UPDATE THIS if your tools are elsewhere
$DemoRoot         = "C:\Demo_Workspace"

# --- Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] This script must be run as Administrator."
    break
}

# --- Init Workspace ---
Write-Host "[:] Setting up Workspace at $DemoRoot..." -ForegroundColor Cyan
if (Test-Path $DemoRoot) { Remove-Item $DemoRoot -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $DemoRoot | Out-Null

# =============================================================================
# DEMO 1: AUTORUNS (Malicious Registry Key)
# =============================================================================
Write-Host "`n[1] Setting up Autoruns Demo (Persistence)..." -ForegroundColor Yellow
$RegPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
$RegName = "EvilNotepad"
$RegValue = "C:\Windows\System32\notepad.exe"

try {
    Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Force
    Write-Host "    [+] Created Registry Run Key: $RegName -> $RegValue" -ForegroundColor Green
} catch {
    Write-Error "    [-] Failed to create registry key."
}

# =============================================================================
# DEMO 2: PROCESS EXPLORER (File Lock)
# =============================================================================
Write-Host "`n[2] Setting up Process Explorer Demo (File Locking)..." -ForegroundColor Yellow
$LockFile = "$DemoRoot\SecretPlans.txt"
"Top Secret Project Info" | Out-File $LockFile

# Start Notepad to lock the file and minimize it
$Process = Start-Process "notepad.exe" -ArgumentList $LockFile -PassThru -WindowStyle Minimized
if ($Process) {
    Write-Host "    [+] Created $LockFile" -ForegroundColor Green
    Write-Host "    [+] Launched Notepad (PID: $($Process.Id)) to lock the file." -ForegroundColor Green
    Write-Host "    [+] Window is minimized." -ForegroundColor Green
} else {
    Write-Error "    [-] Failed to launch Notepad."
}

# =============================================================================
# DEMO 3: PROCESS MONITOR (Script Failure)
# =============================================================================
Write-Host "`n[3] Setting up ProcMon Demo (Broken Script)..." -ForegroundColor Yellow
$BatchFile = "$DemoRoot\BrokenScript.bat"
$MissingFile = "$DemoRoot\MissingFile.txt"

# Content tries to read a file that doesn't exist
"type $MissingFile" | Out-File $BatchFile -Encoding ASCII

# Ensure the missing file is actually missing
if (Test-Path $MissingFile) { Remove-Item $MissingFile -Force }

Write-Host "    [+] Created broken script at: $BatchFile" -ForegroundColor Green
Write-Host "    [+] Ensured target file '$MissingFile' does not exist." -ForegroundColor Green

# =============================================================================
# DEMO 4: SYSMON (Process Logging)
# =============================================================================
Write-Host "`n[4] Setting up Sysmon Demo..." -ForegroundColor Yellow
$SysmonExe = "$SysinternalsPath\sysmon64.exe"

if (Test-Path $SysmonExe) {
    # Check if Sysmon is already running
    if (Get-Service "Sysmon64" -ErrorAction SilentlyContinue) {
        Write-Host "    [!] Sysmon is already installed." -ForegroundColor Cyan
    } else {
        Write-Host "    [*] Installing Sysmon with default configuration..."
        Start-Process -FilePath $SysmonExe -ArgumentList "-i -n -accepteula" -Wait -WindowStyle Hidden
        Write-Host "    [+] Sysmon Installed." -ForegroundColor Green
    }
    
    # Clear the log so the demo is clean
    Write-Host "    [*] Clearing Sysmon Operational Log..."
    wevtutil cl "Microsoft-Windows-Sysmon/Operational"
    Write-Host "    [+] Log Cleared." -ForegroundColor Green

} else {
    Write-Warning "    [-] Sysmon executable not found at $SysmonExe. Please download it."
}

# =============================================================================
# DEMO 5: ACCESSCHK (Weak Permissions)
# =============================================================================
Write-Host "`n[5] Setting up AccessChk Demo (Weak Permissions)..." -ForegroundColor Yellow
$SensitiveDir = "C:\Sensitive"
$DropBox = "$SensitiveDir\DropBox"

if (Test-Path $SensitiveDir) { Remove-Item $SensitiveDir -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $DropBox | Out-Null

# Grant "Users" Full Control
$Acl = Get-Acl $DropBox
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$Acl.SetAccessRule($Ar)
Set-Acl $DropBox $Acl

Write-Host "    [+] Created $DropBox" -ForegroundColor Green
Write-Host "    [+] Granted 'Users' Full Control." -ForegroundColor Green

# =============================================================================
# DEMO 6: AD EXPLORER (Active Directory)
# =============================================================================
Write-Host "`n[6] Checking AD Explorer Requirements..." -ForegroundColor Yellow
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host "    [+] Active Directory module detected." -ForegroundColor Green
    Write-Host "    [i] NOTE: Ensure you have a Domain Controller reachable for this demo." -ForegroundColor Cyan
    
    # Optional: Create a test user if we are on a DC
    try {
        if (Get-Service "ntds" -ErrorAction SilentlyContinue) {
             # We are likely on a DC
             # Check if user exists, if not create
             # (This part is commented out to avoid polluting your AD unless you want it)
             # New-ADUser -Name "DemoGuest" -OtherAttributes @{'title'='Sysinternals Demo User'}
        }
    } catch {}
} else {
    Write-Warning "    [-] Active Directory module not found. This machine is likely not a Domain Controller."
    Write-Warning "    [-] You can still run AdExplorer, but you must connect to a remote DC."
}

# =============================================================================
# FINAL SUMMARY
# =============================================================================
Write-Host "`n========================================================" -ForegroundColor Magenta
Write-Host " SETUP COMPLETE " -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Magenta
Write-Host "1. Autoruns:    'EvilNotepad' key created in HKCU Run."
Write-Host "2. ProcExp:     'SecretPlans.txt' is open and locked by Notepad (Minimized)."
Write-Host "3. ProcMon:     'C:\Demo_Workspace\BrokenScript.bat' is ready to fail."
Write-Host "4. Sysmon:      Installed and Logs Cleared."
Write-Host "5. AccessChk:   'C:\Sensitive\DropBox' created with weak permissions."
Write-Host "6. AdExplorer:  Ready to connect."
Write-Host "`nGo knock 'em dead!" -ForegroundColor Cyan