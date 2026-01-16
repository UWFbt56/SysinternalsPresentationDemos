Write-Host "--- Sysinternals Demo Cleanup ---" -ForegroundColor Cyan

# 1. Remove Registry Persistence (The 'EvilNotepad' Run Key)
$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RegName = "EvilNotepad"

if (Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $RegPath -Name $RegName
    Write-Host "[+] Removed Registry Run Key: $RegName" -ForegroundColor Green
} else {
    Write-Host "[-] Registry Key not found (already clean)." -ForegroundColor Gray
}

# 2. Stop the specific Notepad process (File Locking Demo)
# Warning: This closes ALL Notepad instances to ensure the file handle is released.
Write-Host "[*] Closing Notepad instances to release file locks..." -ForegroundColor Yellow
Stop-Process -Name notepad -ErrorAction SilentlyContinue

# 3. Remove Workspaces and Sensitive Folders
$FoldersToRemove = @("C:\Demo_Workspace", "C:\Sensitive")

foreach ($Folder in $FoldersToRemove) {
    if (Test-Path $Folder) {
        try {
            Remove-Item -Path $Folder -Recurse -Force -ErrorAction Stop
            Write-Host "[+] Deleted folder: $Folder" -ForegroundColor Green
        }
        catch {
            Write-Error "Could not delete $Folder. Ensure no files are open inside it."
        }
    } else {
        Write-Host "[-] Folder $Folder not found (already clean)." -ForegroundColor Gray
    }
}