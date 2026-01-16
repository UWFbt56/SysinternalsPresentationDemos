# Sysinternals Presentation Demos

This project contains the setup scripts and demonstration files used to teach students about the Sysinternals Suite. The primary script (`DemoSetup.ps1`) automatically configures a workspace, creates dummy registry keys for persistence demos, and sets up file-locking scenarios.

## ⚠️ Prerequisites

Before running the setup script, ensure the following requirements are met. The script relies on hardcoded paths and specific system privileges.

### 1. Software Requirements
* **Sysinternals Suite:**
    * **Action:** Download the complete suite from [Microsoft Learn](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite).
    * **Installation Path:** You **must** extract the tools to `C:\Sysinternals`.
    * *Reason:* The script specifically looks for `C:\Sysinternals\sysmon64.exe` and other tools at this location.

* **Active Directory Module (Optional):**
    * For the **AD Explorer** demo to function fully, the machine should be domain-joined or have the RSAT Active Directory tools installed.
    * *Note:* If you are on a standalone machine, the AD Explorer section of the script may be skipped or fail gracefully.

### 2. Permissions
* **Administrator Privileges:**
    * You must run PowerShell as **Administrator**.
    * *Reason:* The script creates folders in the root drive (`C:\Sensitive`), modifies the Registry (`HKCU` Run keys), and changes file permissions.
* **Execution Policy:**
    * Ensure your shell allows local script execution:
        ```powershell
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
        ```
 ## 🚀 How to Run

1.  Open PowerShell as **Administrator**.
2.  Navigate to the directory containing the demo scripts:
    ```powershell
    cd "C:\Users\YourName\Downloads\SysinternalsPresentationDemos"
    ```
3.  Run the setup script:
    ```powershell
    .\DemoSetup.ps1
    ```

    ## 📂 What This Script Creates
* **Workspace:** `C:\Demo_Workspace`
* **Persistence Demo:** Adds a "Run" key to the Registry launching Notepad.
* **File Locking Demo:** Creates `SecretPlans.txt` and locks it via an open Notepad process.
* **Permissions Demo:** Creates `C:\Sensitive\DropBox` with modified ACLs.