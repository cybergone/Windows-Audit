# Windows Audit

## This script performs a comprehensive audit of your Windows system, gathering information on various security aspects.

### Features:
    1. System Information: Checks basic system details like 
        a. OS System Information 
        b. Check Privilege Information 
        c. IP Configuration
        d. PowerShell Version
        e. PC Timezone
        f. List of Installed Programs
        g. List of Hotfix/Windows Update Informations
        h. Net Aliases
        i. PC Last Boot Up Time
        j. PC Scheduled Tasks
        k. PC Account Settings
        l. PC Net Statistics
    2. Antivirus and Antimalware Information: Provides details on your installed antivirus and antimalware software.
    3. SMBv1 Check: Verifies if SMBv1 (a less secure file sharing protocol) is disabled.
    4. SMBv2 Check: Confirms if SMBv2 (a more secure file sharing protocol) is enabled.
    5. Possible Privilege Escalation: Identifies potential vulnerabilities that could allow privilege escalation. Output are __icacls__ based
    6. Unquoted Service Path Check: Detects services with unquoted paths in the registry, which might be a security risk.

### Requirements:
    PowerShell 5.1 or later

### Instructions:
    1. Clone this repo
    2. Open an elevated PowerShell window (Run as administrator).
    3. Navigate to the directory where you saved the script.
    4. Run the script by typing: ./WINDOWS-AUDIT.ps1
    5. The output files will saved in "C:\temp\Windows Audit"
