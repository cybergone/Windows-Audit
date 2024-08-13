Write-Host "

_ _ _ _ _  _ ___  ____ _ _ _ ____    ____ _  _ ___  _ ___ 
| | | | |\ | |  \ |  | | | | [__     |__| |  | |  \ |  |  
|_|_| | | \| |__/ |__| |_|_| ___]    |  | |__| |__/ |  |
             
                                              ~cybergone

" -ForegroundColor "Green"
#Create report on "C:\temp\Windows Audit"

$Directory = "C:\temp\Windows Audit"
if (!(Test-Path $Directory)) {
    New-Item -ItemType Directory -Path $Directory
}

Write-Host "This will create folder on" $Directory

$hostname = hostname

######### Computer Information

function Get-ComputerInformation {
    Write-Host "Getting Systeminfo..."

    try {
        systeminfo > "$Directory\systeminfo.txt"
    }
    catch {
        Write-Error "Error Getting Systeminfo"
    }
        
    Write-Host "Getting Privilege Informations..."
    try {
        whoami /all > "$Directory\Privilege Information.txt"
    }
    catch {
        Write-Error "Error Getting Privilege Informations"
    } 
    
    Write-Host "Getting IP Configuration..."
    try {
        ipconfig > "$Directory\ipconfig.txt"
    }
    catch {
        Write-Error "Error Getting IP Configuration"
    } 
    
    Write-Host "Getting PowerShell version..."
    try {
        $PSVersionTable.PSVersion > "$Directory\PowerShell version.txt"    
    }
    catch {
        Write-Error "Error Getting PowerShell version"
    }
    
    Write-Host "Getting PC Timezone..."
    try {
        Get-TimeZone > "$Directory\Timezone.txt"    
    }
    catch {
        Write-Error "Error Getting PC Timezone"
    }
    
    Write-Host "Getting Installed Programs..."
    try {
        Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallLocation, InstallSource | Sort-Object DisplayName > "$Directory\InstalledPrograms.txt"
    }
    catch {
        Write-Error "Error Getting Installed Programs"
    }
    
    Write-Host "Getting HotFix/Update Informations..."
    try {
        wmic qfe get Caption,Description,HotfixID,InstalledOn,InstalledBy > "$Directory\Get-Hotfix.txt"
    }
    catch {
        Write-Error "Error Getting Hotfix/Update Informations"
    }
    
    Write-Host "Getting Aliases for"$hostname"..."
    try {
        net localgroup > "$Directory\net localgroup $hostname.txt"
    }
    catch {
        Write-Error "Error Getting Aliases for $hostname"
    }
    
    Write-Host "Getting PC Last Boot Up Time..."
    try {
        Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime > "$Directory\Last BootUp Time.txt"
    }
    catch {
        Write-Error "Error getting PC Last Boot Up Time"
    }
    
    Write-Host "Getting PC Scheduled Tasks..."
    try {
        schtasks /Query /FO TABLE > "$Directory\schtask.txt"
    }
    catch {
        Write-Error "Error Getting PC Scheduled Tasks"
    }
    
    Write-Host "Getting PC Task Lists..."
    try {
        tasklist > "$Directory\tasklist.txt"
    }
    catch {
        Write-Error "Error getting PC Task Lists"
    }
    
    Write-Host "Getting PC Account Settings..."
    try {
        net accounts >"$Directory\net account.txt"
    }
    catch {
        Write-Error "Error Getting PC Account Settings"
    }
    
    Write-Host "Getting PC Net Share..."
    try {
        net share >"$Directory\net share.txt"
    }
    catch {
        Write-Error "Error getting PC Net Share"
    }
    
    Write-Host "Getting Net Statistic for $hostname..."
    try {
        net statistics Workstation > "$Directory\net statistic.txt" 
    }
    catch {
        Write-Error "Error getting Net Statistic for $hostname"
    }
}

function Get-AV {
    Write-Host "Getting PC Antivirus and Antimalware Information..."
    try {
        Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct > "$Directory\Antivirus Installed.txt"
        Get-WmiObject -Namespace root\Microsoft\SecurityClient -Class AntimalwareHealthStatus > "$Directory\Antimalware Installed.txt"
    }
    catch [System.Management.Automation.RemoteException]{
        Write-Error "Error Getting PC Antivirus and Antimalware Information"
    }
    catch [System.Management.Automation.InvalidArgumentException] {
        Write-Error "Invalid argument for Get-WmiObject: $_"
    }
    catch {
        Write-Error "Unexpected error: $_"
    }
}

######### Checking Windows Security Misconfigurations

function Get-SMBv1Check {
    try {
        Write-Host "Checking SMBv1..."
        $checkSMB1 = (Get-SmbServerConfiguration).EnableSMB1Protocol

        if ($checkSMB1 -eq $true){
            Write-Host "SMBv1 Enabled, Please disable it" -ForegroundColor "Red"
                }
        else    {
            Write-Host "SMBv1 Disabled" -ForegroundColor "Green"
                }
        } catch{
            Write-Host "SMBv1 Not Found"
        }
}

function Get-SMBv2Check {
    try {
        Write-Host "Checking SMBv2..."
        $checkSMB1 = (Get-SmbServerConfiguration).EnableSMB2Protocol

        if ($checkSMB1 -eq $true){
            Write-Host "SMBv2 Enabled, Please disable it" -ForegroundColor "Red"
                }
        else    {
            Write-Host "SMBv2 Disabled" -ForegroundColor "Green"
                }
        } catch{
            Write-Host "SMBv2 Not Found"
        }
}

function Set-DisableWeakTLS {
    Write-Output "Disable TLS 1.0"
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f

    Write-Output "Disable TLS 1.1"
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 0 /f 
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
}

######### Checking Possible Privilege Escalation

function Get-Privesc {
    Write-Host "Checking Possible Privilege Escalations...."
    Write-Host "Getting permissions for every exe files in C:\Windows\system32..."
    $icaclsdir = "C:\Windows\System32"
    try {
        Get-ChildItem -Path $icaclsdir -Filter "*.exe" | ForEach-Object {
        $icaclspath = $_.FullName
        icacls $icaclspath } | Out-File "C:\temp\Windows Audit\icacls WindowsSystem32.txt"
    }
    catch {
        Write-Error "Error Getting Permission for every exe files in C:\Windows\system32"
    }

    Write-Host "Getting permissions for every exe files in C:\Windows\SysWOW64..."
    $icaclsdir = "C:\Windows\SysWOW64"
    try {
        Get-ChildItem -Path $icaclsdir -Filter "*.exe" | ForEach-Object {
        $icaclspath = $_.FullName
        icacls $icaclspath } | Out-File "C:\temp\Windows Audit\icacls WindowsSysWOW64.txt"   
    }
    catch {
        Write-Error "Error getting permissions for every exe files in C:\Windows\SysWOW64"
    } 
}

function Get-UnquotedSvc {
    Write-Host "Checking Unquoted Service Path..."
    $services = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\services | ForEach-Object { Get-ItemProperty $_.PsPath }

    $vulnerableServices = foreach ($svc in $services) {
        $svcPath = $svc.ImagePath -split ".exe"
        if (($svcPath[0] -like "* *") -and ($svcPath[0] -notlike '"*') -and ($svcPath[0] -notlike "\*")) {
            $svc | Select-Object DisplayName, ImagePath, PsPath, @{Name = "ACL"; Expression = {Get-Acl $_.ImagePath}}
        }
    }

    $vulnerableServices
}



## Running

Get-ComputerInformation
Get-AV
Get-SMBv1Check
Get-SMBv2Check
Get-UnquotedSvc | Export-Csv -Path "C:\temp\Windows Audit\Unquoted Service Path.csv"
Get-Privesc
Set-DisableWeakTLS



Write-Host "============== DONE =============="
