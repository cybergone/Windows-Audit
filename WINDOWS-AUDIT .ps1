Write-Host "

_ _ _ _ _  _ ___  ____ _ _ _ ____    ____ _  _ ___  _ ___ 
| | | | |\ | |  \ |  | | | | [__     |__| |  | |  \ |  |  
|_|_| | | \| |__/ |__| |_|_| ___]    |  | |__| |__/ |  |
             
                                              ~cybergone

"
#Create log audit on "C:\temp\Windows Audit"

$Directory = "C:\temp\Windows Audit"
if (!(Test-Path $Directory)) {
    New-Item -ItemType Directory -Path $Directory
}

Write-Host "This will create folder on" $Directory

$hostname = hostname

######### Computer Information

Write-Host "Getting Systeminfo..."

try {
    systeminfo > "$Directory\systeminfo.txt"
}
catch {
}
    
Write-Host "Getting Privilege Information..."
try {
    whoami /all > "$Directory\Privilege Information.txt"
}
catch {
} 

Write-Host "Getting IP Configuration..."
try {
    ipconfig > "$Directory\ipconfig.txt"
}
catch {
} 

Write-Host "Getting PowerShell version..."
try {
    $PSVersionTable.PSVersion > "$Directory\PowerShell version.txt"    
}
catch {
}

Write-Host "Getting PC Timezone..."
try {
    Get-TimeZone > "$Directory\Timezone.txt"    
}
catch {
}


Write-Host "Getting Installed Programs..."
try {
    Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallLocation, InstallSource | Sort-Object DisplayName > "$Directory\InstalledPrograms.txt"
}
catch {
}

Write-Host "Getting HotFix/Update Information..."
try {
    wmic qfe get Caption,Description,HotfixID,InstalledOn,InstalledBy > "$Directory\Get-Hotfix.txt"
}
catch {
}

Write-Host "Getting Aliases for"$hostname"..."
try {
    net localgroup > "$Directory\net localgroup $hostname.txt"
}
catch {
}

Write-Host "Getting PC Antivirus and Antimalware Information..."
try {
    Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct > "$Directory\Antivirus Installed.txt"
    Get-WmiObject -Namespace root\Microsoft\SecurityClient -Class AntimalwareHealthStatus > "$Directory\Antimalware Installed.txt"
}
catch {
}

Write-Host "Getting PC Last Boot Up Time..."
try {
    Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime > "$Directory\Last BootUp Time.txt"
}
catch {
}

Write-Host "Getting PC Scheduled Tasks..."
try {
    schtasks /Query /FO TABLE > "$Directory\schtask.txt"
}
catch {
}

Write-Host "Getting PC Task List..."
try {
    tasklist > "$Directory\tasklist.txt"
}
catch {
}

Write-Host "Getting PC Account Setting..."
try {
    net accounts >"$Directory\net account.txt"
}
catch {
}


Write-Host "Getting PC Net Share..."
try {
    net share >"$Directory\net share.txt"
}
catch {
}

Write-Host "Getting Net Statistic for $hostname..."
try {
    net statistics Workstation > "$Directory\net statistic.txt" 
}
catch {
}


######### Checking Windows Security Misconfigurations

Write-Host "Checking SMBv1..."
$checkSMB1 = (Get-SmbServerConfiguration).EnableSMB1Protocol

if ($checkSMB1 -eq $false){
    Write-Host "SMBv1 Disabled, saved from SMBv1 Attack " -ForegroundColor "Green"
}
elseif ($checkSMB1 -eq $true) {
    Write-Host "SMBv1 Enabled, please Disable for enhanced security" -ForegroundColor "Red"
}
else{
    Write-Host "SMBv1 Not Found"
}

Write-Host "Checking SMBv2..."
$checkSMB2 = (Get-SmbServerConfiguration).EnableSMB2Protocol

if ($checkSMB2 -eq $false){
    Write-Host "SMBv2 Disabled" -ForegroundColor "Red"
}
elseif ($checkSMB2 -eq $true) {
    Write-Host "SMBv2 Enabled" -ForegroundColor "Green"
}
else{
    Write-Host "SMBv2 Not Found"
}



######### Checking Possible Privilege Escalation
Write-Host "Checking Possible Privilege Escalations...."

Write-Host "Getting permissions for every exe files in C:\Windows\system32..."
$icaclsdir = "C:\Windows\System32"
Get-ChildItem -Path $icaclsdir -Filter "*.exe" | ForEach-Object {
    $icaclspath = $_.FullName
    icacls $icaclspath 
} | Out-File "C:\temp\Windows Audit\icacls WindowsSystem32.txt"

Write-Host "Getting permissions for every exe files in C:\Windows\SysWOW64..."
$icaclsdir = "C:\Windows\SysWOW64"
Get-ChildItem -Path $icaclsdir -Filter "*.exe" | ForEach-Object {
    $icaclspath = $_.FullName
    icacls $icaclspath
} | Out-File "C:\temp\Windows Audit\icacls WindowsSysWOW64.txt"


Write-Host "Checking Unquoted Service Path..."




# Zip file

#Compress-Archive -Path "C:\temp\Windows Audit" -DestinationPath "C:\temp\Windows Audit($hostname).zip"


Write-Host "============== DONE =============="
