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
systeminfo > "$Directory\systeminfo.txt"

Write-Host "Getting Privilege Information..."
whoami /all > "$Directory\Privilege Information.txt"

Write-Host "Getting IP Configuration..."
ipconfig > "$Directory\ipconfig.txt"

Write-Host "Getting PowerShell version..."
$PSVersionTable.PSVersion > "$Directory\PowerShell version.txt"

Write-Host "Getting PC Timezone..."
Get-TimeZone > "$Directory\Timezone.txt"

Write-Host "Getting Installed Programs..."
Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallLocation, InstallSource | Sort-Object DisplayName > "$Directory\InstalledPrograms.txt"

Write-Host "Getting HotFix/Update Information..."
wmic qfe get Caption,Description,HotfixID,InstalledOn,InstalledBy > "$Directory\Get-Hotfix.txt"

Write-Host "Getting Aliases for"$hostname"..."
net localgroup > "$Directory\net localgroup $hostname.txt"

Write-Host "Getting PC Antivirus and Antimalware Information..."
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct > "$Directory\Antivirus Installed.txt"
Get-WmiObject -Namespace root\Microsoft\SecurityClient -Class AntimalwareHealthStatus > "$Directory\Antimalware Installed.txt"

Write-Host "Getting PC Last Boot Up Time..."
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime > "$Directory\Last BootUp Time.txt"

Write-Host "Getting PC Scheduled Tasks..."
schtasks /Query /FO TABLE > "$Directory\schtask.txt"

Write-Host "Getting PC Task List..."
tasklist > "$Directory\tasklist.txt"

Write-Host "Getting PC Account Setting..."
net accounts >"$Directory\net account.txt"

Write-Host "Getting PC Net Share..."
net share >"$Directory\net share.txt"

Write-Host "Getting Net Statistic for $hostname..."
net statistics Workstation > "$Directory\net statistic.txt"


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

Write-Host "Getting permissions for every exe files in C:\Program Files..."
$icaclsdir = "C:\Program Files"
Get-ChildItem -Path $icaclsdir -Filter "*.exe" | ForEach-Object {
    $icaclspath = $_.FullName
    icacls $icaclspath
} | Out-File "C:\temp\Windows Audit\icacls ProgramFiles.txt"

Write-Host "Getting permissions for every exe files in C:\Program Files (x86)..."
$icaclsdir = "C:\Program Files (x86)"
Get-ChildItem -Path $icaclsdir -Filter "*.exe" | ForEach-Object {
    $icaclspath = $_.FullName
    icacls $icaclspath
} | Out-File "C:\temp\Windows Audit\icacls ProgramFilesx86.txt"

Write-Host "Checking Unquoted Service Path..."




# Zip file

#Compress-Archive -Path "C:\temp\Windows Audit" -DestinationPath "C:\temp\Windows Audit($hostname).zip"


Write-Host "============== DONE =============="
