Write-Host "

_ _ _ _ _  _ ___  ____ _ _ _ ____    ____ _  _ ___  _ ___ 
| | | | |\ | |  \ |  | | | | [__     |__| |  | |  \ |  |  
|_|_| | | \| |__/ |__| |_|_| ___]    |  | |__| |__/ |  |
             
                      @cybergone

"
#Membuat direktori pada "C:\temp\Windows Audit"

$Direktori = "C:\temp\Windows Audit"
if (!(Test-Path $Direktori)) {
    New-Item -ItemType Directory -Path $Direktori
}

$hostname = hostname

######### Computer Information #########

Write-Host "Getting Systeminfo..."
systeminfo > "$Direktori\systeminfo.txt"

Write-Host "Getting Privilege Information..."
whoami /priv > "$Direktori\whoami-priv.txt"

Write-Host "Getting IP Configuration..."
ipconfig > "$Direktori\ipconfig.txt"

Write-Host "Getting PowerShell version..."
$PSVersionTable.PSVersion > "$Direktori\PowerShell version.txt"

Write-Host "Getting PC Timezone..."
Get-TimeZone > "$Direktori\Timezone.txt"

Write-Host "Getting Installed Programs..."
Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object InstallDate, DisplayName, DisplayVersion, Publisher, InstallLocation, InstallSource | Sort-Object DisplayName > "$Direktori\InstalledPrograms.txt"

Write-Host "Getting Aliases for"$hostname"..."
net localgroup > "$Direktori\net localgroup $hostname.txt"

Write-Host "Getting PC Antivirus Information..."
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct > "$Direktori\Antivirus Installed.txt"

Write-Host "Getting PC Last Boot Up Time..."
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime > "$Direktori\Last BootUp Time.txt"

Write-Host "Getting PC Scheduled Tasks..."
schtasks /Query /FO TABLE > "$Direktori\schtask.txt"


$icaclsdir = "C:\Windows\System32"
Write-Host "Getting permissions for exe files in C:\Windows\system32..."
Get-ChildItem -Path $icaclsdir -Filter "*.exe" | ForEach-Object {
    $icaclspath = $_.FullName
    icacls $icaclspath
    
} | Out-File "C:\temp\Windows Audit\icacls.txt"



######### Checking Windows Security Misconfigurations


$cekSMB1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
Write-Host "Checking SMBv1..."

if ($cekSMB1 -eq $false){
    Write-Host "SMBv1 Disabled, saved from SMBv1 Attack " -ForegroundColor "Green"
}
elseif ($cekSMB1 -eq $true) {
    Write-Host "SMBv1 Enabled, please Disable for enhanced security" -ForegroundColor "Red"
}
else{
    Write-Host "SMBv1 Not Found"
}


#




# Zip file

#Compress-Archive -Path "C:\temp\Windows Audit" -DestinationPath "C:\temp\Windows Audit($hostname).zip"


Write-Host "============== DONE =============="
