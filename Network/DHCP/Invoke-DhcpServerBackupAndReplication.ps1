<#
.NAME
Invoke-DhcpBackupAndReplication.ps1

.PURPOSE
- Sets DHCP server registry values for remote backup location, daily backup timing, and daily cleanup.
- Reconciles all DHCP scopes.
- Backs up to remote backup location.
- Exports DHCP server configuration and its leases to XML to remote backup location.
- Exports all DHCP server client reservations to CSV to remote backup location.

.USAGE
Set as a scheduled task on Windows DHCP servers with alternating timeframes between failover partners.

.NOTES
Author: Justin Grathwohl
Date: 09/08/2026
Version: 1.1

#>

#Logging and file transfer directories
$dirPath = "C:\ScriptLogging\Invoke-DhcpServerBackupAndReplication"
$localBackupPath = "C:\DHCPBackup"
$remoteBackupPath = "\\dr-it01.hoffmaster.local\DHCPBackup\$ENV:COMPUTERNAME"
$localLogFilePath = "C:\DHCPLogs"

#Check if directories exist
$dirPathCheck = Test-Path -Path $dirPath
$localBackupPathCheck = Test-Path -Path $localBackupPath
$remoteBackupPathCheck = Test-Path -Path $remoteBackupPath
$logDate = Get-Date -Format ddMMyyyy

#Create directories if it doesn't exist
if (!($dirPathCheck)) {
    New-Item -ItemType Directory $DirPath -Force
}

if (!($localBackupPathCheck)) {
    New-Item -ItemType Directory $localBackupPath -Force
}

if (!($remoteBackupPathCheck)) {
    New-Item -ItemType Directory $remoteBackupPath -Force
}

#Start logging console output
Start-Transcript -Path "$dirPath\Invoke-DhcpServerBackupAndReplication-$logDate.txt"

Write-Output "Setting DHCP backup registry options, these settings won't take effect until the DHCP service is restarted"
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "BackupDatabasePath" -Value $localBackupPath
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "BackupInterval" -Value 720
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "DatabaseCleanupInterval" -Value 720
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "DhcpLogFilePath" -Value $localLogFilePath
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "DhcpV6LogFilePath" -Value $localLogFilePath

Write-Output "Reconciling all DHCP scopes"
Get-DhcpServerv4Scope | Repair-DhcpServerv4IPRecord -Force

Write-Output "Backing up DHCP database"
Backup-DhcpServer -Path $localBackupPath -ComputerName $ENV:COMPUTERNAME -Confirm:$false
Copy-Item -Path $localBackupPath -Destination $remoteBackupPath -Recurse -Force

Write-Output "Exporting DHCP configuration and leases to XML"
Export-DhcpServer -ComputerName $ENV:COMPUTERNAME -File $remoteBackupPath\$($ENV:COMPUTERNAME)_config_leases.xml -Leases -Force

Write-Output "Exporting DHCP Reservations to CSV"
Get-DhcpServerv4Scope | ForEach-Object { Get-DhcpServerv4Lease -ScopeId $_.ScopeID | Where-Object { $_.AddressState -like '*Reservation' } } | Select-Object ScopeId, IPAddress, HostName, ClientID, AddressState | Export-Csv -Path $remoteBackupPath\$($ENV:COMPUTERNAME)_Reservations.csv -NoTypeInformation -Force

Write-Output "Checking non-legacy DHCP scopes for activation"
$activeScopes = Get-DhcpServerv4Scope | Where-Object { $_.ScopeId -like "10.*" } | Select-Object ScopeId, Name, State
foreach ($scope in $activeScopes) {
    if ($scope.State -eq "Inactive") {
        Write-Output "Activating $($scope.Name) - $($scope.ScopeId)"
        Set-DhcpServerv4Scope -ScopeId $scope.ScopeId -State Active -Confirm:$false
    }
}

Write-Output "Replicating DHCP scopes and leases."
Invoke-DhcpServerv4FailoverReplication -ComputerName (Get-DhcpServerv4Failover).PartnerServer -Force
Stop-Transcript