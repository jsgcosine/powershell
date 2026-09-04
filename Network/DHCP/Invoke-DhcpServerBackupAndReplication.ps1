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
Date: 09/04/2026
Version: 1.0

#>

#Logging and file transfer directories
$dirPath = "C:\ScriptLogging\Invoke-DhcpServerBackupAndReplication"
$backupPath = "\\server.domain.local\DHCPBackup\$ENV:COMPUTERNAME"

#Check if logging directory is present
$dirPathCheck = Test-Path -Path $DirPath
$backupPathCheck = Test-Path -Path $backupPath
$logDate = Get-Date -Format ddMMyyyy

#Create logging directory if it doesn't exist
if (!($DirPathCheck)) {
    New-Item -ItemType Directory $DirPath -Force
}

if (!($backupPathCheck)) {
    New-Item -ItemType Directory $backupPath -Force
}
Start-Transcript -Path "$dirPath\Invoke-DhcpServerBackupAndReplication-$logDate.txt"
Write-Output "Setting DHCP backup registry options"
Write-Output "Setting values while DHCP server is running won't take effect until the service is restarted."
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "BackupDatabasePath" -Value $backupPath
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "BackupInterval" -Value 1440
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DHCPServer\Parameters -Name "DatabaseCleanupInterval" -Value 1440
Write-Output "Reconciling all DHCP scopes"
Get-DhcpServerv4Scope | Repair-DhcpServerv4IPRecord -Force
Write-Output "Backing up DHCP database and exporting leases to XML"
Backup-DhcpServer -Path $backupPath -ComputerName "$ENV:COMPUTERNAME"
Export-DhcpServer -ComputerName "$ENV:COMPUTERNAME" -File $backupPath\"$ENV:COMPUTERNAME"_leases.xml -Leases -Force
Write-Output "Exporting DHCP Reservations to CSV"
Get-DhcpServerv4Scope | ForEach-Object { Get-DhcpServerv4Lease -ScopeId $_.ScopeID | Where-Object { $_.AddressState -like '*Reservation' } } | Select-Object ScopeId, IPAddress, HostName, ClientID, AddressState | Export-Csv $backupPath\"$ENV:COMPUTERNAME"_Reservations.csv -NoTypeInformation -Force
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