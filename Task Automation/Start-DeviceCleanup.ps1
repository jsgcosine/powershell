<#
.NAME
Start-DeviceCleanup.ps1

.PURPOSE
Cleans out well-known directories, backs up IIS, Windows, and Event Viewer logs, and leverages CleanMgr, SFC, and DISM for deep cleaning and image repair.

.USAGE
You can add additional folders to clean out in the $cleanupFolders array, simply follow the existing syntax.
All CleanMgr options have been added and enabled that currently exist as of Windows 11 24H2. Comment out the ones you don't want to cleanup. The commented out ones are for legacy systems or are valid only when certain system options are enabled.

.TODO
- Get actual last used date of old profiles for cleanup

.NOTES
Author: Justin Grathwohl
Date: 09/05/2025
Version: 2.0

#>
#Requires -Version 5.1
$VerbosePreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"

#Logging directories
$dirPath = "C:\ScriptLogging\Start-DeviceCleanup"
$logBackupPath = "C:\ScriptLogging\Start-DeviceCleanup\backups"

#Check if logging directory is present
$dirPathCheck = Test-Path -Path $dirPath
$logBackupPathCheck = Test-Path -Path $logBackupPath

#Create logging directory if it doesn't exist
If (!($dirPathCheck)) {
    New-Item -ItemType Directory $dirPath -Force
}
If (!($logBackupPathCheck)) {
    New-Item -ItemType Directory $logBackupPath -Force
}

#Date formatting for logging outputs and queries
$logBackupRotateDate = (Get-Date).AddDays(-90)
$scriptLogRotateDate = (Get-Date).AddDays(-7)
$logRotateDate = (Get-Date).AddDays(-90)
$logDate = Get-Date -Format ddMMyyyy

Start-Transcript -Path $dirPath\Start-DeviceCleanup-$logDate.txt
Write-Output "Script starting at $(Get-Date)"
Write-Output "Cleaning up old script log files..."
Get-ChildItem -Path $dirPath -Recurse -Filter *.txt | Where-Object {$_.LastWriteTime -le $scriptLogRotateDate} | Remove-Item -Force
Write-Output "Cleaning up old log backups..."
Get-ChildItem -Path $logBackupPath -Recurse -Filter *.zip | Where-Object {$_.LastWriteTime -le $logBackupRotateDate} | Remove-Item -Force
Write-Output "Clearing the recycle bins for all users on all drives..."
Get-Volume | Where-Object {$_.DriveType -eq "Fixed" -and $null -ne $_.DriveLetter } | ForEach-Object { Clear-RecycleBin -DriveLetter $_.DriveLetter -Force }
Clear-RecycleBin -Force
Write-Output "Setting variables for CleanMgr, DISM, and SFC, and checking folders to cleanup..."

# Create old profile cleanup flow
# $profileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\"
Write-Output "Cleaning up old user profiles"
$getUnloadedProfiles = Get-CimInstance -class Win32_UserProfile | Where-Object {(!$_.Special) -and (!$_.Loaded)} | Select-Object LocalPath,SID,LastUseTime
$thresholdDate = (Get-Date).AddMonths(-6)
$profilesToDelete = $getUnloadedProfiles | Where-Object { $_.LastUseTime -lt $thresholdDate -or $null -eq $_.LastUseTime }
ForEach ($userProfile in $profilesToDelete) {
    $profilePath = $userProfile.LocalPath
    Remove-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($profile.SID)'"
    Get-Item -Path $profilePath | Remove-Item -Force
}

# Create array for the folders to cleanup
$cleanupFolders = @(
    "$ENV:TEMP",`
    "C:\Windows\Temp",`
    "C:\Users\*\Appdata\Local\Temp",`
    "C:Windows\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5",`
    "C:\Windows\SoftwareDistribution\Download",`
    "C:\Windows\System32\FNTCACHE.DAT",`
    "C:\Windows\`$NtUninstall*",`
    "C:\Temp",`
    "C:\Windows\System32\LogFiles",`
    "C:\inetpub\logs",`
    "C:\Windows\System32\winevt\Logs",
)

# Create array for Cleanmgr registry keys
$cleanMgrBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
$cleanMgrRegKeys = @(
    "$cleanMgrBase\Active Setup Temp Folders"
    "$cleanMgrBase\BranchCache"
    "$cleanMgrBase\Content Indexer Cleaner"
    "$cleanMgrBase\D3D Shader Cache"
    "$cleanMgrBase\Delivery Optimization Files"
    "$cleanMgrBase\Device Driver Packages"
    "$cleanMgrBase\Diagnostic Data Viewer database files"
    "$cleanMgrBase\Downloaded Program Files"
    "$cleanMgrBase\Feedback Hub Archive log files"
    # "$cleanMgrBase\GameNewsFiles"
    # "$cleanMgrBase\GameStatisticsFiles"
    # "$cleanMgrBase\GameUpdateFiles"
    "$cleanMgrBase\Internet Cache Files"
    # "$cleanMgrBase\Memory Dump Files"
    "$cleanMgrBase\Offline Pages Files"
    "$cleanMgrBase\Old ChkDsk Files"
    "$cleanMgrBase\Previous Installations"
    "$cleanMgrBase\Recycle Bin"
    # "$cleanMgrBase\Service Pack Cleanup"
    "$cleanMgrBase\Setup Log Files"
    "$cleanMgrBase\System error memory dump files"
    "$cleanMgrBase\System error minidump files"
    "$cleanMgrBase\Temporary Files"
    "$cleanMgrBase\Temporary Setup Files"
    "$cleanMgrBase\Temporary Sync Files"
    "$cleanMgrBase\Thumbnail Cache"
    "$cleanMgrBase\Update Cleanup"
    "$cleanMgrBase\Upgrade Discarded Files"
    "$cleanMgrBase\User file versions"
    "$cleanMgrBase\Windows Defender"
    "$cleanMgrBase\Windows Error Reporting Files"
    # "$cleanMgrBase\Windows Error Reporting Archive Files"
    # "$cleanMgrBase\Windows Error Reporting Queue Files"
    # "$cleanMgrBase\Windows Error Reporting System Archive Files"
    # "$cleanMgrBase\Windows Error Reporting System Queue Files"
    "$cleanMgrBase\Windows ESD installation files"
    "$cleanMgrBase\Windows Reset Log Files"
    "$cleanMgrBase\Windows Upgrade Log Files"
)

# Create hashtable for folders to test if they exist when running
$testCleanupFolders = @()
$testCleanupFoldersTable = @{
    "winSysLogs" = "C:\Windows\System32\LogFiles"
    "iisLogs" = "C:\inetpub\logs"
    "winEventLogs" = "C:\Windows\System32\winevt\Logs"
    "sshLogs" = "C:\ProgramData\ssh\logs"
}
$testCleanupFolders += New-Object psobject -Property $testCleanupFoldersTable

$winSysLogs = Test-Path $testCleanupFolders.winSysLogs
$iisLogs = Test-Path $testCleanupFolders.iisLogs
$winEventLogs = Test-Path $testCleanupFolders.winEventLogs
$pimLogs = Test-Path $testCleanupFolders.pimLogs
$sshLogs = Test-Path $testCleanupFolders.sshLogs

If($iisLogs) {
	Get-ChildItem "$($testCleanupFolders.iisLogs)\*.log" -Recurse | Where-Object {$_.LastWriteTime -ge $logRotateDate} | Compress-Archive -DestinationPath $logBackupPath\cleanupFolders-IIS-$logDate.zip -Force
	Write-Output "IIS logs compressed and backed up"
}

If($winSysLogs) {
	Get-ChildItem "$($testCleanupFolders.winSysLogs)\*.log" -Recurse | Where-Object {$_.LastWriteTime -ge $logRotateDate} | Compress-Archive -DestinationPath $logBackupPath\cleanupFolders-winSysLogs-$logDate.zip -Force
	Write-Output "Windows system logs compressed and backed up"
}

If($winEventLogs) {
	Get-ChildItem "$($testCleanupFolders.winEventLogs)\*.evtx" -Recurse | Where-Object {$_.LastWriteTime -ge $logRotateDate} | Compress-Archive -DestinationPath $logBackupPath\cleanupFolders-winEventLogs-$logDate.zip -Force
	Write-Output "Windows Event logs compressed and backed up"
}

If ($sshLogs) {
	Get-ChildItem "$testCleanupFolders.sshLogs\*.log" -Recurse | Where-Object {$_.LastWriteTime -ge $logRotateDate} | Compress-Archive -DestinationPath $logBackupPath\cleanupFolders-pimLogs-$logDate.zip -Force
	Write-Output "SSH logs compressed and backed up"
}

# WBEM Repository Cleanup to help with slow logon times and other WMI-related issues
$wbemRepo = "C:\Windows\System32\wbem\Repository"
$wbemRepoSize = (Get-ChildItem -Path $wbemRepo -Recurse -File | Measure-Object -Property Length -Sum).Sum
$wbemRepoSizeMB = "{0:N2}" -f ($wbemRepoSize / 1MB)
$checkWbemRepo = Invoke-Command -ScriptBlock { winmgmt /verifyrepository }
# Validate output of the WBEM folder size checks and repository consistency.
Switch -Wildcard ($wbemRepoSizeMB) {
    {$wbemRepoSizeMB -ge 200.00 -and $checkWbemRepo -like "*is consistent"} {
        Stop-Service Winmgmt -Force
        Get-ChildItem $wbemRepo -Recurse | Compress-Archive -DestinationPath $logBackupPath\cleanupFolders-wbemRepo-$logDate.zip -Force
        Invoke-Command -ScriptBlock {
            winmgmt /resetrepository
            winmgmt /verifyrepository
        }
        Start-Service winmgmt
        Write-Output "WBEM Repository is consistent but is larger than allowed size and has been reset."
    }
    {$wbemRepoSizeMB -le 199.99 -and $checkWbemRepo -like "*is consistent"} { Write-Output "WBEM Respository is consistent and below allowed size." }
    {$wbemRepoSizeMB -ge 200.00 -and $checkWbemRepo -notlike "*is consistent"} {
        Stop-Service Winmgmt -Force
        Get-ChildItem $wbemRepo -Recurse | Compress-Archive -DestinationPath $logBackupPath\cleanupFolders-wbemRepo-$logDate.zip -Force
        Invoke-Command -ScriptBlock {
            winmgmt /resetrepository
            winmgmt /verifyrepository
        }
        Start-Service winmgmt
        Write-Output "WBEM Repository has been reset due to inconsistencies and it is larger than allowed size."
    }
    {$wbemRepoSizeMB -le 199.99 -and $checkWbemRepo -notlike "*is consistent"} {
        Get-ChildItem $wbemRepo -Recurse | Compress-Archive -DestinationPath $logBackupPath\cleanupFolders-wbemRepo-$logDate.zip -Force
        Invoke-Command -ScriptBlock {
            Stop-Service Winmgmt -Force
            Push-Location "C:\Windows\system32\wbem"
            $wbem = Get-ChildItem "C:\Windows\system32\wbem" -Filter *.dll
            $wbem | ForEach-Object { RegSvr32 -s $_.FullName }
            # Kill this random window that pops up
            tskill wbemtest /a 2>NUL
            scrcons.exe /RegServer
            unsecapp.exe /RegServer
            wbemtest.exe /RegServer
            tskill wbemtest /a 2>NUL
            tskill wbemtest /a 2>NUL
            winmgmt /salvagerepository
            winmgmt /verifyrepository
            wmiadap.exe /RegServer
            wmiapsrv.exe /RegServer
            wmiprvse.exe /RegServer
            Start-Service winmgmt
            Pop-Location
        }
        Write-Output "WBEM Repository has been reset due to inconsistencies but it was not larger than allowed size."
    }
}

# Start folder cleanup
ForEach ($cleanupFolder in $cleanupFolders) {
    Get-ChildItem "$cleanupFolder\*" -Recurse | Remove-Item -Recurse -Force
    Get-ChildItem "C:\Windows\System32\winevt\Logs\" -Recurse -Filter Archive*.evtx | Remove-Item -Recurse -Force
}
Write-Output "All cleanup folders have been cleared."

Write-Output "Using Windows Disk Cleanup to deep clean system files, Windows Update packages, and old Windows installations"
Write-Output "Setting up Windows Disk Cleanup automation settings"

ForEach ($regKey in $cleanMgrRegKeys) {
    $getRegKeyFlags = Get-ItemProperty -Path $regKey -Name StateFlags0001
    If(!$getRegKeyFlags) {
        Write-Output "Setting CleanMgr key`: $($regKey)"
        New-ItemProperty -Path $regKey -Name StateFlags0001 -Value 2 -PropertyType DWord | Out-Null
    }
}

Write-Output "Starting Windows Disk Cleanup..."
Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:1' -WindowStyle Hidden -Wait

# Running DISM cleanup last
Write-Output "Windows Disk Cleanup complete. Starting DISM component cleanup and reset..."
Start-Process -FilePath Dism.exe -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" -WindowStyle Hidden -Wait

# Post-cleanup component corruption scan and repair
Write-Output "DISM finished. Starting SFC scan..."
Start-Process -FilePath sfc.exe -ArgumentList '/scannow' -WindowStyle Hidden -Wait
Write-Output "SFC scan complete. Starting DISM image health restore..."
Start-Process -FilePath Dism.exe -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -WindowStyle Hidden -Wait

Write-Output "Waiting for Windows Disk Cleanup, SFC, and DISM processes. Second wait neccesary as Windows Disk Cleanup, SFC, and DISM spin off separate processes."
Get-Process -Name cleanmgr,dismhost,sfc | Wait-Process

Write-Output "Windows Disk Cleanup and image repair complete, reboot at the next earliest convenience."

Write-Output "Script completed at $(Get-Date)"
Stop-Transcript
