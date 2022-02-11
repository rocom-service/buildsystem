#Requires -PSEdition Core
#Requires -Module Hyper-V
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $VMName,

    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Path to vhdx drive template.")]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty()]
    [string]
    $VMDisk,

    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ScriptRoot,

    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ulong]
    $DiskSize = 10GB
)

Write-Host 'Stoping VM ' -ForegroundColor Cyan -NoNewline
Stop-VM -Name $VMName -Force -TurnOff -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Write-Host '[done]' -ForegroundColor Green

Write-Host 'Removing VM ' -ForegroundColor Cyan -NoNewline
Get-ChildItem "$ScriptRoot/Virtual Hard Disks/temp.*vhdx"   -ErrorAction SilentlyContinue | Remove-Item
Get-ChildItem "$ScriptRoot/Virtual Hard Disks/temp_*.*vhdx" -ErrorAction SilentlyContinue | Remove-Item
Get-ChildItem "$ScriptRoot/Virtual Hard Disks/disk.*vhdx"   -ErrorAction SilentlyContinue | Remove-Item
Get-ChildItem "$ScriptRoot/Virtual Hard Disks/disk_*.*vhdx" -ErrorAction SilentlyContinue | Remove-Item
Remove-VM -Name $VMName -Force -ErrorAction SilentlyContinue
Write-Host '[done]' -ForegroundColor Green

Write-Host 'Createing VM ' -ForegroundColor Cyan -NoNewline
Copy-Item -Path $VMDisk -Destination "$ScriptRoot/Virtual Hard Disks/disk.vhdx"
New-VHD -Path "$ScriptRoot/Virtual Hard Disks/temp.vhdx" -SizeBytes $DiskSize -Dynamic | Out-Null
New-VM -Name $VMName `
        -MemoryStartupBytes 3GB `
        -BootDevice VHD `
        -SwitchName (Get-VMSwitch | Select-Object -First 1).Name | Out-Null
Set-VM -Name $VMName `
        -AutomaticCheckpointsEnabled $false `
        -AutomaticStartAction Start `
        -AutomaticStopAction ShutDown | Out-Null

Add-VMHardDiskDrive -VMName $VMName -Path "$ScriptRoot/Virtual Hard Disks/disk.vhdx"
Add-VMHardDiskDrive -VMName $VMName -Path "$ScriptRoot/Virtual Hard Disks/temp.vhdx"
Set-VMProcessor -VMName $VMName -HwThreadCountPerCore 0 -Count 2
Write-Host '[done]' -ForegroundColor Green

Write-Host 'Starting VM ' -ForegroundColor Cyan -NoNewLine
Start-VM -Name $VMName
while ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
Write-Host ' [done]' -ForegroundColor Green