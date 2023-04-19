[CmdletBinding()]
param (
)
$ErrorActionPreference = 'Stop'


Write-Host 'Downloading VM ' -ForegroundColor Cyan -NoNewline
Remove-Item $env:TEMP\vm.zip -Force -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri "https://aka.ms/windev_VM_hyperv" -OutFile $env:TEMP\vm.zip
Write-Host '[done]' -ForegroundColor Green


Write-Host 'Extracting VM ' -ForegroundColor Cyan -NoNewline
Remove-Item $env:TEMP\vm -Force -Recurse -ErrorAction SilentlyContinue
Expand-Archive -Path $env:TEMP\vm.zip -DestinationPath $env:TEMP\vm
Write-Host '[done]' -ForegroundColor Green


Write-Host 'Copying vhdx ' -ForegroundColor Cyan -NoNewline
Get-ChildItem -Recurse -Filter template.vhdx | Remove-Item -Force

Get-ChildItem $env:TEMP\vm -Recurse -Filter "*.vhdx" |
    Move-Item -Destination "$PSScriptRoot\..\msaccess\Virtual Hard Disks\template.vhdx" -Force |
    Out-Null

$old = Get-Location
foreach ($location in @("$PSScriptRoot\..\vb6\Virtual Hard Disks\",
                        "$PSScriptRoot\..\test\Virtual Hard Disks\"))
{
    Set-Location $location
    New-Item -ItemType HardLink -Name template.vhdx -Value "$PSScriptRoot\..\msaccess\Virtual Hard Disks\template.vhdx" |
        Out-Null
}
Set-Location $old
Write-Host '[done]' -ForegroundColor Green


Write-Host 'Removing temp ' -ForegroundColor Cyan -NoNewline
Remove-Item $env:TEMP\vm -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\vm.zip -Force -Recurse -ErrorAction SilentlyContinue
Write-Host '[done]' -ForegroundColor Green
