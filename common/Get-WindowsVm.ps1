[CmdletBinding()]
param (
)


Write-Host 'Getting vmsId ' -ForegroundColor Cyan -NoNewline
$vmsId = ((Invoke-WebRequest https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/).Content | Select-String "edgePortal.vmsId = (\d+)").Matches.Groups[1].Value
Write-Host '[done]' -ForegroundColor Green
Write-Host "vmsId is $vmsId"


Write-Host 'Getting download link ' -ForegroundColor Cyan -NoNewline
$hypervVm = (Invoke-RestMethod  https://developer.microsoft.com/en-us/microsoft-edge/api/tools/vms/?id=$vmsId) |
                Select-Object -Last 1 -ExpandProperty software |
                Where-Object name -Like *HyperV* |
                Select-Object -ExpandProperty files |
                Where-Object name -Like *.zip
Write-Host '[done]' -ForegroundColor Green
Write-Host "Download link is:"
$hypervVm | Format-Table


Write-Host 'Downloading VM ' -ForegroundColor Cyan -NoNewline
Remove-Item $env:TEMP\vm.zip -Force -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri $hypervVm.url -OutFile $env:TEMP\vm.zip
Write-Host '[done]' -ForegroundColor Green


Write-Host 'Extracting VM ' -ForegroundColor Cyan -NoNewline
Remove-Item $env:TEMP\vm -Force -Recurse -ErrorAction SilentlyContinue
Expand-Archive -Path $env:TEMP\vm.zip -DestinationPath $env:TEMP\vm
Write-Host '[done]' -ForegroundColor Green


Write-Host 'Copying vhdx ' -ForegroundColor Cyan -NoNewline
Get-ChildItem -Recurse -Filter template.vhdx | Remove-Item -Force 

Get-ChildItem $env:TEMP\vm -Recurse -Filter "*.vhdx" |
    Copy-Item -Destination "$PSScriptRoot\..\msaccess\Virtual Hard Disks\template.vhdx" -Force |
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


Write-Host 'Removeing temp ' -ForegroundColor Cyan -NoNewline
Remove-Item $env:TEMP\vm -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item $env:TEMP\vm.zip -Force -Recurse -ErrorAction SilentlyContinue
Write-Host '[done]' -ForegroundColor Green