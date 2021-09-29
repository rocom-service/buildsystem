$ErrorActionPreference = 'Stop'

New-Item '/azp/agent' -ItemType directory | Out-Null

Write-Host 'Setting up environment...' -ForegroundColor Cyan
[System.Environment]::SetEnvironmentVariable('IsDocker',         'YES',                    [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('AZP_TOKEN_FILE',   'C:/azp/azure_token.txt', [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('AZP_URL_FILE',     'C:/azp/azure_url.txt',   [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('VSO_AGENT_IGNORE', 'AZP_AGENT_NAME,AZP_TOKEN_FILE,ChocolateyLastPathUpdate,chocolateyUseWindowsCompression,PROMPT'
                                                                                         , [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('chocolateyUseWindowsCompression', 
                                                                 'false'                 , [System.EnvironmentVariableTarget]::Machine)

Write-Host 'Determining matching Azure Pipelines agent...' -ForegroundColor Cyan
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$(Get-Content C:/azp/azure_token.txt)"))
$package = Invoke-RestMethod -Headers @{Authorization=("Basic $base64AuthInfo")} "$(Get-Content C:/azp/azure_url.txt)/_apis/distributedtask/packages/agent?platform=win-x64&`$top=1"
$packageUrl = $package[0].Value.downloadUrl
Write-Host $packageUrl

Write-Host 'Downloading and installing Azure Pipelines agent...' -ForegroundColor Cyan
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($packageUrl, "$(Get-Location)/agent.zip")
Expand-Archive -Path "agent.zip" -DestinationPath "/azp/agent"

# thanks to https://github.com/StefanScherer/dockerfiles-windows/tree/main/chocolatey \
Write-Host 'Install chocolatey and some additional development tools...' -ForegroundColor Cyan
mkdir C:\Users\ContainerAdministrator\Documents\WindowsPowerShell
Set-Content C:\Users\ContainerAdministrator\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1 ""
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
try { Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) } catch {}
choco feature disable --name showDownloadProgress
choco install -y nuget.commandline --version=4.9.4
choco install -y git

Write-Host 'Define additional environment variabales for usage in azure pipelines...' -ForegroundColor Cyan
$env:Nuget = (Get-Command nuget).FileVersionInfo.FileVersion