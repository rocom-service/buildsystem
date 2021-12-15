#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

if (-not (Test-Path "$PSScriptRoot\azp\azure_url.txt")) {
  Write-Error "error: missing azure_url.txt"
  exit 1
}
if (-not (Test-Path "$PSScriptRoot\azp\azure_token.txt")) {
  Write-Error "error: missing azure_token.txt"
  exit 1
}
if (-not (Test-Path "$PSScriptRoot\azp\environment.json")) {
  Write-Error "error: missing environment.json"
  exit 1
}

Get-Content "$PSScriptRoot\azp\environment.json" | 
  ConvertFrom-Json |
  ForEach-Object { 
    $obj = $_
    $obj | 
      Get-Member -MemberType NoteProperty |
      ForEach-Object {
        [PSCustomObject]@{
          Name = $_.Name
          Value = $obj.($_.Name)
        }
      }
  } |
  ForEach-Object { [System.Environment]::SetEnvironmentVariable($_.Name, $_.Value) }

$old = Get-Location
Set-Location "$PSScriptRoot\azp\agent"

$work = if (Test-Path Env:AZP_WORK) { ${Env:AZP_WORK} } else { '_work' }
Get-ChildItem .\_work\ -Directory -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -match "\d+" } | 
    Remove-Item -Recurse -Force

try
{
  Write-Host "Configuring Azure Pipelines agent..." -ForegroundColor Cyan
  .\config.cmd --unattended `
    --agent "$(if (Test-Path Env:AZP_AGENT_NAME) { ${Env:AZP_AGENT_NAME} } else { ${Env:computername} })" `
    --url "$(Get-Content "$PSScriptRoot\azp\azure_url.txt")" `
    --auth PAT `
    --token "$(Get-Content "$PSScriptRoot\azp\azure_token.txt")" `
    --pool "$(if (Test-Path Env:AZP_POOL) { ${Env:AZP_POOL} } else { 'Default' })" `
    --work "$work" `
    --replace

  Write-Host "Running Azure Pipelines agent..." -ForegroundColor Cyan
  .\run.cmd
}
finally
{
  Write-Host "Cleanup. Removing Azure Pipelines agent..." -ForegroundColor Cyan
  .\config.cmd remove --unattended `
    --auth PAT `
    --token "$(Get-Content "$PSScriptRoot\azp\azure_token.txt")"

  Set-Location $old
}