$ErrorActionPreference = 'Stop'

if (-not (Test-Path Env:AZP_URL_FILE)) {
  Write-Error "error: missing AZP_URL_FILE environment variable"
  exit 1
}

$Env:AZP_URL = Get-Content $Env:AZP_URL_FILE
Remove-Item Env:AZP_URL_FILE

if (-not (Test-Path Env:AZP_TOKEN_FILE)) {
  Write-Error "error: missing AZP_URL_FILE environment variable"
  exit 1
}

if ($Env:AZP_WORK -and -not (Test-Path Env:AZP_WORK)) {
  New-Item $Env:AZP_WORK -ItemType directory | Out-Null
}

Set-Location \azp\agent

try
{
  Write-Host "Configuring Azure Pipelines agent..." -ForegroundColor Cyan

  .\config.cmd --unattended `
    --agent "$(if (Test-Path Env:AZP_AGENT_NAME) { ${Env:AZP_AGENT_NAME} } else { ${Env:computername} })" `
    --url "$(${Env:AZP_URL})" `
    --auth PAT `
    --token "$(Get-Content ${Env:AZP_TOKEN_FILE})" `
    --pool "$(if (Test-Path Env:AZP_POOL) { ${Env:AZP_POOL} } else { 'Default' })" `
    --work "$(if (Test-Path Env:AZP_WORK) { ${Env:AZP_WORK} } else { '_work' })" `
    --replace

  Write-Host "Running Azure Pipelines agent..." -ForegroundColor Cyan
  .\run.cmd
}
finally
{
  Write-Host "Cleanup. Removing Azure Pipelines agent..." -ForegroundColor Cyan

  .\config.cmd remove --unattended `
    --auth PAT `
    --token "$(Get-Content ${Env:AZP_TOKEN_FILE})"
}