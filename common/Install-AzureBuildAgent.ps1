#Requires -PSEdition Core
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
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
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $User,

    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Password,

    [Parameter(Mandatory=$true,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ScriptRoot
)


$ssh = try { Get-Command ssh.exe -ErrorAction Stop } catch { $null }
if ($ssh.Version -lt [version]::new(8,1,0,1)) {
    throw "OpenSSH.Client << Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 >> is needed"
}

$credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
$session = New-PSSession -Credential $credentials -VMName $VMName
$VMIpAddress = (Get-VM -Name $VMName).Networkadapters.IPAddresses | Select-Object -First 1

Write-Host 'Copying Azure Pipelines agent installation media ' -ForegroundColor Cyan -NoNewline
Write-Host ''
scp "$ScriptRoot/../azure_token.txt"   "${User}@${VMIpAddress}:/H:/azp/azure_token.txt"
scp "$ScriptRoot/../azure_url.txt"     "${User}@${VMIpAddress}:/H:/azp/azure_url.txt"
scp "$ScriptRoot/Start-Agent.ps1"      "${User}@${VMIpAddress}:/H:/Start-Agent.ps1"
scp "$ScriptRoot/vsts-agent-win-*.zip" "${User}@${VMIpAddress}:/H:/"
Write-Host '[done]' -ForegroundColor Green

Invoke-Command -Session $session -ScriptBlock {
    Write-Host 'Determining matching Azure Pipelines agent ' -ForegroundColor Cyan -NoNewline
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$(Get-Content H:/azp/azure_token.txt)"))
    $package = Invoke-RestMethod -Headers @{Authorization=("Basic $base64AuthInfo")} "$(Get-Content H:/azp/azure_url.txt)/_apis/distributedtask/packages/agent?platform=win-x64&`$top=1"
    $packageUrl = [System.Uri]$package[0].Value.downloadUrl
    $filename = $packageUrl.Segments | Select-Object -Last 1
    Write-Host " $filename " -NoNewline
    Write-Host '[done]' -ForegroundColor Green

    Write-Host 'Downloading and installing Azure Pipelines agent ' -ForegroundColor Cyan -NoNewline
    Remove-Item "H:/azp/agent" -Force -Recurse -ErrorAction SilentlyContinue
    if (-not (Test-Path "H:/$filename")) {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($packageUrl, "H:/$filename")
    }
    Expand-Archive -Path "H:/$filename" -DestinationPath "H:/azp/agent"
    Write-Host '[done]' -ForegroundColor Green
}