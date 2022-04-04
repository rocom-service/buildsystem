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
$credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
$session = New-PSSession -Credential $credentials -VMName $VMName

Write-Host 'Copying Azure Pipelines agent installation media ' -ForegroundColor Cyan -NoNewline
Write-Host ''
Copy-VMFile -VMName $VMName -CreateFullPath -FileSource Host -SourcePath "$ScriptRoot/../azure_token.txt"   -DestinationPath "H:/azp/azure_token.txt"
Copy-VMFile -VMName $VMName -CreateFullPath -FileSource Host -SourcePath "$ScriptRoot/../azure_url.txt"     -DestinationPath "H:/azp/azure_url.txt"
Copy-VMFile -VMName $VMName -CreateFullPath -FileSource Host -SourcePath "$ScriptRoot/Start-Agent.ps1"      -DestinationPath "H:/Start-Agent.ps1"
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