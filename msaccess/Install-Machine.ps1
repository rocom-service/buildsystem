#Requires -PSEdition Core
#Requires -Module Hyper-V
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $VMName = "Access 2010 Agent",

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $User = "IEUser",

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Password = "Passw0rd!",

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Path to vhdx drive template.")]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty()]
    [string]
    $VMDisk = "$PSScriptRoot/Virtual Hard Disks/template.vhdx",

    [Parameter(Mandatory=$false,
               ParameterSetName="StageParameterSetName",
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("1", "2", "3", "4", "5", "6", "7")]
    [string]
    $Stage
)
$ErrorActionPreference = 'Stop'

$ssh = try { Get-Command ssh.exe -ErrorAction Stop } catch { $null }
if ($ssh.Version -lt [version]::new(8,1,0,1)) {
    throw "OpenSSH.Client << Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 >> is needed"
}

if ($Stage -eq "1" -or $Stage -eq "") {
    Write-Host "== Stage 1 ==" -ForegroundColor Cyan
    & $PSScriptRoot/../common/New-VM.ps1 `
        -VMName $VMName `
        -ScriptRoot $PSScriptRoot
}

$credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
$session = New-PSSession -Credential $credentials -VMName $VMName
$VMIpAddress = (Get-VM -Name $VMName).Networkadapters.IPAddresses | Select-Object -First 1

if ($Stage -eq "2" -or $Stage -eq "") {
    Write-Host "== Stage 2 ==" -ForegroundColor Cyan
    & $PSScriptRoot/../common/Install-Windows.ps1 `
        -VMName $VMName `
        -ScriptRoot $PSScriptRoot `
        -User $User `
        -Password $Password
}

if ($Stage -eq "3" -or $Stage -eq "") {
    Write-Host "== Stage 3 ==" -ForegroundColor Cyan
    Write-Host 'Copying Microsoft Access installation media ' -ForegroundColor Cyan -NoNewline

    # copy folders as zi
    $zip = "$PSScriptRoot\temp.zip"
    if (-not (Test-Path $zip)) {
        Compress-Archive -DestinationPath $zip -Path "$PSScriptRoot/registry"`
                                                   , "$PSScriptRoot/setup"
    }

    scp $zip "${User}@${VMIpAddress}:/H:/temp.zip"

    Invoke-Command -Session $session -ScriptBlock {
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue "H:/registry"
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue "H:/setup"
        Expand-Archive -Force -Path "H:/temp.zip" -DestinationPath "H:/"
        Remove-Item -Force -ErrorAction SilentlyContinue "H:/temp.zip"
    }
    Remove-Item -Force -ErrorAction SilentlyContinue $zip
    Write-Host '[done]' -ForegroundColor Green

    Invoke-Command -Session $session -ScriptBlock {
        Write-Host "Installing Microsoft Access " -ForegroundColor Cyan -NoNewline
        if (Test-Path 'C:/Program Files (x86)/Microsoft Office/Office14/MSACCESS.EXE') {
            Write-Host '[skiped]' -ForegroundColor Red
        } else {
            & "H:/setup/setup.exe"

            $estimated = 530
            while (-not (Get-Process setup).WaitForExit(3000)) {
                $estimated -= 3
                Write-Progress -Activity "Installing Microsoft Access" -SecondsRemaining $estimated
                Write-Host '.' -ForegroundColor Cyan -NoNewline
            }
            Write-Host 'done' -ForegroundColor Green
            Write-Progress -Activity "Installing Microsoft Access" -Completed
        }
    }

    if ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') {
        Write-Host "Waiting for Reboot " -ForegroundColor Cyan -NoNewline
        while ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
        Write-Host ' [done]' -ForegroundColor Green
    }
    
    Invoke-Command -Session $session -ScriptBlock {
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue H:/setup

        Get-Content H:/registry/TrustedLocations.reg | ForEach-Object {
            if ($_.StartsWith("`"Path`"")) {
                "`"Path`"=`"H:\\azp\\agent\\_work\\`""
            } else {
                $_
            }
        } | Set-Content H:/registry/TrustedLocations.reg.tmp

        reg import "H:\registry\TrustedLocations.reg.tmp" *>&1 | Out-Null
        reg import "H:\registry\UserInfo.reg" *>&1 | Out-Null
        reg import "H:\registry\General.reg" *>&1 | Out-Null

        $app = New-Object -ComObject Access.Application
        Write-Host "Access version installed: $((Get-Process msaccess -FileVersionInfo).FileVersion)"
        $app.Quit()
        Stop-Process -ProcessName msaccess -Force -ErrorAction SilentlyContinue
    }
}

if ($Stage -eq "4" -or $Stage -eq "") {
    Write-Host "== Stage 4 ==" -ForegroundColor Cyan
    Invoke-Command -Session $session -ArgumentList $VMName -ScriptBlock {
        param($VMName)

        Write-Host 'Install chocolatey and additional development tools ' -ForegroundColor Cyan -NoNewline
        [System.Environment]::SetEnvironmentVariable('chocolateyUseWindowsCompression', 'false', [System.EnvironmentVariableTarget]::Machine)
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        if ($null -eq (Get-Command choco -ErrorAction SilentlyContinue)) {
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        }
        else {
            choco feature disable --name showDownloadProgress
            cup chocolatey -y
        }
        choco install -y nuget.commandline --version=4.9.4
        choco install -y git
        Write-Host '[done]' -ForegroundColor Green
        
        Write-Host 'Define additional environment variabales for usage in azure pipelines ' -ForegroundColor Cyan -NoNewline
        @{
            AZP_AGENT_NAME   = "$VMName"
            VSO_AGENT_IGNORE = "AZP_AGENT_NAME,AZP_TOKEN_FILE,ChocolateyLastPathUpdate,chocolateyUseWindowsCompression,PROMPT"
            MsAccess         = "$((Get-Command 'C:/Program Files (x86)/Microsoft Office/Office14/MSACCESS.EXE').Version.ToString())"
            Git              = "$((Get-Command 'C:/Program Files/Git/cmd/git.exe').Version.ToString())"
            Nuget            = "$((Get-Command 'C:/ProgramData/chocolatey/bin/nuget.exe').Version.ToString())"
        } |
            ConvertTo-Json |
            Set-Content -Force -Path "H:/azp/environment.json"
        Write-Host '[done]' -ForegroundColor Green
    }
}

if ($Stage -eq "5" -or $Stage -eq "") {
    Write-Host "== Stage 5 ==" -ForegroundColor Cyan
    & $PSScriptRoot/../common/Install-AzureBuildAgent.ps1 `
        -VMName $VMName `
        -ScriptRoot $PSScriptRoot `
        -User $User `
        -Password $Password
}

if ($Stage -eq "6" -or $Stage -eq "") {
    Write-Host "== Stage 6 ==" -ForegroundColor Cyan
     & $PSScriptRoot/../common/Install-StartupScript.ps1 `
        -VMName $VMName `
        -ScriptRoot $PSScriptRoot `
        -User $User `
        -Password $Password
}

if ($Stage -eq "7" -or $Stage -eq "") {
    Write-Host "== Stage 7 ==" -ForegroundColor Cyan
    Write-Host 'Restarting VM ' -ForegroundColor Cyan -NoNewline
    try {
        Invoke-Command -Session $session -ScriptBlock { 
            Restart-Computer -Force 
        }
    } catch { }
    Write-Host '[done]' -ForegroundColor Green
}

Write-Host 'All done.' -ForegroundColor Green