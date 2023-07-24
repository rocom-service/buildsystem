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
               ValueFromPipeline=$false,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("1", "2", "3", "4", "5", "6", "7")]
    [int[]]
    $Stage,

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Omits printing '== Stage X =='.")]
    [switch]
    $OmitStagePrinting
)
Begin {
    $ErrorActionPreference = 'Stop'
    if ($null -eq $Stage) {
        $ParameterList = (Get-Command -Name "$PSScriptRoot/$($MyInvocation.MyCommand)").Parameters
        $Stages = $ParameterList["Stage"].Attributes.ValidValues
    } else {
        $Stages = $Stage
    }
}

Process {
    foreach ($Stage in $Stages) {
        if (-not $OmitStagePrinting) { Write-Host "== Stage $Stage ==" -ForegroundColor Cyan }

        if ($Stage -eq "1") {
            & $PSScriptRoot/../common/New-VM.ps1 `
                -VMName $VMName `
                -VMDisk $VMDisk `
                -ScriptRoot $PSScriptRoot
        }

        $credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
        $session = New-PSSession -Credential $credentials -VMName $VMName

        if ($Stage -eq "2") {
            & $PSScriptRoot/../common/Install-Windows.ps1 `
                -VMName $VMName `
                -ScriptRoot $PSScriptRoot `
                -User $User `
                -Password $Password
        }

        if ($Stage -eq "3") {
            Write-Host 'Copying Microsoft Access installation media ' -ForegroundColor Cyan -NoNewline
            # copy folders as zip
            $zip = "$PSScriptRoot\temp.zip"
            if (-not (Test-Path $zip)) {
                Compress-Archive -DestinationPath $zip -Path "$PSScriptRoot/registry"`
                                                        , "$PSScriptRoot/setup"
            }

            Copy-VMFile -VMName $VMName -SourcePath $zip -DestinationPath "H:/temp.zip" -CreateFullPath -FileSource Host

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
                    }
                    Write-Host '[done]' -ForegroundColor Green
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

        if ($Stage -eq "4") {
            Invoke-Command -Session $session -ArgumentList $VMName -ScriptBlock {
                param($VMName)

                Write-Host 'Install chocolatey and additional development tools ' -ForegroundColor Cyan -NoNewline
                [System.Environment]::SetEnvironmentVariable('chocolateyUseWindowsCompression', 'false', [System.EnvironmentVariableTarget]::Machine)
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                if ($null -eq (Get-Command choco -ErrorAction SilentlyContinue)) {
                    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                }
                else {
                    @(
                        "choco feature disable --name showDownloadProgress"
                        "choco feature disable --name exitOnRebootDetected"
                        "cup chocolatey -y"
                    ) |
                        ForEach-Object {
                            Write-Host -ForegroundColor Cyan "  $_"
                            Invoke-Expression $_
                        }
                }
                @(
                    "choco install -y nuget.commandline --version=4.9.4"
                    "choco install -y git"
                ) |
                    ForEach-Object {
                        Write-Host -ForegroundColor Cyan "  $_"
                        Invoke-Expression $_
                    }
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

        if ($Stage -eq "5") {
            & $PSScriptRoot/../common/Install-AzureBuildAgent.ps1 `
                -VMName $VMName `
                -ScriptRoot $PSScriptRoot `
                -User $User `
                -Password $Password
        }

        if ($Stage -eq "6") {
            & $PSScriptRoot/../common/Install-StartupScript.ps1 `
                -VMName $VMName `
                -ScriptRoot $PSScriptRoot `
                -User $User `
                -Password $Password
        }

        if ($Stage -eq "7") {
            Write-Host 'Restarting VM ' -ForegroundColor Cyan -NoNewline
            try {
                Invoke-Command -Session $session -ScriptBlock {
                    Restart-Computer -Force
                }
            } catch { }
            Write-Host '[done]' -ForegroundColor Green
        }
    }
}

End {
}
