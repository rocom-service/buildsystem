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
    $VMName = "Visual Basic 6 Agent",

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
            Write-Host "== Stage 1 ==" -ForegroundColor Cyan
            & $PSScriptRoot/../common/New-VM.ps1 `
                -VMName $VMName `
                -VMDisk $VMDisk `
                -ScriptRoot $PSScriptRoot
        }

        $session = $null
        while ($null -eq $session) {
            $credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
            try {
                $session = New-PSSession -Credential $credentials -VMName $VMName
            } catch {
                $session = $null
                Write-Host "Failed to connect to VM. Retrying in 5 seconds..." -ForegroundColor Red
                Start-Sleep -Seconds 5
            }
        }

        if ($Stage -eq "2") {
            Write-Host "== Stage 2 ==" -ForegroundColor Cyan
            & $PSScriptRoot/../common/Install-Windows.ps1 `
                -VMName $VMName `
                -ScriptRoot $PSScriptRoot `
                -User $User `
                -Password $Password
        }

        if ($Stage -eq "3") {
            Write-Host "== Stage 3 ==" -ForegroundColor Cyan
            Write-Host 'Copying Microsoft Visual Basic installation media ' -ForegroundColor Cyan -NoNewline
            Write-Host ''

            $zip = "$PSScriptRoot\temp.zip"
            if (-not (Test-Path $zip)) {
                Compress-Archive -DestinationPath $zip -Path "$PSScriptRoot/1VS60Ent"`
                                                        , "$PSScriptRoot/3SP6_VSEnt"`
                                                        , "$PSScriptRoot/install.ps1"`
                                                        , "$PSScriptRoot/Key.txt"
            }

            Copy-VMFile -VMName $VMName -SourcePath $zip -DestinationPath "H:/temp.zip" -CreateFullPath -FileSource Host

            Invoke-Command -Session $session -ScriptBlock {
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue "H:/1VS60Ent"
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue "H:/3SP6_VSEnt"
                Expand-Archive -Force -Path "H:/temp.zip" -DestinationPath "H:/"
                Remove-Item -Force -ErrorAction SilentlyContinue "H:/temp.zip"
            }
            Remove-Item -Force -ErrorAction SilentlyContinue $zip
            Write-Host '[done]' -ForegroundColor Green
            
            Write-Host "************************************************" -ForegroundColor Magenta
            Write-Host " We need a logged in user to install vb6!       " -ForegroundColor Magenta
            Write-Host " Please log into the vm and run H:\install.ps1 ." -ForegroundColor Magenta
            Write-Host "                                                " -ForegroundColor Magenta
            Write-Host " User:     $User                                " -ForegroundColor Magenta
            Write-Host " Password: $Password                            " -ForegroundColor Magenta
            Write-Host "************************************************" -ForegroundColor Magenta

            Invoke-Command -Session $session -ScriptBlock {
                Write-Host "Installing Microsoft Visual Basic 6 " -ForegroundColor Cyan -NoNewline
                if (Test-Path 'C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.EXE') {
                    Write-Host '[skiped]' -ForegroundColor Red
                } else {
                    while (-not ( (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path -like "*\VB98\*")) {
                        Write-Host "." -ForegroundColor Cyan -NoNewline
                        Start-Sleep -Seconds 10
                    }
                    Write-Host '[done]' -ForegroundColor Green
                }
            }

            try {
                Invoke-Command -Session $session -ScriptBlock { 
                    Restart-Computer -Force 
                }
            } catch { }


            if ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') {
                Write-Host "Waiting for Reboot " -ForegroundColor Cyan -NoNewline
                while ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
                Write-Host ' [done]' -ForegroundColor Green
            }
            
            $credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
            $session = New-PSSession -Credential $credentials -VMName $VMName
            Invoke-Command -Session $session -ScriptBlock {
                Write-Host "Visual Basic version installed: $((Get-Command vb6).Version.ToString())"
            }
        }

        if ($Stage -eq "4") {
            Write-Host "== Stage 4 ==" -ForegroundColor Cyan
            & $PSScriptRoot/../common/Install-AzureBuildAgent.ps1 `
                -VMName $VMName `
                -ScriptRoot $PSScriptRoot `
                -User $User `
                -Password $Password
        }

        if ($Stage -eq "5") {
            Write-Host "== Stage 5 ==" -ForegroundColor Cyan
            Write-Host 'Install chocolatey and additional development tools ' -ForegroundColor Cyan -NoNewline
            Invoke-Command -Session $session -ArgumentList $VMName -ScriptBlock {
                param($VMName)

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
                choco install -y windows-sdk-10.1
                choco install -y pwsh
                Write-Host '[done]' -ForegroundColor Green
            }

            Invoke-Command -Session $session -ScriptBlock {
                Write-Host 'Define additional environment variabales for usage in azure pipelines ' -ForegroundColor Cyan -NoNewline
                @{
                    AZP_AGENT_NAME   = "$VMName"
                    VSO_AGENT_IGNORE = "AZP_AGENT_NAME,AZP_TOKEN_FILE,ChocolateyLastPathUpdate,chocolateyUseWindowsCompression,PROMPT"
                    VisualBasic      = "$((Get-Command vb6).Version.ToString())"
                    Git              = "$((Get-Command git).Version.ToString())"
                    Nuget            = "$((Get-Command nuget).Version.ToString())"
                } |
                    ConvertTo-Json |
                    Set-Content -Force -Path "H:/azp/environment.json"
            }
            Write-Host '[done]' -ForegroundColor Green
        }

        if ($Stage -eq "6") {
            Write-Host "== Stage 6 ==" -ForegroundColor Cyan
            & $PSScriptRoot/../common/Install-StartupScript.ps1 `
                -VMName $VMName `
                -ScriptRoot $PSScriptRoot `
                -User $User `
                -Password $Password
        }

        if ($Stage -eq "7") {
            Write-Host "== Stage 7 ==" -ForegroundColor Cyan
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