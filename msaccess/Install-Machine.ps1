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
    [ValidateSet("CreateVM", "SetupInitial", "SetupDrive", "SetupAccess", "SetupAgent", "SetupAutostart", "RestartVM")]
    [string]
    $Stage
)
$ErrorActionPreference = 'Stop'

$ssh = try { Get-Command ssh.exe -ErrorAction Stop } catch { $null }
if ($ssh.Version -lt [version]::new(8,1,0,1)) {
    throw "OpenSSH.Client << Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 >> is needed"
}

if ($Stage -eq "CreateVM" -or $Stage -eq "") {
    Write-Host 'Stoping VM ' -ForegroundColor Cyan -NoNewline
    Stop-VM -Name $VMName -Force -TurnOff -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Write-Host '[done]' -ForegroundColor Green

    Write-Host 'Removing VM ' -ForegroundColor Cyan -NoNewline
    Get-ChildItem "$PSScriptRoot/Virtual Hard Disks/temp.*vhdx"   -ErrorAction SilentlyContinue | Remove-Item
    Get-ChildItem "$PSScriptRoot/Virtual Hard Disks/temp_*.*vhdx" -ErrorAction SilentlyContinue | Remove-Item
    Get-ChildItem "$PSScriptRoot/Virtual Hard Disks/disk.*vhdx"   -ErrorAction SilentlyContinue | Remove-Item
    Get-ChildItem "$PSScriptRoot/Virtual Hard Disks/disk_*.*vhdx" -ErrorAction SilentlyContinue | Remove-Item
    Remove-VM -Name $VMName -Force -ErrorAction SilentlyContinue
    Write-Host '[done]' -ForegroundColor Green

    Write-Host 'Createing VM ' -ForegroundColor Cyan -NoNewline
    Copy-Item -Path $VMDisk -Destination "$PSScriptRoot/Virtual Hard Disks/disk.vhdx"
    New-VHD -Path "$PSScriptRoot/Virtual Hard Disks/temp.vhdx" -SizeBytes 10GB -Dynamic | Out-Null
    New-VM -Name $VMName `
           -MemoryStartupBytes 3GB `
           -BootDevice VHD `
           -SwitchName (Get-VMSwitch | Select-Object -First 1).Name | Out-Null
    Set-VM -Name $VMName `
           -AutomaticCheckpointsEnabled $false `
           -AutomaticStartAction Start `
           -AutomaticStopAction ShutDown | Out-Null

    Add-VMHardDiskDrive -VMName $VMName -Path "$PSScriptRoot/Virtual Hard Disks/disk.vhdx"
    Add-VMHardDiskDrive -VMName $VMName -Path "$PSScriptRoot/Virtual Hard Disks/temp.vhdx"
    Set-VMProcessor -VMName $VMName -HwThreadCountPerCore 0 -Count 2
    Write-Host '[done]' -ForegroundColor Green

    Write-Host 'Starting VM ' -ForegroundColor Cyan -NoNewLine
    Start-VM -Name $VMName
    while ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
    Write-Host ' [done]' -ForegroundColor Green
}

$credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
$session = New-PSSession -Credential $credentials -VMName $VMName
$VMIpAddress = (Get-VM -Name $VMName).Networkadapters.IPAddresses | Select-Object -First 1

if ($Stage -eq "SetupInitial" -or $Stage -eq "") {
    Write-Host 'Initial Windows setup ' -ForegroundColor Cyan -NoNewline
    Invoke-Command -Session $session -ArgumentList $User,$Password,$VMName -ScriptBlock {
        param($User,$Password,$VMName)

        $WindowsUpdatePath = "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\"
        $AutoUpdatePath = "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

        If (Test-Path -Path $WindowsUpdatePath) {
            Remove-Item -Path $WindowsUpdatePath -Recurse
        }

        If (Test-Path -Path $AutoUpdatePath) {
            Set-ItemProperty -Path $AutoUpdatePath -Name NoAutoUpdate -Value 0
            Set-ItemProperty -Path $AutoUpdatePath -Name AUOptions -Value 2
            Set-ItemProperty -Path $AutoUpdatePath -Name ScheduledInstallDay -Value 0
            Set-ItemProperty -Path $AutoUpdatePath -Name ScheduledInstallTime -Value 3
        }

        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" "OSUpgrade" -Value 0 -Type DWord

        # stop Windows Update Service
        Stop-Service wuauserv
        Set-Service wuauserv -StartupType Disabled

        # remove Windows Update Servers
        @(
            "# windowsupdate.microsoft.com"
            "127.0.0.1      windowsupdate.microsoft.com"
            "127.0.0.1      www.windowsupdate.microsoft.com"
            "127.0.0.1      v4.windowsupdate.microsoft.com"
            "127.0.0.1      www.v4.windowsupdate.microsoft.com"
            "# windowsupdate.com"
            "127.0.0.1      windowsupdate.com"
            "127.0.0.1      www.windowsupdate.com"
            "127.0.0.1      download.windowsupdate.com"
            "127.0.0.1      www.download.windowsupdate.com"
            "127.0.0.1      v4.windowsupdate.com"
            "127.0.0.1      www.v4.windowsupdate.com"
            "# windowsupdate.microsoft.nsatc.net"
            "127.0.0.1      windowsupdate.microsoft.nsatc.net"
            "127.0.0.1      v4windowsupdate.microsoft.nsatc.net"
            "# wustat.windows.com"
            "127.0.0.1      wustat.windows.com"
        ) | Add-Content -Path C:\Windows\System32\drivers\etc\hosts

        # login without password
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon" -Value "1" -Type String 
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultUsername" -Value $User -Type String 
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultPassword" -Value $Password -Type String
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "DefaultDomainName" -Value $env:COMPUTERNAME -Type String

        # disable UAC
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0"
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value "0"
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value "1"
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value "0"

        # restart time sync
        net stop w32time  *>&1 | Out-Null
        w32tm /unregister *>&1 | Out-Null
        w32tm /register   *>&1 | Out-Null
        net start w32time *>&1 | Out-Null
    }
    Write-Host '[done]' -ForegroundColor Green

    Write-Host "Installing OpenSSH " -ForegroundColor Cyan -NoNewline
    Invoke-Command -Session $session -ScriptBlock {
        # Install the OpenSSH Server
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null

        # OPTIONAL but recommended:
        Set-Service -Name sshd -StartupType 'Automatic'
        Set-Service -Name ssh-agent -StartupType 'Automatic'

        # Start the sshd service
        Start-Service sshd

        # Confirm the firewall rule is configured. It should be created automatically by setup.
        Get-NetFirewallRule -Name *ssh* | Out-Null

        # There should be a firewall rule named "OpenSSH-Server-In-TCP", which should be enabled
        # If the firewall does not exist, create one
        New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host '[done]' -ForegroundColor Green

    Write-Host 'Createing ssh keys ' -ForegroundColor Cyan -NoNewline
    if (Test-Path "$PSScriptRoot/id_rsa") {
        Write-Host '[skiped]' -ForegroundColor Red
    } else {
        Set-Service -Name ssh-agent -StartupType 'Automatic'
        Start-Service ssh-agent
        ssh-keygen.exe -b 4096 -t rsa -f "$PSScriptRoot/id_rsa" -q -N """"
        & ssh-add "$PSScriptRoot/id_rsa"
        Write-Host '[done]' -ForegroundColor Green
    }

    Write-Host 'Copying ssh keys ' -ForegroundColor Cyan -NoNewline
    Copy-Item -ToSession $session -Path "$PSScriptRoot/id_rsa.pub" -Destination "C:/ProgramData/ssh/administrators_authorized_keys" -Force
    Invoke-Command -Session $session -ScriptBlock { 
        $acl = Get-Acl C:\ProgramData\ssh\administrators_authorized_keys
        $acl.SetAccessRuleProtection($true, $false)
        $administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
        $systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
        $acl.SetAccessRule($administratorsRule)
        $acl.SetAccessRule($systemRule)
        $acl | Set-Acl
    }
    Write-Host '[done]' -ForegroundColor Green

    Write-Host 'Adding ssh server fingerprint to known_hosts ' -ForegroundColor Cyan -NoNewline
    New-Item -ItemType Directory -Path ${ENV:USERPROFILE}/.ssh -ErrorAction SilentlyContinue | Out-Null
    if (Test-Path ${ENV:USERPROFILE}/.ssh/known_hosts) {
        Get-Content ${ENV:USERPROFILE}/.ssh/known_hosts | Where-Object { -not $_.StartsWith("|") } | Out-String | Set-Content $env:USERPROFILE/.ssh/known_hosts
    }
    ssh-keyscan -T 10 -t rsa -4 $VMIpAddress | Set-Content -Path $env:USERPROFILE/.ssh/known_hosts
    Write-Host '[done]' -ForegroundColor Green
}

if ($Stage -eq "SetupDrive" -or $Stage -eq "") {
    Write-Host "Preparing drive " -ForegroundColor Cyan -NoNewline
    Invoke-Command -Session $session -ScriptBlock {
        try {
            Initialize-Disk -Number 1 | Out-Null
            New-Partition -DiskNumber 1 -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel temp | Out-Null
            Get-Partition -DiskNumber 1 -PartitionNumber 2 | Set-Partition -NewDriveLetter H | Out-Null
            Write-Host '[done]' -ForegroundColor Green
        }
        catch {
            Write-Host '[skiped]' -ForegroundColor Red
        }
        New-Item -ItemType Directory "H:/azp/" -ErrorAction SilentlyContinue | Out-Null
    }
}

if ($Stage -eq "SetupAccess" -or $Stage -eq "") {
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

if ($Stage -eq "SetupAgent" -or $Stage -eq "") {
    Write-Host 'Copying Azure Pipelines agent installation media ' -ForegroundColor Cyan -NoNewline
    Write-Host ''
    scp "$PSScriptRoot/../azure_token.txt"   "${User}@${VMIpAddress}:/H:/azp/azure_token.txt"
    scp "$PSScriptRoot/../azure_url.txt"     "${User}@${VMIpAddress}:/H:/azp/azure_url.txt"
    scp "$PSScriptRoot/Start-Agent.ps1"      "${User}@${VMIpAddress}:/H:/Start-Agent.ps1"
    scp "$PSScriptRoot/vsts-agent-win-*.zip" "${User}@${VMIpAddress}:/H:/"
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

if ($Stage -eq "SetupAutostart" -or $Stage -eq "") {
    Write-Host "Installing startup script " -ForegroundColor Cyan -NoNewline
    Invoke-Command -Session $session -ArgumentList $User -ScriptBlock {
        param($User)

        $name = "Start-Agent.ps1"
        Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue | Unregister-ScheduledTask

        $p = @{
            TaskName    = $name
            Description = "starts azure pipeline agent"
            Action      = (
                            New-ScheduledTaskAction `
                                -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
                                -Argument '-NoProfile -NoExit -File H:/Start-Agent.ps1' `
                          )
            Trigger     = (
                            New-ScheduledTaskTrigger `
                                -AtStartup `
                          )
            Settings    = (
                            New-ScheduledTaskSettingsSet `
                                -MultipleInstances Queue `
                                -DontStopOnIdleEnd `
                                -DontStopIfGoingOnBatteries `
                                -Compatibility Win8 `
                          )
            Principal   = (
                            New-ScheduledTaskPrincipal `
                                -UserID "$User" `
                                -LogonType ServiceAccount `
                                -RunLevel Highest `
                          )
        }
        $p.Settings.ExecutionTimeLimit = 'PT0S'
        $p.Settings.IdleSettings.StopOnIdleEnd = $false
        $p.Settings.Compatibility = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.CompatibilityEnum]::Win8

        $p | ConvertTo-Json -Depth 1 | Write-Host -ForegroundColor Yellow
        Register-ScheduledTask @p
    }
    Write-Host '[done]' -ForegroundColor Green
}

if ($Stage -eq "RestartVM" -or $Stage -eq "") {
    Write-Host 'Restarting VM ' -ForegroundColor Cyan -NoNewline
    try {
        Invoke-Command -Session $session -ScriptBlock { 
            Restart-Computer -Force 
        }
    } catch { }
    Write-Host '[done]' -ForegroundColor Green
}

Write-Host 'All done.' -ForegroundColor Green