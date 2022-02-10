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
if (Test-Path "$ScriptRoot/id_rsa") {
    Write-Host '[skiped]' -ForegroundColor Red
} else {
    Set-Service -Name ssh-agent -StartupType 'Automatic'
    Start-Service ssh-agent
    ssh-keygen.exe -b 4096 -t rsa -f "$ScriptRoot/id_rsa" -q -N """"
    & ssh-add "$ScriptRoot/id_rsa"
    Write-Host '[done]' -ForegroundColor Green
}

Write-Host 'Copying ssh keys ' -ForegroundColor Cyan -NoNewline
Copy-Item -ToSession $session -Path "$ScriptRoot/id_rsa.pub" -Destination "C:/ProgramData/ssh/administrators_authorized_keys" -Force
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
ssh-keyscan -T 10 -t ecdsa-sha2-nistp256 -4 $VMIpAddress | Set-Content -Path $env:USERPROFILE/.ssh/known_hosts
Write-Host '[done]' -ForegroundColor Green

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