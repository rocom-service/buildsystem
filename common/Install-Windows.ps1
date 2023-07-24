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

Write-Host 'Initial Windows setup ' -ForegroundColor Cyan -NoNewline
$Gateway = Get-NetIPAddress -AddressFamily IPv4 |
                Where-Object InterfaceAlias -Like "*Default Switch*" |
                ForEach-Object IPAddress

Invoke-Command -Session $session -ArgumentList $User,$Password,$VMName,$Gateway -ScriptBlock {
    param($User,$Password,$VMName,$Gateway)

    Rename-Computer $($VMName -replace " ","") -Force

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

    # set fixed ip address
    Get-NetIPAddress -AddressFamily IPv4 |
        Select-Object -First 1 |
        ForEach-Object {
            if (! $_.IPAddress.StartsWith("192.")) {
                $Address = @(
                            $Gateway.Split(".") | Select-Object -First 3
                            $_.IPAddress.Split(".") | Select-Object -Last 1
                        ) -join "."
                New-NetIPAddress `
                    -InterfaceIndex $_.InterfaceIndex `
                    -AddressFamily IPv4 `
                    -IPAddress $Address `
                    -DefaultGateway $Gateway `
                    -PrefixLength 24 |
                        Out-Null
            }

            Set-DnsClientServerAddress `
                -InterfaceIndex $_.InterfaceIndex `
                -ServerAddresses "8.8.8.8","8.8.4.4"
        }
    
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

    # enable rdp
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    # restart time sync
    net stop w32time  *>&1 | Out-Null
    w32tm /unregister *>&1 | Out-Null
    w32tm /register   *>&1 | Out-Null
    net start w32time *>&1 | Out-Null

}
Write-Host '[done]' -ForegroundColor Green


Write-Host "Setting System to german " -ForegroundColor Cyan -NoNewline
Invoke-Command -Session $session -ScriptBlock {
    '["Windows Registry Editor Version 5.00","","[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage]","\"10000\"=\"c_10000.nls\"","\"10001\"=\"c_10001.nls\"","\"10002\"=\"c_10002.nls\"","\"10003\"=\"c_10003.nls\"","\"10004\"=\"c_10004.nls\"","\"10005\"=\"c_10005.nls\"","\"10006\"=\"c_10006.nls\"","\"10007\"=\"c_10007.nls\"","\"10008\"=\"c_10008.nls\"","\"10010\"=\"c_10010.nls\"","\"10017\"=\"c_10017.nls\"","\"10021\"=\"c_10021.nls\"","\"10029\"=\"c_10029.nls\"","\"10079\"=\"c_10079.nls\"","\"10081\"=\"c_10081.nls\"","\"10082\"=\"c_10082.nls\"","\"1026\"=\"c_1026.nls\"","\"1047\"=\"c_1047.nls\"","\"1140\"=\"c_1140.nls\"","\"1141\"=\"c_1141.nls\"","\"1142\"=\"c_1142.nls\"","\"1143\"=\"c_1143.nls\"","\"1144\"=\"c_1144.nls\"","\"1145\"=\"c_1145.nls\"","\"1146\"=\"c_1146.nls\"","\"1147\"=\"c_1147.nls\"","\"1148\"=\"c_1148.nls\"","\"1149\"=\"c_1149.nls\"","\"1250\"=\"c_1250.nls\"","\"1251\"=\"c_1251.nls\"","\"1252\"=\"c_1252.nls\"","\"1253\"=\"c_1253.nls\"","\"1254\"=\"c_1254.nls\"","\"1255\"=\"c_1255.nls\"","\"1256\"=\"c_1256.nls\"","\"1257\"=\"c_1257.nls\"","\"1258\"=\"c_1258.nls\"","\"1361\"=\"c_1361.nls\"","\"20000\"=\"c_20000.nls\"","\"20001\"=\"c_20001.nls\"","\"20002\"=\"c_20002.nls\"","\"20003\"=\"c_20003.nls\"","\"20004\"=\"c_20004.nls\"","\"20005\"=\"c_20005.nls\"","\"20105\"=\"c_20105.nls\"","\"20106\"=\"c_20106.nls\"","\"20107\"=\"c_20107.nls\"","\"20108\"=\"c_20108.nls\"","\"20127\"=\"c_20127.nls\"","\"20261\"=\"c_20261.nls\"","\"20269\"=\"c_20269.nls\"","\"20273\"=\"c_20273.nls\"","\"20277\"=\"c_20277.nls\"","\"20278\"=\"c_20278.nls\"","\"20280\"=\"c_20280.nls\"","\"20284\"=\"c_20284.nls\"","\"20285\"=\"c_20285.nls\"","\"20290\"=\"c_20290.nls\"","\"20297\"=\"c_20297.nls\"","\"20420\"=\"c_20420.nls\"","\"20423\"=\"c_20423.nls\"","\"20424\"=\"c_20424.nls\"","\"20833\"=\"c_20833.nls\"","\"20838\"=\"c_20838.nls\"","\"20866\"=\"c_20866.nls\"","\"20871\"=\"c_20871.nls\"","\"20880\"=\"c_20880.nls\"","\"20905\"=\"c_20905.nls\"","\"20924\"=\"c_20924.nls\"","\"20932\"=\"c_20932.nls\"","\"20936\"=\"c_20936.nls\"","\"20949\"=\"c_20949.nls\"","\"21025\"=\"c_21025.nls\"","\"21027\"=\"c_21027.nls\"","\"21866\"=\"c_21866.nls\"","\"28591\"=\"C_28591.NLS\"","\"28592\"=\"C_28592.NLS\"","\"28593\"=\"c_28593.nls\"","\"28594\"=\"C_28594.NLS\"","\"28595\"=\"C_28595.NLS\"","\"28596\"=\"C_28596.NLS\"","\"28597\"=\"C_28597.NLS\"","\"28598\"=\"c_28598.nls\"","\"28599\"=\"c_28599.nls\"","\"28603\"=\"c_28603.nls\"","\"28605\"=\"c_28605.nls\"","\"37\"=\"c_037.nls\"","\"38598\"=\"c_28598.nls\"","\"437\"=\"c_437.nls\"","\"500\"=\"c_500.nls\"","\"50220\"=\"c_is2022.dll\"","\"50221\"=\"c_is2022.dll\"","\"50222\"=\"c_is2022.dll\"","\"50225\"=\"c_is2022.dll\"","\"50227\"=\"c_is2022.dll\"","\"50229\"=\"c_is2022.dll\"","\"51949\"=\"c_20949.nls\"","\"52936\"=\"c_is2022.dll\"","\"54936\"=\"c_g18030.dll\"","\"55000\"=\"c_gsm7.dll\"","\"55001\"=\"c_gsm7.dll\"","\"55002\"=\"c_gsm7.dll\"","\"55003\"=\"c_gsm7.dll\"","\"55004\"=\"c_gsm7.dll\"","\"57002\"=\"c_iscii.dll\"","\"57003\"=\"c_iscii.dll\"","\"57004\"=\"c_iscii.dll\"","\"57005\"=\"c_iscii.dll\"","\"57006\"=\"c_iscii.dll\"","\"57007\"=\"c_iscii.dll\"","\"57008\"=\"c_iscii.dll\"","\"57009\"=\"c_iscii.dll\"","\"57010\"=\"c_iscii.dll\"","\"57011\"=\"c_iscii.dll\"","\"708\"=\"c_708.nls\"","\"720\"=\"c_720.nls\"","\"737\"=\"c_737.nls\"","\"775\"=\"c_775.nls\"","\"850\"=\"c_850.nls\"","\"852\"=\"c_852.nls\"","\"855\"=\"c_855.nls\"","\"857\"=\"c_857.nls\"","\"858\"=\"c_858.nls\"","\"860\"=\"c_860.nls\"","\"861\"=\"c_861.nls\"","\"862\"=\"c_862.nls\"","\"863\"=\"c_863.nls\"","\"864\"=\"c_864.nls\"","\"865\"=\"c_865.nls\"","\"866\"=\"c_866.nls\"","\"869\"=\"c_869.nls\"","\"870\"=\"c_870.nls\"","\"874\"=\"c_874.nls\"","\"875\"=\"c_875.nls\"","\"932\"=\"c_932.nls\"","\"936\"=\"c_936.nls\"","\"949\"=\"c_949.nls\"","\"950\"=\"c_950.nls\"","\"AllowDeprecatedCP\"=dword:42414421","\"OEMHAL\"=\"vgaoem.fon\"","\"ACP\"=\"1252\"","\"OEMCP\"=\"850\"","\"MACCP\"=\"10000\"","","[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage\\EUDCCodeRange]","\"932\"=\"F040-F9FC\"","\"936\"=\"AAA1-AFFE,F8A1-FEFE,A140-A7A0\"","\"949\"=\"C9A1-C9FE,FEA1-FEFE\"","\"950\"=\"FA40-FEFE,8E40-A0FE,8140-8DFE,C6A1-C8FE\"",""]' |
        ConvertFrom-Json |
        Set-Content "$env:TEMP\oemcp.reg"

    reg import "$env:TEMP\oemcp.reg" *>&1 | Out-Null

    # set date format to german
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sCountry -Value "Germany" | Out-Null
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sLongDate -Value "dddd, d. MMMM yyyy" | Out-Null
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "dd.MM.yyyy" | Out-Null
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortTime -Value "HH:mm" | Out-Null
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss" | Out-Null
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sYearMonth -Value "MMMM yyyy" | Out-Null
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name iFirstDayOfWeek -Value 0 | Out-Null
}
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
