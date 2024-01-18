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
    $VMName = "Testsystem",

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
    [string]
    $VMDisk = "$PSScriptRoot/Virtual Hard Disks/template.vhdx",

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Path to data for the testsystem.")]
    [string]
    $DataPath = "$PSScriptRoot/*.zip",

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Path to the setup.")]
    [string]
    $SetupPath = "$PSScriptRoot/*.msi",

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$false,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("1", "2", "3", "4", "5", "6", "7", "8")]
    [int[]]
    $Stage,

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Omits printing '== Stage X =='.")]
    [switch]
    $OmitStagePrinting,

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Set a snapshot after successful stage.")]
    [switch]
    $UseSnapshots,

    [Parameter(Mandatory=$false,
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [switch]
    $Force
)
Begin {
    $ErrorActionPreference = 'Stop'

    try {
        if (-not ($VMDisk | Test-Path -PathType Leaf)) { throw "Parameter VMDisk: File '$VMDisk' not found." }
        if ((Get-ChildItem $DataPath | Measure-Object).Count -le 0)  { throw "Parameter DataPath: File or directory '$DataPath' not found." }
        if ((Get-ChildItem $SetupPath | Measure-Object).Count -le 0) { throw "Parameter SetupPath: File '$SetupPath' not found." }
    } catch {
        if ($Force) {
            Write-Warning $_
        } else {
            throw
        }
    }

    if ($null -eq $Stage) {
        $ParameterList = (Get-Command -Name "$PSScriptRoot/$($MyInvocation.MyCommand)").Parameters
        $Stages = $ParameterList["Stage"].Attributes.ValidValues
    } else {
        $Stages = $Stage
        if (1 -notin $Stages) {
            Get-VMSnapshot -VMName $VMName `
                | Where-Object Name -EQ "after installer stage $($Stage[0] - 1)" `
                | Restore-VMSnapshot
        }
    }
}

Process {
    foreach ($Stage in $Stages) {
        if (-not $OmitStagePrinting) { Write-Host "== Stage $Stage ==" -ForegroundColor Cyan }

        if ($Stage -eq "1") {
            & $PSScriptRoot/../common/New-VM.ps1 `
                -VMName $VMName `
                -VMDisk $VMDisk `
                -ScriptRoot $PSScriptRoot `
                -DiskSize 40GB
        }

        if ($Stage -eq "2") {
            & $PSScriptRoot/../common/Install-Windows.ps1 `
                -VMName $VMName `
                -ScriptRoot $PSScriptRoot `
                -User $User `
                -Password $Password
        }

        if ($Stage -eq "3") {
            & $PSScriptRoot/../msaccess/Install-Machine.ps1 `
                -VMName $VMName `
                -User $User `
                -Password $Password `
                -Stage 3 `
                -OmitStagePrinting
        }

        if ($Stage -eq "4") {
            & $PSScriptRoot/../msaccess/Install-Machine.ps1 `
                -VMName $VMName `
                -User $User `
                -Password $Password `
                -Stage 4 `
                -OmitStagePrinting
        }

        if ((get-vm -Name $VMName).State -eq 'Off') {
            Write-Host 'Starting VM ' -ForegroundColor Cyan -NoNewLine
            Start-VM -Name $VMName
            while ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
            Write-Host ' [done]' -ForegroundColor Green
        }

        $credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
        $session = New-PSSession -Credential $credentials -VMName $VMName

        if ($Stage -eq "5") {
            Write-Host 'Installing tools ' -ForegroundColor Cyan
            Write-Progress -Activity "Installing tools"
            $tools = @(
                "7zip.commandline"
                "dotnet-6.0-desktopruntime"
                "dotnetfx"
                "gsudo"
                "sql-server-express"
            )
            Invoke-Command -Session $session -ArgumentList ($tools -join " ") -ScriptBlock {
                param($arguments)
                choco install $($arguments -split " ") -y
            } |
            Where-Object Length -gt 0 |
            ForEach-Object {
                    $line = $_
                    Write-Progress -Activity "Installing tools" -Status $line
                    Write-Debug $line
                    foreach ($i in $tools) {
                        if ($line.Contains($i) -and !$line.Contains(";")) {
                            Write-Host $line
                        }
                    }
                } `
                -End {
                    Write-Progress -Activity "Installing tools" -Completed
                    Write-Host '[done]' -ForegroundColor Green
                }


            # restart session
            $session = New-PSSession -Credential $credentials -VMName $VMName

            Invoke-Command -Session $session -ScriptBlock {
                $PSDefaultParameterValues = @{
                    "Invoke-SqlCmd:ServerInstance" = ".\SQLEXPRESS"
                }
                Invoke-Sqlcmd "
                USE [master]
                EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 2
                ALTER LOGIN [sa] WITH PASSWORD=N'rocom'
                ALTER LOGIN [sa] ENABLE
                "

                Restart-Service MSSQL`$SQLEXPRESS
            }
        }

        if ($Stage -eq "6") {
            $file = (Get-ChildItem $SetupPath | Select-Object -First 1)

            Write-Host 'Copying Setup ' -ForegroundColor Cyan -NoNewline
            Invoke-Command -Session $session -ArgumentList "H:/setup" -ScriptBlock {
                param($path)
                Get-ChildItem "$path.*" -ErrorAction SilentlyContinue | Remove-Item -Force
            }
            Copy-VMFile -VMName $VMName -SourcePath $file -DestinationPath "H:/setup$($file.Extension)" -CreateFullPath -FileSource Host
            Write-Host '[done]' -ForegroundColor Green

            switch ($file.Extension) {
                ".msi" {
                    Invoke-Command -Session $session -ScriptBlock {
                        $file = "H:\setup.lnk"
                        $WshShell = New-Object -comObject WScript.Shell
                        $Shortcut = $WshShell.CreateShortcut($file)
                        $Shortcut.TargetPath = (Get-Command msiexec).Path
                        $Shortcut.Arguments = "/I H:\setup.msi /l* H:\setup.log INSTALLFOLDER=`"C:\Program Files (x86)\Tau-Office`""
                        $Shortcut.WindowStyle = 3
                        $Shortcut.WorkingDirectory = "H:\"
                        $Shortcut.Save()

                        $bytes = [System.IO.File]::ReadAllBytes($file)
                        $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON (Use –bor to set RunAsAdministrator option and –bxor to unset)
                        [System.IO.File]::WriteAllBytes($file, $bytes)
                    }

                    Write-Host
                    Write-Host "************************************************" -ForegroundColor Magenta
                    Write-Host " We need a logged in user to install tau-office!" -ForegroundColor Magenta
                    Write-Host " Please log into the vm and run H:\setup.lnk .  " -ForegroundColor Magenta
                    Write-Host "                                                " -ForegroundColor Magenta
                    Write-Host " User:     $User                                " -ForegroundColor Magenta
                    Write-Host " Password: $Password                            " -ForegroundColor Magenta
                    Write-Host "************************************************" -ForegroundColor Magenta
                    Read-Host "Press Enter to connect ..."

                    Write-Host 'Connecting RDP ' -ForegroundColor Cyan -NoNewline
                    while ($null -eq ((Get-VM $VMName).NetworkAdapters.IPAddresses | Select-Object -First 1)) { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
                    $IpAddress = (Get-VM $VMName).NetworkAdapters.IPAddresses | Select-Object -First 1
                    while (-not (Test-NetConnection $IpAddress -Port 3389 -InformationLevel Quiet)) { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
                    Start-Sleep 10
                    mstsc /v:$IpAddress
                    Write-Host '[done]' -ForegroundColor Green

                    Read-Host "Press Enter to continue ..."
                }
                ".exe" {
                    Invoke-Command -Session $session -ScriptBlock {
                        Write-Host "Installing " -ForegroundColor Cyan -NoNewline
                        & "H:/setup.exe" /S /A
                        Start-Sleep -Seconds 1
                        (Get-Process setup).WaitForExit()
                        Remove-Item "H:/setup.exe"
                        Write-Host 'done' -ForegroundColor Green
                    }
                }
                default {
                    Write-Host -ForegroundColor Red "This Script can not install $extension-files."
                }
            }
        }

        if ($Stage -eq "7") {
            Write-Host 'Removeing databases ' -ForegroundColor Cyan -NoNewline
            Invoke-Command -Session $session -ScriptBlock {
                $PSDefaultParameterValues = @{
                    "Invoke-SqlCmd:ServerInstance" = ".\SQLEXPRESS"
                    "Invoke-SqlCmd:Password" = "rocom"
                    "Invoke-SqlCmd:Username" = "sa"
                }
                $databases = Invoke-Sqlcmd "SELECT database_id, name FROM sys.databases WHERE database_id > 4" | ForEach-Object name

                $databases | ForEach-Object {
                    Invoke-Sqlcmd "
                    DECLARE @kill varchar(8000) = '';
                    SELECT @kill = @kill + 'kill ' + CONVERT(varchar(5), session_id) + ';'
                    FROM sys.dm_exec_sessions
                    WHERE database_id  = db_id('$_')

                    EXEC(@kill);

                    DROP DATABASE [$_];"
                }
            }
            Write-Host '[done]' -ForegroundColor Green

            Write-Host 'Copying files ' -ForegroundColor Cyan -NoNewline
            $zip = Get-ChildItem "$DataPath" | Select-Object -First 1
            $zip = switch ($zip.GetType().FullName) {
                "System.IO.FileInfo" {
                    $zip
                }
                "System.IO.DirectoryInfo" {
                    "$PSScriptRoot/Data.zip"
                }
            }
            $zip = (Resolve-Path $zip).Path

            Invoke-Command -Session $session -ScriptBlock {
                Get-ChildItem H:/ | Remove-Item -Recurse -Force
            }

            Copy-VMFile -VMName $VMName -SourcePath $zip -DestinationPath "H:/temp.zip" -CreateFullPath -FileSource Host
            Remove-Item "$PSScriptRoot/Data.zip" -ErrorAction SilentlyContinue

            Invoke-Command -Session $session -ScriptBlock {
                7z e "H:/temp.zip" -o"H:/" -r -aoa | Out-Null
                Remove-Item -Force "H:/temp.zip"
            }
            Write-Host '[done]' -ForegroundColor Green


            Write-Host 'Restoring directory ' -ForegroundColor Cyan -NoNewline
            Invoke-Command -Session $session -ScriptBlock {
                Get-ChildItem "C:\Program Files (x86)\Tau-Office\DATEN" | Remove-Item -Force -Recurse

                New-Item -Type Directory -Path "C:\Program Files (x86)\Tau-Office\DATEN\CFG" | Out-Null
                Get-ChildItem H:/ -Recurse -Include "*.xml" | ForEach-Object {
                    Copy-Item $_.FullName "C:\Program Files (x86)\Tau-Office\DATEN\CFG"
                    Remove-Item $_.FullName -Force
                }

                New-Item -Type Directory -Path "C:\Program Files (x86)\Tau-Office\DATEN\Vorlagen" | Out-Null
                Get-ChildItem H:/ -Recurse -File -Exclude "*.zip","*.bak" | ForEach-Object {
                    Copy-Item $_.FullName "C:\Program Files (x86)\Tau-Office\DATEN\Vorlagen"
                    Remove-Item $_.FullName -Force
                }

                Get-ChildItem H:/ -Recurse -Include "*.bak" | Sort-Object { $_.Name.Length } | Select-Object -First 1 | ForEach-Object {
                    $db  = [System.IO.Path]::GetFileNameWithoutExtension($_.Name).ToUpper()

                    $data = @(
                        "[Datasource]"
                        "SERVER=MSSQL"
                        "Zugriff=STANDARD"
                        "ODBC=JA"
                        "Datenbank=$db"
                        "INSTANCE=.\SQLEXPRESS"
                        "USER=sa"
                        "PASSWORT=rocom"
                    ) | Out-String
                    [System.IO.File]::WriteAllLines("C:\Program Files (x86)\Tau-Office\DATEN\Datenquelle.ini", $data, [System.Text.Encoding]::GetEncoding(1250))
                }
            }
            Write-Host '[done]' -ForegroundColor Green


            Write-Host 'Restoring databases ' -ForegroundColor Cyan -NoNewline
            Invoke-Command -Session $session -ScriptBlock {
                $PSDefaultParameterValues = @{
                    "Invoke-SqlCmd:ServerInstance" = ".\SQLEXPRESS"
                    "Invoke-SqlCmd:Password" = "rocom"
                    "Invoke-SqlCmd:Username" = "sa"
                }
                Invoke-Sqlcmd "SELECT database_id, name FROM sys.databases WHERE database_id > 4" | ForEach-Object {
                    Invoke-Sqlcmd "DROP DATABASE [$($_.name)];"
                }

                Get-ChildItem "H:/DATA" -ErrorAction SilentlyContinue | Remove-Item -Force
                New-Item -Type Directory -Path "H:/DATA" -ErrorAction SilentlyContinue | Out-Null

                Get-ChildItem H:/*.bak | ForEach-Object {
                    $files = Invoke-Sqlcmd "RESTORE FILELISTONLY FROM DISK = '$($_.FullName)'"
                    $dat = ($files | Where-Object { $_.Type -eq 'D' }).LogicalName
                    $log = ($files | Where-Object { $_.Type -eq 'L' }).LogicalName
                    $db  = [System.IO.Path]::GetFileNameWithoutExtension($_.Name).ToUpper()

                    Invoke-Sqlcmd  "RESTORE DATABASE [$db] FROM DISK = '$($_.FullName)' WITH
                                    MOVE '$dat' TO 'H:\DATA\$db.mdf',
                                    MOVE '$log' TO 'H:\DATA\$db.log',
                                    REPLACE"

                    Remove-Item $_.FullName -Force
                }

                $databases = Invoke-Sqlcmd "SELECT name FROM sys.databases WHERE database_id > 4" | ForEach-Object { $_.name }
                $databases | ForEach-Object {
                    Invoke-Sqlcmd `
                        -Database $_ `
                        -Query "UPDATE ZR_Account SET PASSWORT = 'B70F9CC091B8F5B44BBF0B4472CDED0F402CCDDF'" `
                        -ErrorAction SilentlyContinue
                }
            }
            Write-Host '[done]' -ForegroundColor Green

            Write-Host 'Writeing Profile' -ForegroundColor Cyan -NoNewline
            Invoke-Command -Session $session -ScriptBlock {
                $script = '$PSDefaultParameterValues = @{
                    "Invoke-SqlCmd:ServerInstance" = ".\SQLEXPRESS"
                    "Invoke-SqlCmd:Password" = "rocom"
                    "Invoke-SqlCmd:Username" = "sa"
                }'

                New-Item "$env:USERPROFILE\Documents\PowerShell" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
                $script | Set-Content "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"

                New-Item "$env:USERPROFILE\Documents\WindowsPowerShell" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
                $script | Set-Content "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
            }
            Write-Host '[done]' -ForegroundColor Green
        }

        if ($Stage -eq "8") {
            Write-Host 'Restarting VM ' -ForegroundColor Cyan -NoNewline
            try {
                Invoke-Command -Session $session -ScriptBlock {
                    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -InformationAction Quiet
                    Restart-Computer -Force
                }
            } catch { }
            while ((Get-VM -Name $VMName).Heartbeat -notlike 'OkApplications*') { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
            Write-Host '[done]' -ForegroundColor Green

            Write-Host 'Connecting RDP ' -ForegroundColor Cyan -NoNewline
            while ($null -eq ((Get-VM $VMName).NetworkAdapters.IPAddresses | Select-Object -First 1)) { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
            $IpAddress = (Get-VM $VMName).NetworkAdapters.IPAddresses | Select-Object -First 1
            while (-not (Test-NetConnection $IpAddress -Port 3389 -InformationLevel Quiet)) { Write-Host "." -ForegroundColor Cyan -NoNewLine ; Start-Sleep 1}
            Start-Sleep 10
            mstsc /v:$IpAddress
            Write-Host '[done]' -ForegroundColor Green
        }


        if ($UseSnapshots) {
            Get-VMSnapshot -VMName $VMName | Remove-VMSnapshot
            Checkpoint-VM -Name $VMName -SnapshotName "after installer stage $Stage"
        }
    }
}

End {
}
