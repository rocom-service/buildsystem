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
    $VMName = "Testsytem",

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
    $VMDisk = "$PSScriptRoot\..\msaccess\Virtual Hard Disks\template.vhdx",

    [Parameter(Mandatory=$false,
               ParameterSetName="StageParameterSetName",
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [ValidateSet("1", "2", "3", "4", "5", "6", "7", "8")]
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
        -VMDisk $VMDisk `
        -ScriptRoot $PSScriptRoot `
        -DiskSize 40GB
}

if ($Stage -eq "2" -or $Stage -eq "") {
    & $PSScriptRoot/../msaccess/Install-Machine.ps1 `
        -VMName $VMName `
        -User $User `
        -Password $Password `
        -Stage 2
}

if ($Stage -eq "3" -or $Stage -eq "") {
    & $PSScriptRoot/../msaccess/Install-Machine.ps1 `
        -VMName $VMName `
        -User $User `
        -Password $Password `
        -Stage 3
}

if ($Stage -eq "4" -or $Stage -eq "") {
    & $PSScriptRoot/../msaccess/Install-Machine.ps1 `
        -VMName $VMName `
        -User $User `
        -Password $Password `
        -Stage 4
}

$credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
$session = New-PSSession -Credential $credentials -VMName $VMName
$VMIpAddress = (Get-VM -Name $VMName).Networkadapters.IPAddresses | Select-Object -First 1

if ($Stage -eq "5" -or $Stage -eq "") {
    Write-Host "== Stage 5 ==" -ForegroundColor Cyan

    Invoke-Command -Session $session -ScriptBlock {
        Write-Host 'Installing sql server ' -ForegroundColor Cyan -NoNewline
        choco install sql-server-express 7zip.commandline -y
        Write-Host '[done]' -ForegroundColor Green
    }

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

if ($Stage -eq "6" -or $Stage -eq "") {
    Write-Host "== Stage 6 ==" -ForegroundColor Cyan

    Write-Host 'Copying Tau-Office Setup ' -ForegroundColor Cyan -NoNewline
    scp (Get-ChildItem "$PSScriptRoot/setup*.exe" | Select-Object -First 1) "${User}@${VMIpAddress}:/H:/setup.exe"
    Write-Host '[done]' -ForegroundColor Green

    Invoke-Command -Session $session -ScriptBlock {
        Write-Host "Installing Tau-Office " -ForegroundColor Cyan -NoNewline
        & "H:/setup.exe" /S /A
        Start-Sleep -Seconds 1
        (Get-Process setup).WaitForExit()
        Remove-Item "H:/setup.exe"
        Write-Host 'done' -ForegroundColor Green
    }
}

if ($Stage -eq "7" -or $Stage -eq "") {
    Write-Host "== Stage 7 ==" -ForegroundColor Cyan

    Write-Host 'Copying files ' -ForegroundColor Cyan -NoNewline
    $zip = Get-ChildItem "$PSScriptRoot/*.zip" | Select-Object -First 1
    
    Invoke-Command -Session $session -ScriptBlock {
        Get-ChildItem H:/ | Remove-Item -Recurse -Force
    }

    scp $zip "${User}@${VMIpAddress}:/H:/temp.zip"

    Invoke-Command -Session $session -ScriptBlock {
        7z e "H:/temp.zip" -o"H:/" -r -aoa
        Remove-Item -Force "H:/temp.zip"
    }
    Write-Host '[done]' -ForegroundColor Green


    Write-Host 'Restoring data directory ' -ForegroundColor Cyan -NoNewline
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
        '$PSDefaultParameterValues = @{
            "Invoke-SqlCmd:ServerInstance" = ".\SQLEXPRESS"
            "Invoke-SqlCmd:Password" = "rocom"
            "Invoke-SqlCmd:Username" = "sa"
        }' | Set-Content $Profile
    }
    Write-Host '[done]' -ForegroundColor Green
}

if ($Stage -eq "8" -or $Stage -eq "") {
    Write-Host "== Stage 8 ==" -ForegroundColor Cyan

    Write-Host 'Restarting VM ' -ForegroundColor Cyan -NoNewline
    try {
        Invoke-Command -Session $session -ScriptBlock { 
            Restart-Computer -Force 
        }
    } catch { }
    Write-Host '[done]' -ForegroundColor Green
}