#Requires -Module Hyper-V
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
[CmdletBinding()]
param (
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
    $Password = "Passw0rd!"
)
$ErrorActionPreference = 'Stop'

$pwsh = (Get-Process -PID $PID)

foreach ($vm in Get-VM) {
    $cmd = {
        # :( not working:
        # param([string] $User, [string] $Password, [string] $VMName)
        $credentials = New-Object System.Management.Automation.PSCredential $User, (ConvertTo-SecureString $Password -AsPlainText -Force)
        $session = New-PSSession -Credential $credentials -VMName $VMName

        Invoke-Command -Session $session -ScriptBlock {
            H:\Start-Agent.ps1
        }
        Read-Host
    }

    $parameter = @{
        FilePath=$pwsh.Path
        ArgumentList=@(
                        "-NoExit"
                        "-Command"
                        $cmd.ToString().Replace("`$User", "'$User'").Replace("`$Password", "'$Password'").Replace("`$VMName", "'$($vm.Name)'")
                        # :( not working:
                        # "-Args"
                        # $User
                        # $Password
                        # $vm.Name
                      )
        Wait=$false
    }

    # Write-Host -ForegroundColor Yellow "Start-Process $($parameter | ConvertTo-Json)"
    Start-Process @parameter
}