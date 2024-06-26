﻿#Requires -PSEdition Core
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

Write-Host "Installing startup script " -ForegroundColor Cyan -NoNewline
Invoke-Command -Session $session -ArgumentList $User,$Password -ScriptBlock {
    param($User,$Password)

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
        User        = $User
        Password    = $Password
    }
    $p.Settings.ExecutionTimeLimit = 'PT0S'
    $p.Settings.IdleSettings.StopOnIdleEnd = $false
    $p.Settings.Compatibility = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.CompatibilityEnum]::Win8

    $p | ConvertTo-Json -Depth 1 | Write-Host -ForegroundColor Yellow
    Register-ScheduledTask @p
}
Write-Host '[done]' -ForegroundColor Green
