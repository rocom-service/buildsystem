# thanks to https://github.com/Ro-Fo/Vb6IdeDocker and https://github.com/telyn/docker-vb6 !

# insert your details here
$vs_organisation = "rocom service GmbH"
$vs_name = $env:USERNAME
$vs_key = [String]::Join("", [array]((Get-Content $PSScriptRoot\Key.txt | Select-String -Pattern \d+ -AllMatches).Matches | ForEach-Object { $_.Value } ))




# check environment before anything else
if (![Environment]::Is64BitOperatingSystem) {
    Write-Host -ForegroundColor Red "This script does not work with 32-Bit OS. Sorry."
}

# check folder 1VS60Ent
if (!(Test-Path "$PSScriptRoot\1VS60Ent\ACMSetup.Exe")) {
    Write-Host -ForegroundColor Red "Installation media 1VS60Ent is missing. Please copy your VisualStudio 6.0 setup files into .\1VS60Ent\ and try again."
}

# check folder 3SP6_VSEnt
if (!(Test-Path "$PSScriptRoot\3SP6_VSEnt\ACMSetup.Exe")) {
    Write-Host -ForegroundColor Red "Installation media 3SP6_VSEnt is missing. Please copy your VisualStudio 6.0 SP6 setup files into .\3SP6_VSEnt\ and try again."
}

# check folder Key.txt
if (!(Test-Path "$PSScriptRoot\Key.txt")) {
    Write-Host -ForegroundColor Red "Productkey is missing. Please copy your procuct key into .\Key.txt "
}

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}





# extract java runtime
New-Item -ItemType Directory $env:temp\MSJAVX86 | Out-Null

$cmd = '"' + $PSScriptRoot + '\1VS60Ent\IE4\MSJAVX86.EXE"'
$arguments = '/q /c /t:' + $env:temp + '\MSJAVX86'
Write-Host -ForegroundColor Yellow $cmd $arguments
Start-Process $cmd -ArgumentList $arguments -Verb RunAs -Wait

$cmd = 'expand.exe'
$arguments = $env:temp + '\MSJAVX86\javabase.cab "' + $env:SystemRoot + '"\SysWOW64\" -f:msjava.dll'
Write-Host -ForegroundColor Yellow $cmd $arguments
Start-Process $cmd -ArgumentList $arguments -Verb RunAs -Wait

Remove-Item -Recurse -Force $env:temp\MSJAVX86



# mark the setup wizard run successful
if (!(Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\6.0\Setup\Visual Studio 98\SetupWizard")) {
    Set-Location "HKLM:\SOFTWARE\WOW6432Node\Microsoft"
    New-Item "VisualStudio" | Set-Location
    New-Item "6.0" | Set-Location
    New-Item "Setup" | Set-Location
    New-Item "Visual Studio 98" | Set-Location
    New-Item "SetupWizard" | Set-Location
    New-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\6.0\Setup\Visual Studio 98\SetupWizard" -Name aspo -Value 0 -PropertyType DWord | Out-Null
}



# install Visual Basic 6
Set-Location "$PSScriptRoot\1VS60Ent\"
$cmd = '"' + $PSScriptRoot + '\1VS60Ent\ACMSetup.Exe"'
$arguments = '/k ' + $vs_key + ' /n "' + $vs_name + '" /o "' + $vs_organisation + '" /T vb6only.STF  /B 1 /GC "' + $env:temp + '\install_vb6.log" /QTN'
Write-Host -ForegroundColor Yellow $cmd $arguments
Start-Process $cmd -ArgumentList $arguments -Verb RunAs -Wait



# install Visual Basic 6 Service Pack 6
Copy-Item "$PSScriptRoot\1VS60Ent\vb6only.STF" "$PSScriptRoot\3SP6_VSEnt\ACMSetup.STF"
Copy-Item "$PSScriptRoot\1VS60Ent\vb6only.STF" "$PSScriptRoot\3SP6_VSEnt\vb6only.STF"

Set-Location "$PSScriptRoot\3SP6_VSEnt"
$cmd = '"' + $PSScriptRoot + '\3SP6_VSEnt\setupsp6.Exe"'
$arguments = '/k ' + $vs_key + ' /n "' + $vs_name + '" /o "' + $vs_organisation + '" /B 1 /GC "' + $env:temp + '\install_sp6.log" /QTN'
Write-Host -ForegroundColor Yellow $cmd $arguments
Start-Process $cmd -ArgumentList $arguments -Verb RunAs -Wait

# add vb6 to path
$newPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path + ";C:\Program Files (x86)\Microsoft Visual Studio\VB98\"
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath