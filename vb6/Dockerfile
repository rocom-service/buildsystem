# You can get your windows version with powershell:
#    (cmd /c ver | Out-String) -replace '[^\d\.]',''
ARG VERSION

FROM mcr.microsoft.com/windows/servercore:${VERSION}
LABEL maintainer="rocom service GmbH <wpuchinger@rocom-service.de>"
ENV AZP_AGENT_NAME="Visual Basic 6 Agent" \
    ChocolateyUseWindowsCompression=false \
    IsDocker=YES \
    AZP_TOKEN_FILE=C:/azp/azure_token.txt \
    AZP_URL_FILE=C:/azp/azure_url.txt \
    VSO_AGENT_IGNORE=AZP_AGENT_NAME,AZP_TOKEN_FILE,ChocolateyLastPathUpdate,chocolateyUseWindowsCompression,PROMPT

WORKDIR C:/azp
SHELL ["powershell.exe", "-NoProfile", "-Command"]

COPY 1VS60Ent ./1VS60Ent
COPY 3SP6_VSEnt ./3SP6_VSEnt
COPY install.ps1 Key.txt ./
RUN $ErrorActionPreference = 'Stop'; \
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force; \
    \
    Write-Host 'Installing Visual Basic...' -ForegroundColor Cyan; \
    ./install.ps1 -Verb RunAs;

RUN $ErrorActionPreference = 'Stop'; \
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force; \
    \
    # thanks to https://github.com/StefanScherer/dockerfiles-windows/tree/main/chocolatey \
    Write-Host 'Install chocolatey...' -ForegroundColor Cyan; \
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; \
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')); \
    \
    Write-Host 'Install some additional development tools...' -ForegroundColor Cyan; \
    choco feature disable --name showDownloadProgress; \
    choco install -y nuget.commandline --version=4.9.4; \
    choco install -y git; \
    choco install -y windows-sdk-10.1; \
    choco install -y pwsh;

COPY azure_token.txt azure_url.txt start.ps1 C:/azp/
RUN $ErrorActionPreference = 'Stop'; \
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force; \
    \
    Write-Host 'Determining matching Azure Pipelines agent...' -ForegroundColor Cyan; \
    New-Item '/azp/agent' -ItemType directory | Out-Null; \
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(\":$(Get-Content C:/azp/azure_token.txt)\")); \
    $package = Invoke-RestMethod -Headers @{Authorization=(\"Basic $base64AuthInfo\")} \"$(Get-Content C:/azp/azure_url.txt)/_apis/distributedtask/packages/agent?platform=win-x64&`$top=1\"; \
    $packageUrl = $package[0].Value.downloadUrl; \
    Write-Host $packageUrl; \
    \
    Write-Host 'Downloading and installing Azure Pipelines agent...' -ForegroundColor Cyan; \
    $wc = New-Object System.Net.WebClient; \
    $wc.DownloadFile($packageUrl, \"$(Get-Location)/agent.zip\"); \
    Expand-Archive -Path "agent.zip" -DestinationPath \"/azp/agent\";

RUN $ErrorActionPreference = 'Stop'; \
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force; \
    \
    Write-Host 'Verifying installation...' -ForegroundColor Cyan; \
    [System.Environment]::SetEnvironmentVariable('Git',         (Get-Command git).Version.ToString(),   [System.EnvironmentVariableTarget]::Machine); \
    [System.Environment]::SetEnvironmentVariable('NuGet',       (Get-Command nuget).Version.ToString(), [System.EnvironmentVariableTarget]::Machine); \
    [System.Environment]::SetEnvironmentVariable('VisualBasic', (Get-Command 'C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.EXE').Version.ToString(), [System.EnvironmentVariableTarget]::Machine);

CMD ./start.ps1