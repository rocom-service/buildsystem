# You can get your windows version with powershell:
#    (cmd /c ver | Out-String) -replace '[^\d\.]',''
ARG VERSION

FROM mcr.microsoft.com/windows/servercore:${VERSION}
LABEL maintainer="rocom service GmbH <wpuchinger@rocom-service.de>"
SHELL ["powershell.exe", "-Command"]

COPY azure_token.txt azure_url.txt common/install.ps1 common/start.ps1 C:/azp/
WORKDIR C:/azp
RUN $ErrorActionPreference = 'Stop'; \
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force; \
    ./install.ps1;

COPY 1VS60Ent ./1VS60Ent
COPY 3SP6_VSEnt ./3SP6_VSEnt
COPY install.ps1 Key.txt ./

RUN Write-Host 'Installing Visual Basic...' -ForegroundColor Cyan; \
    ./install.ps1 -Verb RunAs;\
    \
    Write-Host 'Verifying installation...' -ForegroundColor Cyan; \
    [System.Environment]::SetEnvironmentVariable('AZP_AGENT_NAME', 'Visual Basic 6 Agent', [System.EnvironmentVariableTarget]::Machine); \
    [System.Environment]::SetEnvironmentVariable('VisualBasic', (ls 'C:/Program Files (x86)/Microsoft Visual Studio/VB98/VB6.EXE').VersionInfo.FileVersion, [System.EnvironmentVariableTarget]::Machine);

CMD ./start.ps1