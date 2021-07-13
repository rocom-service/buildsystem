# Visual Basic 6 setup script
This project helps you to install Visual Basic on a modern Windows 10 machine. You may even use the Dockerfile in order build your vb6 application with Azure Piplines.

# What do you need
1. A productkey for Visual Studio 6.0 Enterprise
2. Installation files for Visual Studio 6.0
3. Insatllation files for Visual Studio 6.0 Service Pack 6
4. (optional) Docker, if you want connect to Azure Piplines vb6

# How to install locally
1. Create a key.txt and copy your productkey into it.
2. Copy your Visual Studio 6.0 installation files into `.\1VS60Ent\`
3. Copy your Visual Studio 6.0 Service Pack 6 installation files into `.\3SP6_VSEnt\`
4. Run `.\install.ps1`

# How use vb6 with Azure Piplines
1. Create a key.txt and copy your productkey into it.
2. Copy your Visual Studio 6.0 installation files into 1VS60Ent
3. Copy your Visual Studio 6.0 Service Pack 6 installation files into 3SP6_VSEnt
4. Create a azure_url.txt and copy your Azure DevOps url into it. (e.g. `https://dev.azure.com/<your organization>/`)
5. Create your self a personal access token (see [Docs](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=preview-page)) and copy it into azure_token.txt
6. Open powershell and run 
    ```powershell
    docker build `
        --build-arg Version=$((cmd /c ver | Out-String) -replace '[^\d\.]','') `
        --rm `
        --isolation process `
        -t "vb6" .
    ```
7. Start the container with `docker run -it --isolation process --rm vb6`
8. Modify your azure-pipelines.yml and set some demands. e.g.:
    ```yml
    /* ... */
    pool:
        name: Default
        demands:
            - VisualBasic
    /* ... */
    ```
9. Que your build.
10. After your Build is finish the container will be destroyed, so you have a clean one for your next build.



# Special thanks
Special thanks to https://github.com/Ro-Fo/Vb6IdeDocker and https://github.com/telyn/docker-vb6 !
Without these, this project would have been a lot harder.

# Legal
Please be aware that Visual Studio is a product of Microsoft and be mindful of there license agreement.
The Docker file uses `mcr.microsoft.com/windows/servercore` which is also a product of Microsoft.
You can check there license agreement [here](https://hub.docker.com/_/microsoft-windows-servercore).
