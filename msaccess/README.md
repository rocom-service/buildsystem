# MsAccess Build Agent
This project helps building your MsAccess 2010 Application with Azure Pipelines.

# What do you need
1. A product key for Microsoft Office 2010
2. Installation files for Microsoft Office 2010 in ./setup/
3. A Virtual Hard Disk with installed Windows 10 in ./Virtual Hard Disks/template.vhdx
4. Hyper-V

# How to use with Azure Pipelines
1. Copy your Office 2010 installation files into Setup
2. If you want to customize the office installation, create your .msp-files now and copy them into .\setup\Updates
3. Create a azure_url.txt and copy your Azure DevOps url into it. (e.g. `https://dev.azure.com/<your organization>/`)
4. Create your self a personal access token (see [Docs](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=preview-page)) and copy it into azure_token.txt
5. Download or create a Virtual Hard Disk with a working Windows installation (you can use ../common/Get-WindowsVm.ps1 for that)
6. Open powershell and run `Install-Machine.ps1` (this takes a while)
7. Modify your azure-pipelines.yml and set some demands. e.g.:
    ```yml
    /* ... */
    pool:
        name: Default
        demands:
            - MsAccess
    /* ... */
    ```
8. Que your build.
9. Profit ;)

# Legal
Please be aware that Office and Access are products of Microsoft and be mindful of their license agreement.
