# Tau-Office test system
This project helps building a test system for Tau-Office.

# What do you need
1. A Tau-Office setup in this directory, e.g. setup_20211215_029.exe
2. A zip file in this directory with
    - at least to database backups (.bak files)
    - content of the "Mandantenpfad" (CFG, Vorlagen, Mand000000-Mand99999)
3. A Virtual Hard Disk with installed Windows 10 in ./Virtual Hard Disks/template.vhdx
4. Hyper-V

# How to use
1. Copy your Tau-Office setup into this directory (must be named setup*.exe)
2. Zip your "Mandantenpfad" and add a backup of your databases (.bak files)
3. Copy your zip file into this directory (must be named *.zip)
4. Copy your Office 2010 installation files into ../msaccess/Setup
7. Download or create a Virtual Hard Disk with a working Windows installation (you can use ../common/Get-WindowsVm.ps1 for that)
8. Open powershell and run `Install-Machine.ps1` (this takes a while)
9. Run your tests

# Legal
Please be aware that Office and Access are products of Microsoft and be mindful of their license agreement.
Also be aware that Tau-Office is a product of rocom GmbH and be mindful of their license agreement.
