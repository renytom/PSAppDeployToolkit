<#
.SYNOPSIS
    Install RSAT features for Approved Windows OS.

.DESCRIPTION
    Install RSAT features for Windows 10 22H2 or Windows 11 23H2/24H2. All features are installed online from Microsoft Update thus the script requires Internet access

.PARAM All
    Installs all the features within RSAT. This takes several minutes, depending on your Internet connection

.PARAM Basic
    Installs ADDS, DHCP, DNS, GPO, ServerManager

.PARAM ServerManager
    Installs ServerManager

.PARAM Uninstall
    Uninstalls all the RSAT features

.NOTES
    Version: 1.2
    Author: Martin Bengtsson
    Blog: www.imab.dk
    Twitter: @mwbengtsson

    Version history:

    1.0   -   Script created

    1.2   -   Added test for pending reboots. If reboot is pending, RSAT features might not install successfully
              Added test for configuration of local WSUS by Group Policy.
                - If local WSUS is configured by Group Policy, history shows that additional settings might be needed for some environments
    1.3   -   Now using Get-CmiInstance instead of Get-WmiObject for determining OS buildnumber
    1.4   -   Updated the Windows version to reflect Microsoft supported versions. 3/12/2024 - Reny Thomas

#>

[CmdletBinding()]
param(
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [switch]$All,
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [switch]$Basic,
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [switch]$ServerManager,
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [switch]$Uninstall
)

# Check for administrative rights
if (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "The script requires elevation"
    break
}

# Create Pending Reboot function for registry
function Test-PendingRebootRegistry {
    $CBSRebootKey = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
    $WURebootKey = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
    if (($null -ne $CBSRebootKey) -OR ($null -ne $WURebootKey)) {
        $true
    }
    else {
        $false
    }
}

# Approved Windows OS
$ApprovedWinOS = "19045", "22631", "26100"
<# $21H1Build = "19043"
# Windows 10 21H2 build
$21H2Build = "19044" #>

# Get running Windows build
$WindowsBuild = (Get-CimInstance -Class Win32_OperatingSystem).BuildNumber

# Get information about local WSUS server
$WUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction Ignore).WUServer
#$DualScan = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name DisableDualScan -ErrorAction Ignore).DisableDualScan
$TestPendingRebootRegistry = Test-PendingRebootRegistry

if (($ApprovedWinOS -contains $WindowsBuild))
{
    Write-Verbose -Verbose "Running correct Windows build number for installing RSAT with Features on Demand. Build number is: $WindowsBuild"
    Write-Verbose -Verbose "***********************************************************"

    if ($null -ne $WUServer) {
        Write-Verbose -Verbose "A local WSUS server was found configured by group policy: $WUServer"
        Write-Verbose -Verbose "You might need to configure additional setting by GPO if things are not working"
        Write-Verbose -Verbose "The GPO of interest is following: Specify settings for optional component installation and component repair"
        Write-Verbose -Verbose "Check ON: Download repair content and optional features directly from Windows Update..."
        Write-Verbose -Verbose "***********************************************************"
    }

    if ($TestPendingRebootRegistry -eq "True") {
        Write-Verbose -Verbose "Reboots are pending. The script will continue, but RSAT might not install successfully"
        Write-Verbose -Verbose "***********************************************************"
    }

    if ($PSBoundParameters["All"]) {
        Write-Verbose -Verbose "Script is running with -All parameter. Installing all available RSAT features"
        $Install = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "NotPresent"}
        if ($null -ne $Install) {
            foreach ($Item in $Install) {
                $RsatItem = $Item.Name
                Write-Verbose -Verbose "Adding $RsatItem to Windows"
                try {
                    Add-WindowsCapability -Online -Name $RsatItem
                    }
                catch [System.Exception]
                    {
                    Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
                    Write-Warning -Message $_.Exception.Message
                    }
            }
        }
        else {
            Write-Verbose -Verbose "All RSAT features seems to be installed already"
        }
    }

    if ($PSBoundParameters["Basic"]) {
        Write-Verbose -Verbose "Script is running with -Basic parameter. Installing basic RSAT features"
        # Querying for what I see as the basic features of RSAT. Modify this if you think something is missing. :-)
        $Install = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat.ActiveDirectory*" -OR $_.Name -like "Rsat.BitLocker.Recovery.Tools*" <#-OR $_.Name -like "Rsat.DHCP.Tools*" -OR $_.Name -like "Rsat.Dns.Tools*" -OR $_.Name -like "Rsat.GroupPolicy*" -OR $_.Name -like "Rsat.ServerManager*" -AND $_.State -eq "NotPresent" #> }
        if ($null -ne $Install) {
            foreach ($Item in $Install) {
                $RsatItem = $Item.Name
                Write-Verbose -Verbose "Adding $RsatItem to Windows"
                try {
                        Add-WindowsCapability -Online -Name $RsatItem
                    }
                catch [System.Exception]
                    {
                        Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
                        Write-Warning -Message $_.Exception.Message
                    }
            }
        }
        else {
            Write-Verbose -Verbose "The basic features of RSAT seems to be installed already"
        }
    }

    if ($PSBoundParameters["ServerManager"]) {
        Write-Verbose -Verbose "Script is running with -ServerManager parameter. Installing Server Manager RSAT feature"
        $Install = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat.ServerManager*" -AND $_.State -eq "NotPresent"}
        if ($null -ne $Install) {
            $RsatItem = $Install.Name
            Write-Verbose -Verbose "Adding $RsatItem to Windows"
            try {
                    Add-WindowsCapability -Online -Name $RsatItem
                }
            catch [System.Exception]
                {
                    Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
                    Write-Warning -Message $_.Exception.Message ; break
                }
         }

        else {
                Write-Verbose -Verbose "$RsatItem seems to be installed already"
        }
    }

    if ($PSBoundParameters["Uninstall"]) {
        Write-Verbose -Verbose "Script is running with -Uninstall parameter. Uninstalling all RSAT features"
        # Querying for installed RSAT features first time
        $Installed = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "Installed" -AND $_.Name -notlike "Rsat.ServerManager*" -AND $_.Name -notlike "Rsat.GroupPolicy*" -AND $_.Name -notlike "Rsat.ActiveDirectory*"}
        if ($null -ne $Installed) {
            Write-Verbose -Verbose "Uninstalling the first round of RSAT features"
            # Uninstalling first round of RSAT features - some features seems to be locked until others are uninstalled first
            foreach ($Item in $Installed) {
                $RsatItem = $Item.Name
                Write-Verbose -Verbose "Uninstalling $RsatItem from Windows"
                try {
                        Remove-WindowsCapability -Name $RsatItem -Online
                    }
                catch [System.Exception]
                    {
                        Write-Verbose -Verbose "Failed to uninstall $RsatItem from Windows"
                        Write-Warning -Message $_.Exception.Message
                    }
            }
        }
        # Querying for installed RSAT features second time
        $Installed = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "Installed"}
        if ($null -ne $Installed) {
            Write-Verbose -Verbose "Uninstalling the second round of RSAT features"
            # Uninstalling second round of RSAT features
            foreach ($Item in $Installed) {
                $RsatItem = $Item.Name
                Write-Verbose -Verbose "Uninstalling $RsatItem from Windows"
                try {
                        Remove-WindowsCapability -Name $RsatItem -Online
                    }
                catch [System.Exception]
                    {
                        Write-Verbose -Verbose "Failed to remove $RsatItem from Windows"
                        Write-Warning -Message $_.Exception.Message
                    }
            }
        }
        else {
                Write-Verbose -Verbose "All RSAT features seems to be uninstalled already"
        }
    }
}
else {
    Write-Warning -Message "Not running correct Windows build: $WindowsBuild"
}
