# Check the encryption status
$encryptionStatus = (Get-BitLockerVolume -MountPoint C:).EncryptionPercentage

# If the drive is already encrypted, exit the script
if ($encryptionStatus -eq 100) {
    Write-Output "Encryption is already in place"
    exit
}

# Check if the device has a TPM chip
$tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm

# If the TPM chip is not present or not enabled, exit the script
if ($tpm -eq $null -or $tpm.IsEnabled().IsEnabled -eq $false) {
    Write-Output "TPM chip is not present or not enabled. Exiting the script."
    exit
}

# Check if there is a CD/DVD present
$cdDrive = Get-WmiObject -Class Win32_CDROMDrive

# If a CD/DVD is present, eject it and then sleep for 10 seconds
if ($cdDrive.MediaLoaded -eq $true) {
    $eject = New-Object -comObject Shell.Application
    $eject.Namespace(17).ParseName($cdDrive.Drive).InvokeVerb("Eject")
    Write-Output "CD/DVD is present in the drive. Ejecting the CD/DVD."
    Start-Sleep -Seconds 10
}

# Check again if there is a CD/DVD present
$cdDrive = Get-WmiObject -Class Win32_CDROMDrive
if ($cdDrive.MediaLoaded -eq $true) {
    Write-Output "CD/DVD is still present in the drive. Exiting the script."
    exit
}
# Create the directory if it doesn't exist
if (!(Test-Path -Path "C:\Scripts")) {
    New-Item -ItemType Directory -Path "C:\Scripts"
}

# Create a local copy of this script
$scriptPath = "C:\Scripts\BitlockerTask.ps1"
Copy-Item -Path $PSCommandPath -Destination $scriptPath -Force

# Function to check if the task exists
function TaskExists {
    param (
        [Parameter(Mandatory=$true)]
        [string] $TaskName
    )

    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()

    try {
        $task = $taskService.GetFolder('\').GetTask($TaskName)
        return $true
    } catch {
        return $false
    }
}

# Check if the task exists
$taskName = "BitlockerTask"
if (-not (TaskExists -TaskName $taskName)) {
    # Create a new scheduled task to run this script at startup
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -Description "Run BitLocker script at startup" -Principal $principal

    # Enable BitLocker on the C: drive with Recovery Password and Skip Hardware Test
    manage-bde -on C: -RecoveryPassword -SkipHardwareTest -UsedSpaceOnly
}

# Check the encryption status
$encryptionStatus = (Get-BitLockerVolume -MountPoint C:).EncryptionPercentage

# If the drive is currently encrypting, wait for the encryption to complete
if ($encryptionStatus -lt 100) {
    while ($encryptionStatus -lt 100) {
        Start-Sleep -Seconds 30
        $encryptionStatus = (Get-BitLockerVolume -MountPoint C:).EncryptionPercentage
    }
}

# Enable auto-unlock
manage-bde -autounlock -enable C:

# Backup the BitLocker key to Active Directory
$keyID = (Get-BitLockerVolume -MountPoint C:).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}
Backup-BitLockerKeyProtector -MountPoint C: -KeyProtectorId $keyID.KeyProtectorId

# Synco integration
# Function to handle BitLocker status and recovery password
function HandleBitLocker {
    param (
        [Parameter(Mandatory=$true)]
        [string] $DriveLetter
    )

    # Check if the specified drive exists
    if (!(Test-Path $DriveLetter)) {
        #Write-Output "$DriveLetter does not exist."
        return
    }

    # Check if BitLocker is completed
    $encryptionStatus = (Get-BitLockerVolume -MountPoint $DriveLetter).EncryptionPercentage
    if ($encryptionStatus -eq 100) {
        # Check if the 'Syncro' service exists
        $service = Get-Service -Name Syncro -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            # Run the command to import the Syncro module
            Import-Module $env:SyncroModule
            # Export the BitLocker recovery password for the drive and add it to the variable
            $Bitlocker_Key = (Get-BitLockerVolume -MountPoint $DriveLetter).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | Select-Object -ExpandProperty RecoveryPassword

            # Run the command to set the asset field
            Set-Asset-Field -Subdomain "alamo" -Name "Bitlocker_Key_$($DriveLetter.Replace(':', ''))" -Value $Bitlocker_Key
            Set-Asset-Field -Subdomain "alamo" -Name "Bitlocker_Enabled_C" -Value "BitLocker is enabled"
        } else {
            Write-Output "Service 'Syncro' does not exist."
        }
    } elseif ($DriveLetter -eq "C:") {
        # Run the commands if BitLocker is not enabled on the C: drive
        Import-Module $env:SyncroModule
        Set-Asset-Field -Subdomain "alamo" -Name "Bitlocker_Enabled_C" -Value "BitLocker is NOT enabled"
    }
}

# Check BitLocker status for C:, D:, and E: drives
HandleBitLocker -DriveLetter "C:"
HandleBitLocker -DriveLetter "D:"
HandleBitLocker -DriveLetter "E:"

# Remove the scheduled task as the script has completed successfully
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false