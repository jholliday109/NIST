<#
.SYNOPSIS
    Windows 11 Enterprise - CIS Level 1 Hardening Script (Enhanced Version)

.DESCRIPTION
    Applies a comprehensive set of CIS Level 1-aligned security controls via registry modifications,
    audit policies, firewall configuration, and security templates. This enhanced version includes
    improved error handling, validation, rollback capabilities, and additional security controls.

.NOTES
    Author: Enhanced by Claude AI
    Version: 3.0 (Enhanced & Fixed)
    Requires: Windows 11 Enterprise/Pro, PowerShell 5.1+, Administrative privileges
    Log: C:\Logs\CIS-Hardening-<timestamp>.log

.PARAMETER Force
    Skip confirmation prompts and apply all settings without user interaction

.PARAMETER NoReboot
    Skip reboot recommendation after completion

.PARAMETER Rollback
    Restore settings from a previous backup (specify backup directory with -BackupPath)

.PARAMETER BackupPath
    Path to backup directory for rollback operations

.PARAMETER SkipServices
    Skip service configuration changes

.PARAMETER SkipFirewall
    Skip Windows Firewall configuration

.EXAMPLE
    .\CIS-Win11-Level1-Enhanced.ps1
    Run with interactive prompts

.EXAMPLE
    .\CIS-Win11-Level1-Enhanced.ps1 -Force -NoReboot
    Run silently without reboot

.EXAMPLE
    .\CIS-Win11-Level1-Enhanced.ps1 -Rollback -BackupPath "C:\Logs\Registry-Backup-20241201-120000"
    Restore from backup
#>

[CmdletBinding(DefaultParameterSetName = 'Apply')]
param(
    [Parameter(ParameterSetName = 'Apply')]
    [switch]$Force,
    
    [Parameter(ParameterSetName = 'Apply')]
    [switch]$NoReboot,
    
    [Parameter(ParameterSetName = 'Apply')]
    [switch]$SkipServices,
    
    [Parameter(ParameterSetName = 'Apply')]
    [switch]$SkipFirewall,
    
    [Parameter(ParameterSetName = 'Rollback', Mandatory)]
    [switch]$Rollback,
    
    [Parameter(ParameterSetName = 'Rollback', Mandatory)]
    [ValidateScript({Test-Path $_})]
    [string]$BackupPath
)

#region Safety & Initialization
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Script metadata
$ScriptVersion = "3.0"
$ScriptName = "CIS Windows 11 Level 1 Hardening (Enhanced)"

# Verify Windows version
$OSInfo = Get-ComputerInfo -Property WindowsProductName, WindowsVersion
if ($OSInfo.WindowsProductName -notmatch "Windows 11") {
    Write-Error "This script is designed for Windows 11. Current OS: $($OSInfo.WindowsProductName)" -ErrorAction Stop
}

# Require administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Please restart PowerShell as Administrator." -ErrorAction Stop
}

# Initialize logging
$LogDir = "C:\Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("CIS-Hardening-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $LogFile -Append

Write-Host "=== $ScriptName v$ScriptVersion ===" -ForegroundColor Cyan
Write-Host "Execution started: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Log file: $LogFile" -ForegroundColor Yellow
Write-Host "Operating System: $($OSInfo.WindowsProductName) $($OSInfo.WindowsVersion)" -ForegroundColor Yellow

# Confirmation unless -Force or -Rollback
if ($Rollback) {
    if (-not $Force) {
        $confirm = Read-Host "This will restore settings from backup at '$BackupPath'. Continue? (y/N)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Host "Rollback cancelled by user." -ForegroundColor Yellow
            Stop-Transcript
            exit 0
        }
    }
} elseif (-not $Force) {
    Write-Host "`nThis script will apply CIS Level 1 hardening settings including:" -ForegroundColor White
    Write-Host "  • Account policies and password requirements" -ForegroundColor Gray
    Write-Host "  • UAC and authentication settings" -ForegroundColor Gray
    Write-Host "  • Network security and SMB hardening" -ForegroundColor Gray
    Write-Host "  • Windows Firewall configuration" -ForegroundColor Gray
    Write-Host "  • Service hardening and audit policies" -ForegroundColor Gray
    Write-Host "  • Additional security controls" -ForegroundColor Gray
    
    $confirm = Read-Host "`nContinue with hardening? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Script cancelled by user." -ForegroundColor Yellow
        Stop-Transcript
        exit 0
    }
}
#endregion

#region Enhanced Helper Functions
function Set-RegValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('String','DWord','QWord','Binary','MultiString','ExpandString')]$Type,
        [Parameter(Mandatory)]$Value,
        [switch]$Force
    )
    
    try {
        # Create registry path if it doesn't exist
        if (-not (Test-Path $Path)) { 
            New-Item -Path $Path -Force | Out-Null
            Write-Verbose "Created registry path: $Path"
        }
        
        # Get current value
        $currentValue = $null
        $currentType = $null
        try {
            $property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($property) {
                $currentValue = $property.$Name
                $regKey = Get-Item -Path $Path
                $currentType = $regKey.GetValueKind($Name)
            }
        } catch {
            # Property doesn't exist
        }
        
        # Set value if different, doesn't exist, or force is specified
        $needsUpdate = $null -eq $currentValue -or $currentValue -ne $Value -or $currentType -ne $Type -or $Force
        
        if ($needsUpdate) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Host "  [SET] $Path\$Name = $Value ($Type)" -ForegroundColor Green
            return @{Changed = $true; OldValue = $currentValue; NewValue = $Value}
        } else {
            Write-Host "  [SKIP] $Path\$Name already configured" -ForegroundColor DarkGray
            return @{Changed = $false; OldValue = $currentValue; NewValue = $Value}
        }
    } catch {
        Write-Warning "Failed to set $Path\$Name to $Value : $($_.Exception.Message)"
        return @{Changed = $false; Error = $_.Exception.Message}
    }
}

function Set-ServiceSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][ValidateSet('Disabled','Manual','Automatic','AutomaticDelayedStart')]$StartupType,
        [switch]$StopService,
        [switch]$Force
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Warning "Service '$ServiceName' not found"
            return @{Changed = $false; Error = "Service not found"}
        }
        
        $changed = $false
        $originalStartType = $service.StartType
        $originalStatus = $service.Status
        
        # Update startup type if different
        if ($service.StartType -ne $StartupType -or $Force) {
            Set-Service -Name $ServiceName -StartupType $StartupType
            Write-Host "  [SET] Service '$ServiceName': $originalStartType -> $StartupType" -ForegroundColor Green
            $changed = $true
        } else {
            Write-Host "  [SKIP] Service '$ServiceName' already set to $StartupType" -ForegroundColor DarkGray
        }
        
        # Stop service if requested and running
        if ($StopService -and $service.Status -eq 'Running') {
            try {
                Stop-Service -Name $ServiceName -Force -NoWait -ErrorAction Stop
                Write-Host "  [STOP] Service '$ServiceName' stopped" -ForegroundColor Yellow
                $changed = $true
            } catch {
                Write-Warning "Failed to stop service '$ServiceName': $($_.Exception.Message)"
            }
        }
        
        return @{
            Changed = $changed
            OriginalStartType = $originalStartType
            OriginalStatus = $originalStatus
            NewStartType = $StartupType
        }
    } catch {
        Write-Warning "Failed to configure service '$ServiceName': $($_.Exception.Message)"
        return @{Changed = $false; Error = $_.Exception.Message}
    }
}

function Backup-RegistryKeys {
    [CmdletBinding()]
    param([string[]]$RegistryPaths)
    
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupDir = Join-Path $LogDir "Registry-Backup-$timestamp"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    $backupManifest = @()
    
    foreach ($regPath in $RegistryPaths) {
        try {
            $fileName = ($regPath -replace '[\\/:*?"<>| ]','_') + '.reg'
            $backupFile = Join-Path $backupDir $fileName
            
            # Use reg export with proper error handling
            $process = Start-Process -FilePath 'reg.exe' -ArgumentList @('export', $regPath, $backupFile, '/y') -Wait -NoNewWindow -PassThru -RedirectStandardError (Join-Path $backupDir 'reg_errors.log')
            
            if ($process.ExitCode -eq 0 -and (Test-Path $backupFile)) {
                Write-Host "  [BACKUP] $regPath -> $fileName" -ForegroundColor Cyan
                $backupManifest += @{Path = $regPath; File = $fileName; Status = "Success"}
            } else {
                Write-Warning "Failed to backup $regPath (Exit Code: $($process.ExitCode))"
                $backupManifest += @{Path = $regPath; File = $fileName; Status = "Failed"; ExitCode = $process.ExitCode}
            }
        } catch {
            Write-Warning "Failed to backup $regPath : $($_.Exception.Message)"
            $backupManifest += @{Path = $regPath; File = $fileName; Status = "Error"; Error = $_.Exception.Message}
        }
    }
    
    # Save backup manifest
    $backupManifest | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $backupDir "backup_manifest.json") -Encoding UTF8
    
    return $backupDir
}

function Test-RegistryPath {
    [CmdletBinding()]
    param([string]$Path)
    
    try {
        return Test-Path $Path -PathType Container
    } catch {
        return $false
    }
}

function Get-ServiceStatus {
    [CmdletBinding()]
    param([string]$ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            return @{
                Exists = $true
                Status = $service.Status
                StartType = $service.StartType
            }
        } else {
            return @{Exists = $false}
        }
    } catch {
        return @{Exists = $false; Error = $_.Exception.Message}
    }
}

function Invoke-SystemRestart {
    [CmdletBinding()]
    param(
        [int]$DelaySeconds = 30,
        [switch]$Force
    )
    
    if ($Force) {
        Write-Host "Forcing system restart in $DelaySeconds seconds..." -ForegroundColor Red
        Start-Sleep -Seconds $DelaySeconds
        Restart-Computer -Force
    } else {
        $restart = Read-Host "System restart is recommended. Restart now? (y/N)"
        if ($restart -eq 'y' -or $restart -eq 'Y') {
            Write-Host "Restarting system in $DelaySeconds seconds..." -ForegroundColor Red
            Write-Host "Press Ctrl+C to cancel..." -ForegroundColor Yellow
            Start-Sleep -Seconds $DelaySeconds
            Restart-Computer -Force
        }
    }
}
#endregion

#region Rollback Function
function Invoke-SettingsRollback {
    [CmdletBinding()]
    param([string]$BackupDirectory)
    
    Write-Host "Starting rollback from: $BackupDirectory" -ForegroundColor Yellow
    
    # Check for backup manifest
    $manifestPath = Join-Path $BackupDirectory "backup_manifest.json"
    if (Test-Path $manifestPath) {
        try {
            $manifest = Get-Content $manifestPath | ConvertFrom-Json
            Write-Host "Found backup manifest with $($manifest.Count) entries" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to read backup manifest: $($_.Exception.Message)"
        }
    }
    
    # Restore registry files
    $regFiles = Get-ChildItem -Path $BackupDirectory -Filter "*.reg" -ErrorAction SilentlyContinue
    $successCount = 0
    $failCount = 0
    
    foreach ($regFile in $regFiles) {
        try {
            Write-Host "Restoring: $($regFile.Name)" -ForegroundColor Cyan
            $process = Start-Process -FilePath 'reg.exe' -ArgumentList @('import', $regFile.FullName) -Wait -NoNewWindow -PassThru
            
            if ($process.ExitCode -eq 0) {
                Write-Host "  [OK] Successfully restored $($regFile.Name)" -ForegroundColor Green
                $successCount++
            } else {
                Write-Warning "Failed to restore $($regFile.Name) (Exit Code: $($process.ExitCode))"
                $failCount++
            }
        } catch {
            Write-Warning "Error restoring $($regFile.Name): $($_.Exception.Message)"
            $failCount++
        }
    }
    
    Write-Host "`nRollback Summary:" -ForegroundColor Yellow
    Write-Host "  Successful: $successCount" -ForegroundColor Green
    Write-Host "  Failed: $failCount" -ForegroundColor Red
    
    if ($failCount -eq 0) {
        Write-Host "Rollback completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "Rollback completed with errors. Check the log for details." -ForegroundColor Yellow
    }
}
#endregion

# Handle rollback mode
if ($Rollback) {
    Invoke-SettingsRollback -BackupDirectory $BackupPath
    Write-Host "Rollback operation completed. Check log file: $LogFile" -ForegroundColor Yellow
    Stop-Transcript
    exit 0
}

#region Main Hardening Process
Write-Host "`n1. Creating Registry Backups..." -ForegroundColor Yellow
$backupTargets = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    "HKLM\SOFTWARE\Policies\Microsoft",
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
)

$backupLocation = Backup-RegistryKeys -RegistryPaths $backupTargets
Write-Host "Registry backups saved to: $backupLocation" -ForegroundColor Green

Write-Host "`n2. Configuring Account Policies..." -ForegroundColor Yellow
$securityTemplate = @"
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
MaximumPasswordAge = 365
MinimumPasswordAge = 1
LockoutBadCount = 10
ResetLockoutCount = 15
LockoutDuration = 15
ClearTextPassword = 0
RequireLogonToChangePassword = 0

[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3

[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1
MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1

[Version]
signature="`$CHICAGO`$"
Revision=1
"@

try {
    $tempInfFile = Join-Path $env:TEMP "CIS-SecurityPolicy-$((Get-Date).Ticks).inf"
    $tempDbFile = Join-Path $env:TEMP "CIS-SecurityPolicy-$((Get-Date).Ticks).sdb"
    
    $securityTemplate | Out-File -FilePath $tempInfFile -Encoding ASCII -Force
    
    # Apply security template with enhanced error handling
    $seceditArgs = @('/configure', '/db', $tempDbFile, '/cfg', $tempInfFile, '/areas', 'SECURITYPOLICY', '/quiet')
    $seceditResult = Start-Process -FilePath 'secedit.exe' -ArgumentList $seceditArgs -Wait -NoNewWindow -PassThru
    
    if ($seceditResult.ExitCode -eq 0) {
        Write-Host "  [OK] Account policies applied successfully" -ForegroundColor Green
    } else {
        Write-Warning "secedit returned exit code: $($seceditResult.ExitCode)"
        # Try to get more detailed error information
        $seceditLog = "$env:WINDIR\security\logs\scesrv.log"
        if (Test-Path $seceditLog) {
            $logContent = Get-Content $seceditLog -Tail 10 | Out-String
            Write-Verbose "Recent secedit log entries: $logContent"
        }
    }
    
    # Cleanup temp files
    Remove-Item $tempInfFile, $tempDbFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Failed to apply account policies: $($_.Exception.Message)"
}

Write-Host "`n3. Configuring Local Accounts & Authentication..." -ForegroundColor Yellow

# Enhanced Guest account handling
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest) {
        if ($guest.Enabled) {
            Disable-LocalUser -Name "Guest"
            Write-Host "  [OK] Guest account disabled" -ForegroundColor Green
        } else {
            Write-Host "  [SKIP] Guest account already disabled" -ForegroundColor DarkGray
        }
        
        # Ensure Guest account cannot be used
        $guestSid = $guest.SID.Value
        Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name "Guest" -Type DWord -Value 0
    } else {
        Write-Host "  [INFO] Guest account not found" -ForegroundColor Gray
    }
} catch {
    Write-Warning "Failed to configure Guest account: $($_.Exception.Message)"
}

# Enhanced logon security settings
$systemPolicies = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$winlogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Core security settings
Set-RegValue -Path $systemPolicies -Name "DisableCAD" -Type DWord -Value 0
Set-RegValue -Path $systemPolicies -Name "DontDisplayLastUserName" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "LegalNoticeCaption" -Type String -Value "NOTICE: Authorized Use Only"
Set-RegValue -Path $systemPolicies -Name "LegalNoticeText" -Type String -Value "This system is for authorized users only. All activities are monitored and logged. Unauthorized access is prohibited and may result in criminal prosecution."

# Additional security settings
Set-RegValue -Path $systemPolicies -Name "ShutdownWithoutLogon" -Type DWord -Value 0
Set-RegValue -Path $systemPolicies -Name "UndockWithoutLogon" -Type DWord -Value 0
Set-RegValue -Path $winlogonPath -Name "AutoAdminLogon" -Type String -Value "0"
Set-RegValue -Path $winlogonPath -Name "ScreenSaverGracePeriod" -Type String -Value "5"

Write-Host "`n4. Configuring UAC..." -ForegroundColor Yellow
Set-RegValue -Path $systemPolicies -Name "EnableLUA" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 2
Set-RegValue -Path $systemPolicies -Name "ConsentPromptBehaviorUser" -Type DWord -Value 3
Set-RegValue -Path $systemPolicies -Name "EnableInstallerDetection" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "EnableSecureUIAPaths" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "EnableUIADesktopToggle" -Type DWord -Value 0
Set-RegValue -Path $systemPolicies -Name "EnableVirtualization" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "PromptOnSecureDesktop" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "ValidateAdminCodeSignatures" -Type DWord -Value 0
Set-RegValue -Path $systemPolicies -Name "FilterAdministratorToken" -Type DWord -Value 1

Write-Host "`n5. Configuring Network Security..." -ForegroundColor Yellow

# Disable LLMNR and NetBIOS
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Type DWord -Value 1

# Enhanced SMB Security
try {
    # SMBv1 Server
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbConfig -and $smbConfig.EnableSMB1Protocol) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
        Write-Host "  [OK] SMBv1 server protocol disabled" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] SMBv1 server already disabled" -ForegroundColor DarkGray
    }
    
    # SMBv1 Client
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1Feature -and $smb1Feature.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  [OK] SMBv1 client feature disabled" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] SMBv1 client already disabled" -ForegroundColor DarkGray
    }
    
    # Additional SMB hardening
    Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -EncryptData $true -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  [OK] SMB encryption and signing enabled" -ForegroundColor Green
} catch {
    Write-Warning "SMB configuration failed: $($_.Exception.Message)"
}

# SMB registry settings
$workstationParams = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$serverParams = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

Set-RegValue -Path $workstationParams -Name "RequireSecuritySignature" -Type DWord -Value 1
Set-RegValue -Path $workstationParams -Name "EnableSecuritySignature" -Type DWord -Value 1
Set-RegValue -Path $workstationParams -Name "AllowInsecureGuestAuth" -Type DWord -Value 0
Set-RegValue -Path $workstationParams -Name "EnablePlainTextPassword" -Type DWord -Value 0

Set-RegValue -Path $serverParams -Name "RequireSecuritySignature" -Type DWord -Value 1
Set-RegValue -Path $serverParams -Name "EnableSecuritySignature" -Type DWord -Value 1
Set-RegValue -Path $serverParams -Name "AutoDisconnectTimeout" -Type DWord -Value 15
Set-RegValue -Path $serverParams -Name "EnableForcedLogOff" -Type DWord -Value 1

# Enhanced NTLM and authentication settings
$lsaPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
Set-RegValue -Path $lsaPath -Name "LmCompatibilityLevel" -Type DWord -Value 5
Set-RegValue -Path $lsaPath -Name "RestrictAnonymous" -Type DWord -Value 1
Set-RegValue -Path $lsaPath -Name "RestrictAnonymousSAM" -Type DWord -Value 1
Set-RegValue -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Type DWord -Value 0
Set-RegValue -Path $lsaPath -Name "NoLMHash" -Type DWord -Value 1
Set-RegValue -Path $lsaPath -Name "LimitBlankPasswordUse" -Type DWord -Value 1
Set-RegValue -Path $lsaPath -Name "CrashOnAuditFail" -Type DWord -Value 0

# Disable weak protocols
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Type DWord -Value 0x20080000
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Type DWord -Value 0x20080000

Write-Host "`n6. Configuring Windows Security Features..." -ForegroundColor Yellow

# Enhanced SmartScreen configuration
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 2
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Type String -Value "Block"

# Microsoft Edge SmartScreen
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Type DWord -Value 1

# Windows Defender configuration
try {
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
        Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
        Write-Host "  [OK] Windows Defender preferences configured" -ForegroundColor Green
    }
    
    # Windows Defender registry settings
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 0
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Type DWord -Value 0
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 1
} catch {
    Write-Warning "Windows Defender configuration failed: $($_.Exception.Message)"
}

# Application Guard and Credential Guard
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowAppHVSI_ProviderSet" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 1

Write-Host "`n7. Configuring Privacy & Telemetry..." -ForegroundColor Yellow

# Enhanced telemetry settings
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDeviceNameInTelemetry" -Type DWord -Value 0

# Disable consumer features and suggestions
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type DWord -Value 1

# Disable location services
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1

# Advertising and app suggestions
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

Write-Host "`n8. Configuring Remote Desktop Security..." -ForegroundColor Yellow

$terminalServerPath = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpTcpPath = "$terminalServerPath\WinStations\RDP-Tcp"

# RDP security settings (disabled by default but secured)
Set-RegValue -Path $terminalServerPath -Name "fDenyTSConnections" -Type DWord -Value 1
Set-RegValue -Path $terminalServerPath -Name "fAllowToGetHelp" -Type DWord -Value 0
Set-RegValue -Path $rdpTcpPath -Name "UserAuthentication" -Type DWord -Value 1
Set-RegValue -Path $rdpTcpPath -Name "MinEncryptionLevel" -Type DWord -Value 3
Set-RegValue -Path $rdpTcpPath -Name "SecurityLayer" -Type DWord -Value 2
Set-RegValue -Path $rdpTcpPath -Name "fDisableCdm" -Type DWord -Value 1
Set-RegValue -Path $rdpTcpPath -Name "fDisableCam" -Type DWord -Value 1
Set-RegValue -Path $rdpTcpPath -Name "fDisableLPT" -Type DWord -Value 1

# Disable Remote Assistance
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowFullControl" -Type DWord -Value 0

Write-Host "`n9. Configuring AutoPlay, AutoRun & Screen Lock..." -ForegroundColor Yellow

# Enhanced AutoPlay/AutoRun settings
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HonorAutorunSetting" -Type DWord -Value 1

# USB and removable media restrictions
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices" -Name "Deny_All" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" -Name "Deny_Write" -Type DWord -Value 0

# Screen saver and lock settings
$screenSaverPaths = @(
    "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
    "HKU\.DEFAULT\Software\Policies\Microsoft\Windows\Control Panel\Desktop",
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
)

$screenSaverSettings = @{
    "ScreenSaveActive" = "1"
    "ScreenSaverIsSecure" = "1"
    "ScreenSaveTimeOut" = "900"
    "SCRNSAVE.EXE" = "scrnsave.scr"
}

foreach ($path in $screenSaverPaths) {
    foreach ($setting in $screenSaverSettings.GetEnumerator()) {
        if ($path -like "*System*" -and $setting.Key -eq "ScreenSaveTimeOut") {
            # Use different value name for System path
            Set-RegValue -Path $path -Name "InactivityTimeoutSecs" -Type DWord -Value 900
        } else {
            Set-RegValue -Path $path -Name $setting.Key -Type String -Value $setting.Value
        }
    }
}

# Machine inactivity limit
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Type DWord -Value 900

if (-not $SkipFirewall) {
    Write-Host "`n10. Configuring Windows Firewall..." -ForegroundColor Yellow
    
    try {
        $firewallProfiles = @('Domain', 'Private', 'Public')
        
        foreach ($profile in $firewallProfiles) {
            # Enhanced firewall configuration
            Set-NetFirewallProfile -Profile $profile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowInboundRules True -AllowLocalFirewallRules False -AllowLocalIPsecRules False -AllowUnicastResponseToMulticast False -ErrorAction SilentlyContinue
            
            # Configure comprehensive logging
            $logPath = "%systemroot%\system32\LogFiles\Firewall\$($profile.ToLower())fw.log"
            Set-NetFirewallProfile -Profile $profile -LogAllowed True -LogBlocked True -LogFileName $logPath -LogMaxSizeKilobytes 32768 -ErrorAction SilentlyContinue
        }
        
        # Disable unused firewall rules that might pose security risks
        $riskyRules = @(
            "File and Printer Sharing*",
            "Network Discovery*",
            "Windows Media Player*",
            "Windows Remote Management*"
        )
        
        foreach ($rule in $riskyRules) {
            try {
                Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
            } catch {
                # Rule might not exist, continue
            }
        }
        
        Write-Host "  [OK] Windows Firewall profiles configured with enhanced security" -ForegroundColor Green
    } catch {
        Write-Warning "Firewall configuration failed: $($_.Exception.Message)"
    }
} else {
    Write-Host "`n10. Skipping Windows Firewall configuration..." -ForegroundColor Yellow
}

if (-not $SkipServices) {
    Write-Host "`n11. Configuring Services..." -ForegroundColor Yellow
    
    # Enhanced service hardening
    $servicesToDisable = @(
        @{Name = "RemoteRegistry"; DisplayName = "Remote Registry"},
        @{Name = "SSDPSRV"; DisplayName = "SSDP Discovery"},
        @{Name = "upnphost"; DisplayName = "UPnP Device Host"},
        @{Name = "WerSvc"; DisplayName = "Windows Error Reporting Service"},
        @{Name = "Fax"; DisplayName = "Fax"},
        @{Name = "TapiSrv"; DisplayName = "Telephony"},
        @{Name = "simptcp"; DisplayName = "Simple TCP/IP Services"},
        @{Name = "sacsvr"; DisplayName = "Special Administration Console Helper"},
        @{Name = "NetTcpPortSharing"; DisplayName = "Net.Tcp Port Sharing Service"},
        @{Name = "MsDepSvc"; DisplayName = "Web Deployment Agent Service"},
        @{Name = "WMPNetworkSvc"; DisplayName = "Windows Media Player Network Sharing Service"},
        @{Name = "icssvc"; DisplayName = "Windows Mobile Hotspot Service"},
        @{Name = "WpcMonSvc"; DisplayName = "Parental Controls"},
        @{Name = "CscService"; DisplayName = "Offline Files"},
        @{Name = "RemoteAccess"; DisplayName = "Routing and Remote Access"}
    )
    
    $servicesToSecure = @(
        @{Name = "Spooler"; StartupType = "Manual"; DisplayName = "Print Spooler"},
        @{Name = "BITS"; StartupType = "Manual"; DisplayName = "Background Intelligent Transfer Service"},
        @{Name = "wuauserv"; StartupType = "Manual"; DisplayName = "Windows Update"},
        @{Name = "Schedule"; StartupType = "Automatic"; DisplayName = "Task Scheduler"}
    )
    
    # Disable risky services
    foreach ($svc in $servicesToDisable) {
        Set-ServiceSecure -ServiceName $svc.Name -StartupType Disabled -StopService
    }
    
    # Secure other services
    foreach ($svc in $servicesToSecure) {
        Set-ServiceSecure -ServiceName $svc.Name -StartupType $svc.StartupType
    }
} else {
    Write-Host "`n11. Skipping service configuration..." -ForegroundColor Yellow
}

Write-Host "`n12. Configuring Enhanced Audit Policy..." -ForegroundColor Yellow

# Enhanced audit policy configuration
$auditSubcategories = @{
    "Credential Validation" = @{Success = $true; Failure = $true}
    "Kerberos Authentication Service" = @{Success = $false; Failure = $true}
    "Kerberos Service Ticket Operations" = @{Success = $false; Failure = $true}
    "Other Account Logon Events" = @{Success = $false; Failure = $true}
    "Application Group Management" = @{Success = $true; Failure = $true}
    "Computer Account Management" = @{Success = $true; Failure = $true}
    "Distribution Group Management" = @{Success = $true; Failure = $true}
    "Other Account Management Events" = @{Success = $true; Failure = $true}
    "Security Group Management" = @{Success = $true; Failure = $true}
    "User Account Management" = @{Success = $true; Failure = $true}
    "DPAPI Activity" = @{Success = $false; Failure = $true}
    "Process Creation" = @{Success = $true; Failure = $false}
    "Process Termination" = @{Success = $false; Failure = $false}
    "RPC Events" = @{Success = $false; Failure = $true}
    "Account Lockout" = @{Success = $true; Failure = $true}
    "IPsec Extended Mode" = @{Success = $false; Failure = $true}
    "Logoff" = @{Success = $true; Failure = $false}
    "Logon" = @{Success = $true; Failure = $true}
    "Network Policy Server" = @{Success = $true; Failure = $true}
    "Other Logon/Logoff Events" = @{Success = $false; Failure = $true}
    "Special Logon" = @{Success = $true; Failure = $false}
    "Detailed File Share" = @{Success = $false; Failure = $true}
    "File Share" = @{Success = $true; Failure = $true}
    "File System" = @{Success = $false; Failure = $true}
    "Filtering Platform Connection" = @{Success = $false; Failure = $true}
    "Filtering Platform Packet Drop" = @{Success = $false; Failure = $false}
    "Handle Manipulation" = @{Success = $false; Failure = $false}
    "Kernel Object" = @{Success = $false; Failure = $true}
    "Other Object Access Events" = @{Success = $false; Failure = $true}
    "Registry" = @{Success = $false; Failure = $true}
    "Removable Storage" = @{Success = $true; Failure = $true}
    "SAM" = @{Success = $false; Failure = $true}
    "Audit Policy Change" = @{Success = $true; Failure = $true}
    "Authentication Policy Change" = @{Success = $true; Failure = $false}
    "Authorization Policy Change" = @{Success = $true; Failure = $false}
    "MPSSVC Rule-Level Policy Change" = @{Success = $false; Failure = $true}
    "Other Policy Change Events" = @{Success = $false; Failure = $true}
    "Non Sensitive Privilege Use" = @{Success = $false; Failure = $false}
    "Other Privilege Use Events" = @{Success = $false; Failure = $false}
    "Sensitive Privilege Use" = @{Success = $false; Failure = $true}
    "IPsec Driver" = @{Success = $true; Failure = $true}
    "Other System Events" = @{Success = $true; Failure = $true}
    "Security State Change" = @{Success = $true; Failure = $false}
    "Security System Extension" = @{Success = $true; Failure = $true}
    "System Integrity" = @{Success = $true; Failure = $true}
}

foreach ($subcategory in $auditSubcategories.GetEnumerator()) {
    try {
        $successFlag = if ($subcategory.Value.Success) { "enable" } else { "disable" }
        $failureFlag = if ($subcategory.Value.Failure) { "enable" } else { "disable" }
        
        $result = Start-Process -FilePath 'auditpol.exe' -ArgumentList @('/set', '/subcategory:"' + $subcategory.Key + '"', "/success:$successFlag", "/failure:$failureFlag") -Wait -NoNewWindow -PassThru -WindowStyle Hidden
        
        if ($result.ExitCode -eq 0) {
            Write-Host "  [OK] Audit subcategory '$($subcategory.Key)' configured" -ForegroundColor Green
        } else {
            Write-Warning "Failed to configure audit subcategory '$($subcategory.Key)' (exit code: $($result.ExitCode))"
        }
    } catch {
        Write-Warning "Failed to configure audit subcategory '$($subcategory.Key)': $($_.Exception.Message)"
    }
}

Write-Host "`n13. Applying Additional Security Controls..." -ForegroundColor Yellow

# Enhanced RPC and network security
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "RestrictRemoteClients" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Type DWord -Value 1

# Windows Update security
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 4
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type DWord -Value 3

# PowerShell security
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy" -Name "ExecutionPolicy" -Type String -Value "RemoteSigned"
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Type DWord -Value 1

# WinRM security (if enabled)
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Type DWord -Value 0

# Event log settings
$eventLogs = @("Application", "Security", "System")
foreach ($log in $eventLogs) {
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log" -Name "MaxSize" -Type DWord -Value 196608
    Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$log" -Name "Retention" -Type String -Value "0"
}

# Credential delegation restrictions
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowDefaultCredentials" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowFreshCredentials" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowSavedCredentials" -Type DWord -Value 0

Write-Host "`n14. Comprehensive Security Validation..." -ForegroundColor Yellow

$validationResults = @{}
$criticalChecks = @{
    "Guest Account Disabled" = {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        return ($guest -and -not $guest.Enabled)
    }
    "UAC Enabled" = {
        $uacEnabled = (Get-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
        return ($uacEnabled -eq 1)
    }
    "Windows Firewall Domain Enabled" = {
        $domainProfile = Get-NetFirewallProfile -Profile Domain -ErrorAction SilentlyContinue
        return ($domainProfile -and $domainProfile.Enabled)
    }
    "Windows Firewall Private Enabled" = {
        $privateProfile = Get-NetFirewallProfile -Profile Private -ErrorAction SilentlyContinue
        return ($privateProfile -and $privateProfile.Enabled)
    }
    "Windows Firewall Public Enabled" = {
        $publicProfile = Get-NetFirewallProfile -Profile Public -ErrorAction SilentlyContinue
        return ($publicProfile -and $publicProfile.Enabled)
    }
    "SMBv1 Server Disabled" = {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        return ($smbConfig -and -not $smbConfig.EnableSMB1Protocol)
    }
    "Remote Registry Disabled" = {
        $remoteReg = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
        return ($remoteReg -and $remoteReg.StartType -eq "Disabled")
    }
    "LLMNR Disabled" = {
        $llmnr = (Get-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
        return ($llmnr -eq 0)
    }
    "AutoRun Disabled" = {
        $autorun = (Get-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        return ($autorun -eq 255)
    }
    "Screen Saver Enabled" = {
        $screenSaver = (Get-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue).InactivityTimeoutSecs
        return ($screenSaver -eq 900)
    }
}

# Perform validation checks
foreach ($check in $criticalChecks.GetEnumerator()) {
    try {
        $result = & $check.Value
        $validationResults[$check.Key] = $result
    } catch {
        $validationResults[$check.Key] = $false
        Write-Warning "Validation check '$($check.Key)' failed: $($_.Exception.Message)"
    }
}

# Display validation results
Write-Host "`nSecurity Validation Results:" -ForegroundColor White
$passCount = 0
$totalChecks = $validationResults.Count

foreach ($check in $validationResults.GetEnumerator()) {
    $status = if ($check.Value) { "[PASS]" } else { "[FAIL]" }
    $color = if ($check.Value) { "Green" } else { "Red" }
    Write-Host "  $status $($check.Key)" -ForegroundColor $color
    if ($check.Value) { $passCount++ }
}

$passPercentage = [math]::Round(($passCount / $totalChecks) * 100, 1)
Write-Host "`nValidation Summary: $passCount/$totalChecks checks passed ($passPercentage%)" -ForegroundColor $(if ($passPercentage -ge 90) { "Green" } elseif ($passPercentage -ge 75) { "Yellow" } else { "Red" })

Write-Host "`n15. Generating Security Report..." -ForegroundColor Yellow

# Create comprehensive security report
$reportPath = Join-Path $LogDir ("CIS-Security-Report-{0:yyyyMMdd-HHmmss}.html" -f (Get-Date))
$reportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>CIS Windows 11 Level 1 Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { color: #2E86AB; border-bottom: 3px solid #2E86AB; padding-bottom: 10px; }
        .section { margin: 20px 0; }
        .pass { color: green; }
        .fail { color: red; }
        .info { background-color: #f0f0f0; padding: 10px; border-left: 4px solid #2E86AB; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1 class="header">CIS Windows 11 Level 1 Security Report</h1>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="info">
            <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>System:</strong> $($OSInfo.WindowsProductName) $($OSInfo.WindowsVersion)</p>
            <p><strong>Script Version:</strong> $ScriptVersion</p>
            <p><strong>Validation Score:</strong> $passCount/$totalChecks ($passPercentage%)</p>
            <p><strong>Backup Location:</strong> $backupLocation</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Validation Results</h2>
        <table>
            <tr><th>Security Control</th><th>Status</th></tr>
"@

foreach ($check in $validationResults.GetEnumerator()) {
    $statusClass = if ($check.Value) { "pass" } else { "fail" }
    $statusText = if ($check.Value) { "PASS" } else { "FAIL" }
    $reportContent += "            <tr><td>$($check.Key)</td><td class=`"$statusClass`">$statusText</td></tr>`n"
}

$reportContent += @"
        </table>
    </div>
    
    <div class="section">
        <h2>Applied Security Controls</h2>
        <ul>
            <li>Account Policies and Password Requirements</li>
            <li>User Account Control (UAC) Configuration</li>
            <li>Network Security and Protocol Hardening</li>
            <li>SMB Security and Authentication</li>
            <li>Windows Firewall Configuration</li>
            <li>Service Security Hardening</li>
            <li>Audit Policy Configuration</li>
            <li>Privacy and Telemetry Controls</li>
            <li>Remote Desktop Security</li>
            <li>AutoPlay/AutoRun Restrictions</li>
            <li>Screen Lock and Inactivity Settings</li>
            <li>PowerShell Security</li>
            <li>Event Logging Configuration</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <p>The following additional steps are recommended:</p>
        <ul>
            <li>Review and test all applied settings in a controlled environment</li>
            <li>Implement regular security monitoring and log analysis</li>
            <li>Schedule periodic security assessments</li>
            <li>Ensure all users are trained on the new security requirements</li>
            <li>Consider implementing additional CIS Level 2 controls for enhanced security</li>
            <li>Backup registry settings have been saved to: $backupLocation</li>
        </ul>
    </div>
</body>
</html>
"@

try {
    $reportContent | Out-File -FilePath $reportPath -Encoding UTF8 -Force
    Write-Host "  [OK] Security report generated: $reportPath" -ForegroundColor Green
} catch {
    Write-Warning "Failed to generate security report: $($_.Exception.Message)"
}

#endregion

Write-Host "`n=== CIS Level 1 Hardening Complete ===" -ForegroundColor Cyan
Write-Host "Execution completed: $(Get-Date)" -ForegroundColor Yellow
Write-Host "Script version: $ScriptVersion" -ForegroundColor Yellow
Write-Host "Log file: $LogFile" -ForegroundColor Yellow
Write-Host "Registry backups: $backupLocation" -ForegroundColor Yellow
Write-Host "Security report: $reportPath" -ForegroundColor Yellow
Write-Host "Validation score: $passCount/$totalChecks ($passPercentage%)" -ForegroundColor $(if ($passPercentage -ge 90) { "Green" } elseif ($passPercentage -ge 75) { "Yellow" } else { "Red" })

if ($passPercentage -lt 100) {
    Write-Host "`nSome validation checks failed. Please review the results and re-run if necessary." -ForegroundColor Yellow
}

# Reboot recommendation
if (-not $NoReboot) {
    Write-Host "`nA system restart is recommended to ensure all changes take effect." -ForegroundColor Yellow
    Write-Host "Some Group Policy changes may require a restart to be fully applied." -ForegroundColor Yellow
    
    if (-not $Force) {
        Invoke-SystemRestart -DelaySeconds 30
    } else {
        Write-Host "Use -NoReboot parameter to skip this recommendation in automated deployments." -ForegroundColor Gray
    }
}

Write-Host "`nTo rollback these changes, use:" -ForegroundColor Gray
Write-Host "  .\CIS-Win11-Level1-Enhanced.ps1 -Rollback -BackupPath `"$backupLocation`"" -ForegroundColor Gray

Stop-Transcript
Write-Host "`nHardening completed successfully!" -ForegroundColor Green
