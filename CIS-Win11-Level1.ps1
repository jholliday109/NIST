<#
  
.DESCRIPTION
    Windows 11 Enterprise - CIS Level 1 Hardening (Safe Starter)
    Applies a curated set of CIS Level 1-aligned controls via registry, auditpol,
    firewall cmdlets, and a minimal secedit template for Account Policies.
    Designed to be idempotent and verbose, with backups and logging.

.NOTES
    Author: (James Holliday)
    Version: 2.0 (Fixed)
    Log: C:\Logs\CIS-Hardening-<date>.log

.PARAMETER Force
    Skip confirmation prompts

.PARAMETER NoReboot
    Skip reboot recommendation

.EXAMPLE
    .\CIS-Win11-Level1.ps1
    .\CIS-Win11-Level1.ps1 -Force -NoReboot
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$NoReboot
)

#---------------------------#
# Safety & Utilities
#---------------------------#

# Set strict error handling
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Require admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator." -ErrorAction Stop
}

# Confirm execution unless -Force
if (-not $Force) {
    $confirm = Read-Host "This script will apply CIS Level 1 hardening settings. Continue? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Script cancelled by user."
        exit 0
    }
}

# Create log directory and start transcript
$LogDir = "C:\Logs"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("CIS-Hardening-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $LogFile -Append

Write-Host "=== CIS Windows 11 Level 1 Hardening Script ===" -ForegroundColor Green
Write-Host "Log file: $LogFile" -ForegroundColor Yellow

# Enhanced registry helper with better error handling
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
        
        # Check current value
        $currentValue = $null
        try {
            $currentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        } catch {
            # Property doesn't exist
        }
        
        # Set value if different or doesn't exist
        if ($null -eq $currentValue -or $currentValue -ne $Value -or $Force) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
            Write-Host "  [SET] $Path\$Name = $Value ($Type)" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  [SKIP] $Path\$Name already set to $Value" -ForegroundColor Gray
            return $false
        }
    } catch {
        Write-Warning "Failed to set $Path\$Name to $Value : $($_.Exception.Message)"
        return $false
    }
}

# Enhanced service management function
function Set-ServiceSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][ValidateSet('Disabled','Manual','Automatic')]$StartupType,
        [switch]$StopService
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.StartType -ne $StartupType) {
                Set-Service -Name $ServiceName -StartupType $StartupType
                Write-Host "  [SET] Service '$ServiceName' startup type: $StartupType" -ForegroundColor Green
            } else {
                Write-Host "  [SKIP] Service '$ServiceName' already set to $StartupType" -ForegroundColor Gray
            }
            
            if ($StopService -and $service.Status -eq 'Running') {
                Stop-Service -Name $ServiceName -Force -NoWait
                Write-Host "  [STOP] Service '$ServiceName' stopped" -ForegroundColor Yellow
            }
        } else {
            Write-Warning "Service '$ServiceName' not found"
        }
    } catch {
        Write-Warning "Failed to configure service '$ServiceName': $($_.Exception.Message)"
    }
}

# Registry backup function
function Backup-RegistryKeys {
    [CmdletBinding()]
    param([string[]]$RegistryPaths)
    
    $backupDir = Join-Path $LogDir "Registry-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    
    foreach ($regPath in $RegistryPaths) {
        try {
            $fileName = ($regPath -replace '[\\/:*?"<>| ]','_') + '.reg'
            $backupFile = Join-Path $backupDir $fileName
            $result = Start-Process -FilePath 'reg.exe' -ArgumentList @('export', $regPath, $backupFile, '/y') -Wait -NoNewWindow -PassThru
            if ($result.ExitCode -eq 0) {
                Write-Host "  [BACKUP] $regPath -> $fileName" -ForegroundColor Cyan
            }
        } catch {
            Write-Warning "Failed to backup $regPath : $($_.Exception.Message)"
        }
    }
    return $backupDir
}

#---------------------------#
# Registry Backup
#---------------------------#
Write-Host "`n1. Creating Registry Backups..." -ForegroundColor Yellow
$backupTargets = @(
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
    "HKLM\SOFTWARE\Policies\Microsoft",
    "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
    "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
)
$backupLocation = Backup-RegistryKeys -RegistryPaths $backupTargets
Write-Host "Registry backups saved to: $backupLocation" -ForegroundColor Green

#---------------------------#
# 1) Account Policies (secedit)
#---------------------------#
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

[Version]
signature="`$CHICAGO`$"
Revision=1
"@

try {
    $tempInfFile = Join-Path $env:TEMP "CIS-SecurityPolicy.inf"
    $tempDbFile = Join-Path $env:TEMP "CIS-SecurityPolicy.sdb"
    
    $securityTemplate | Out-File -FilePath $tempInfFile -Encoding ASCII -Force
    
    # Apply security template
    $seceditResult = Start-Process -FilePath 'secedit.exe' -ArgumentList @('/configure', '/db', $tempDbFile, '/cfg', $tempInfFile, '/areas', 'SECURITYPOLICY', '/quiet') -Wait -NoNewWindow -PassThru
    
    if ($seceditResult.ExitCode -eq 0) {
        Write-Host "  [OK] Account policies applied successfully" -ForegroundColor Green
    } else {
        Write-Warning "secedit returned exit code: $($seceditResult.ExitCode)"
    }
    
    # Cleanup temp files
    Remove-Item $tempInfFile, $tempDbFile -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Failed to apply account policies: $($_.Exception.Message)"
}

#---------------------------#
# 2) Local Accounts & Authentication
#---------------------------#
Write-Host "`n3. Configuring Local Accounts & Authentication..." -ForegroundColor Yellow

# Disable Guest account
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        Disable-LocalUser -Name "Guest"
        Write-Host "  [OK] Guest account disabled" -ForegroundColor Green
    } else {
        Write-Host "  [SKIP] Guest account already disabled" -ForegroundColor Gray
    }
} catch {
    Write-Warning "Failed to disable Guest account: $($_.Exception.Message)"
}

# Security logon settings
$systemPolicies = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-RegValue -Path $systemPolicies -Name "DisableCAD" -Type DWord -Value 0
Set-RegValue -Path $systemPolicies -Name "DontDisplayLastUserName" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "LegalNoticeCaption" -Type String -Value "Authorized Use Only"
Set-RegValue -Path $systemPolicies -Name "LegalNoticeText" -Type String -Value "This system is for authorized users only. All activity is monitored and logged."

# Disable automatic admin logon
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Type String -Value "0"

#---------------------------#
# 3) UAC Configuration
#---------------------------#
Write-Host "`n4. Configuring UAC..." -ForegroundColor Yellow
Set-RegValue -Path $systemPolicies -Name "EnableLUA" -Type DWord -Value 1
Set-RegValue -Path $systemPolicies -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 2  # Prompt for consent on secure desktop
Set-RegValue -Path $systemPolicies -Name "PromptOnSecureDesktop" -Type DWord -Value 1

#---------------------------#
# 4) Network Security & Authentication
#---------------------------#
Write-Host "`n5. Configuring Network Security..." -ForegroundColor Yellow

# Disable LLMNR
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0

# SMB Security
try {
    # Disable SMBv1
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbConfig -and $smbConfig.EnableSMB1Protocol) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
        Write-Host "  [OK] SMBv1 server disabled" -ForegroundColor Green
    }
    
    # Try to disable SMBv1 client feature
    $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smb1Feature -and $smb1Feature.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  [OK] SMBv1 client feature disabled" -ForegroundColor Green
    }
} catch {
    Write-Warning "SMBv1 configuration failed: $($_.Exception.Message)"
}

# SMB signing requirements
$workstationParams = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$serverParams = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Set-RegValue -Path $workstationParams -Name "RequireSecuritySignature" -Type DWord -Value 1
Set-RegValue -Path $workstationParams -Name "EnableSecuritySignature" -Type DWord -Value 1
Set-RegValue -Path $serverParams -Name "RequireSecuritySignature" -Type DWord -Value 1
Set-RegValue -Path $serverParams -Name "EnableSecuritySignature" -Type DWord -Value 1

# Disable insecure guest authentication
Set-RegValue -Path $workstationParams -Name "AllowInsecureGuestAuth" -Type DWord -Value 0

# NTLM security settings
$lsaPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
Set-RegValue -Path $lsaPath -Name "LmCompatibilityLevel" -Type DWord -Value 5  # Send NTLMv2 response only
Set-RegValue -Path $lsaPath -Name "RestrictAnonymous" -Type DWord -Value 1
Set-RegValue -Path $lsaPath -Name "RestrictAnonymousSAM" -Type DWord -Value 1
Set-RegValue -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Type DWord -Value 0
Set-RegValue -Path $lsaPath -Name "NoLMHash" -Type DWord -Value 1

#---------------------------#
# 5) Windows Security Features
#---------------------------#
Write-Host "`n6. Configuring Windows Security Features..." -ForegroundColor Yellow

# SmartScreen
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Type String -Value "Block"

# Microsoft Edge SmartScreen (if applicable)
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Type DWord -Value 1
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Type DWord -Value 1

# Windows Defender settings
try {
    if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
        Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
        Write-Host "  [OK] Windows Defender preferences configured" -ForegroundColor Green
    }
} catch {
    Write-Warning "Windows Defender configuration failed: $($_.Exception.Message)"
}

#---------------------------#
# 6) Privacy & Telemetry
#---------------------------#
Write-Host "`n7. Configuring Privacy Settings..." -ForegroundColor Yellow

# Telemetry (Enterprise/Education only)
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

#---------------------------#
# 7) Remote Desktop Security
#---------------------------#
Write-Host "`n8. Configuring Remote Desktop..." -ForegroundColor Yellow

$terminalServerPath = "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
$rdpTcpPath = "$terminalServerPath\WinStations\RDP-Tcp"

# Keep RDP disabled by default, but configure security settings
Set-RegValue -Path $terminalServerPath -Name "fDenyTSConnections" -Type DWord -Value 1
Set-RegValue -Path $rdpTcpPath -Name "UserAuthentication" -Type DWord -Value 1  # Require NLA
Set-RegValue -Path $rdpTcpPath -Name "MinEncryptionLevel" -Type DWord -Value 3  # High encryption
Set-RegValue -Path $rdpTcpPath -Name "SecurityLayer" -Type DWord -Value 2       # Require SSL/TLS

#---------------------------#
# 8) AutoPlay/AutoRun & Screen Lock
#---------------------------#
Write-Host "`n9. Configuring AutoPlay and Screen Lock..." -ForegroundColor Yellow

# Disable AutoPlay/AutoRun
Set-RegValue -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

# Screen saver security (apply to current user and default profile)
$screenSaverSettings = @{
    "ScreenSaveActive" = "1"
    "ScreenSaverIsSecure" = "1"
    "ScreenSaveTimeOut" = "900"  # 15 minutes
}

foreach ($setting in $screenSaverSettings.GetEnumerator()) {
    # Current user
    Set-RegValue -Path "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name $setting.Key -Type String -Value $setting.Value
    # Default profile for new users
    Set-RegValue -Path "HKU\.DEFAULT\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name $setting.Key -Type String -Value $setting.Value
}

#---------------------------#
# 9) Windows Firewall
#---------------------------#
Write-Host "`n10. Configuring Windows Firewall..." -ForegroundColor Yellow

try {
    $firewallProfiles = @('Domain', 'Private', 'Public')
    
    foreach ($profile in $firewallProfiles) {
        Set-NetFirewallProfile -Profile $profile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowInboundRules True -AllowLocalFirewallRules False -AllowLocalIPsecRules False -ErrorAction SilentlyContinue
        
        # Configure logging
        $logPath = "%systemroot%\system32\LogFiles\Firewall\$($profile.ToLower())fw.log"
        Set-NetFirewallProfile -Profile $profile -LogAllowed True -LogBlocked True -LogFileName $logPath -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
    }
    Write-Host "  [OK] Windows Firewall profiles configured" -ForegroundColor Green
} catch {
    Write-Warning "Firewall configuration failed: $($_.Exception.Message)"
}

#---------------------------#
# 10) Service Hardening
#---------------------------#
Write-Host "`n11. Configuring Services..." -ForegroundColor Yellow

# Disable risky services
$servicesToDisable = @(
    @{Name = "RemoteRegistry"; DisplayName = "Remote Registry"},
    @{Name = "SSDPSRV"; DisplayName = "SSDP Discovery"},
    @{Name = "upnphost"; DisplayName = "UPnP Device Host"}
)

foreach ($svc in $servicesToDisable) {
    Set-ServiceSecure -ServiceName $svc.Name -StartupType Disabled -StopService
}

#---------------------------#
# 11) Audit Policy
#---------------------------#
Write-Host "`n12. Configuring Audit Policy..." -ForegroundColor Yellow

$auditCategories = @{
    "Account Logon" = "enable"
    "Account Management" = "enable" 
    "Logon/Logoff" = "enable"
    "Object Access" = "enable"
    "Policy Change" = "enable"
    "Privilege Use" = "enable"
    "System" = "enable"
    "Detailed Tracking" = "enable"
}

foreach ($category in $auditCategories.GetEnumerator()) {
    try {
        $result = Start-Process -FilePath 'auditpol.exe' -ArgumentList @('/set', '/category:"' + $category.Key + '"', '/success:enable', '/failure:enable') -Wait -NoNewWindow -PassThru -WindowStyle Hidden
        if ($result.ExitCode -eq 0) {
            Write-Host "  [OK] Audit category '$($category.Key)' configured" -ForegroundColor Green
        } else {
            Write-Warning "Failed to configure audit category '$($category.Key)' (exit code: $($result.ExitCode))"
        }
    } catch {
        Write-Warning "Failed to configure audit category '$($category.Key)': $($_.Exception.Message)"
    }
}

# Reduce noise from Privilege Use auditing
try {
    Start-Process -FilePath 'auditpol.exe' -ArgumentList @('/set', '/subcategory:"Sensitive Privilege Use"', '/success:disable', '/failure:enable') -Wait -NoNewWindow -PassThru -WindowStyle Hidden | Out-Null
} catch {
    Write-Warning "Failed to configure Sensitive Privilege Use auditing"
}

#---------------------------#
# 12) Additional Security Settings
#---------------------------#
Write-Host "`n13. Applying Additional Security Settings..." -ForegroundColor Yellow

# Disable RPC over HTTP
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableRpcEpMapperUdp" -Type DWord -Value 0

# Windows Update settings (require admin approval for updates)
Set-RegValue -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 3  # Download and notify

#---------------------------#
# Validation & Summary
#---------------------------#
Write-Host "`n14. Validation Summary..." -ForegroundColor Yellow

$validationResults = @{
    "Guest Account Disabled" = $false
    "UAC Enabled" = $false
    "Windows Firewall Enabled" = $false
    "SMBv1 Disabled" = $false
    "Remote Registry Disabled" = $false
}

# Validate key settings
try {
    # Guest account
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $validationResults["Guest Account Disabled"] = ($guest -and -not $guest.Enabled)
    
    # UAC
    $uacEnabled = (Get-ItemProperty -Path $systemPolicies -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    $validationResults["UAC Enabled"] = ($uacEnabled -eq 1)
    
    # Firewall
    $domainProfile = Get-NetFirewallProfile -Profile Domain -ErrorAction SilentlyContinue
    $validationResults["Windows Firewall Enabled"] = ($domainProfile -and $domainProfile.Enabled)
    
    # SMBv1
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $validationResults["SMBv1 Disabled"] = ($smbConfig -and -not $smbConfig.EnableSMB1Protocol)
    
    # Remote Registry
    $remoteReg = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
    $validationResults["Remote Registry Disabled"] = ($remoteReg -and $remoteReg.StartType -eq "Disabled")
} catch {
    Write-Warning "Validation check failed: $($_.Exception.Message)"
}

# Display validation results
foreach ($check in $validationResults.GetEnumerator()) {
    $status = if ($check.Value) { "[PASS]" } else { "[FAIL]" }
    $color = if ($check.Value) { "Green" } else { "Red" }
    Write-Host "  $status $($check.Key)" -ForegroundColor $color
}

#---------------------------#
# Completion
#---------------------------#
Write-Host "`n=== CIS Level 1 Hardening Complete ===" -ForegroundColor Green
Write-Host "Log file: $LogFile" -ForegroundColor Yellow
Write-Host "Registry backups: $backupLocation" -ForegroundColor Yellow

if (-not $NoReboot) {
    Write-Host "`nA system restart is recommended to ensure all changes take effect." -ForegroundColor Yellow
    if (-not $Force) {
        $reboot = Read-Host "Restart now? (y/N)"
        if ($reboot -eq 'y' -or $reboot -eq 'Y') {
            Write-Host "Restarting system in 10 seconds..." -ForegroundColor Red
            Start-Sleep -Seconds 10
            Restart-Computer -Force
        }
    }
}

Stop-Transcript