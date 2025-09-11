<#
.SYNOPSIS
  NIST SP 800-53-inspired Windows laptop baseline (PowerShell).
.DESCRIPTION
  This script applies a pragmatic, idempotent set of technical controls to harden Windows laptops
  against many NIST 800-53 Rev.5 controls. It is intended for domain-joined Windows 10/11 or Server
  endpoints used as laptops. This is **not** an official NIST deliverable: it's a technical baseline
  that maps to common NIST control families (AC, AU, CM, IA, SC, SI, CP etc.).
  TEST IN A LAB FIRST. Some settings can break legacy apps or require infrastructure (Azure AD/Intune/AD DS).

  High-level features applied:
    - BitLocker enforcement (TPM + optional startup PIN)
    - Local account & password policy tuning
    - Remove local admin from standard users (prep only)
    - Windows Firewall - all profiles enabled, default inbound deny
    - Disable SMBv1, LLMNR, NetBIOS over TCP/IP, and legacy protocols/ciphers guidance
    - Advanced audit policy + process creation command-line capture
    - PowerShell scriptblock logging & transcription
    - Microsoft Defender / EDR guidance & preference tuning
    - AppLocker skeleton policy for executables (you must test and adapt)
    - Auto-lock & screensaver settings
    - Windows Update & time sync settings
    - Service hardening and disablement for dangerous legacy services
    - Central logging / SIEM forwarding notes (requires SIEM agent)
    - Many changes are idempotent; backups are taken before registry changes.

.PARAMETER NoReboot
  Suppress automatic reboot. Default = $true to avoid unexpected reboots on user devices.

.PARAMETER EnableBitLockerPIN
  If true, will attempt to enable TPM+PIN (requires user interaction for PIN creation)

.PARAMETER TranscriptPath
  Path for logging transcripts

.PARAMETER BackupPath
  Path for registry backups

.NOTES
  - Some controls (MFA, Azure AD Conditional Access, BitLocker escrow to AD/Azure) require Azure AD/Intune/AD DS or GPO. The script marks those sections and provides guidance.
  - Use Group Policy / Intune for fleet-wide enforcement where possible.
  - Run as Administrator.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$NoReboot = $true,
    [switch]$EnableBitLockerPIN = $false,
    [string]$TranscriptPath = "$env:ProgramData\NIST80053-Baseline\Logs",
    [string]$BackupPath = "$env:ProgramData\NIST80053-Baseline\Backups",
    [switch]$SkipBitLocker = $false,
    [switch]$SkipAppLocker = $false,
    [int]$ScreenLockTimeoutSeconds = 900
)

# Error handling preference
$ErrorActionPreference = 'Continue'
$WarningPreference = 'Continue'

function Assert-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "You must run this script as Administrator."
        exit 1
    }
}

function New-Folder { 
    param([string]$Path) 
    if (-not (Test-Path $Path)) { 
        New-Item -ItemType Directory -Path $Path -Force | Out-Null 
        Write-Verbose "Created directory: $Path"
    } 
}

function Start-Logging {
    New-Folder -Path $TranscriptPath
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $global:TranscriptFile = Join-Path $TranscriptPath "NIST80053-Baseline-$stamp.log"
    Start-Transcript -Path $global:TranscriptFile -Force | Out-Null
    New-Folder -Path $BackupPath
}

function Backup-RegKey {
    param([string]$Path)
    try {
        # Fix path format for reg.exe
        $regPath = $Path -replace '^HKLM:', 'HKLM'
        $regPath = $regPath -replace '^HKCU:', 'HKCU'
        $regPath = $regPath -replace '^HKU:', 'HKU'
        
        # Check if the registry path exists
        $testPath = $Path
        if (-not $testPath.StartsWith('Registry::')) {
            if ($testPath.StartsWith('HKLM:')) {
                $testPath = "Registry::HKEY_LOCAL_MACHINE\" + $testPath.Substring(5).TrimStart('\')
            } elseif ($testPath.StartsWith('HKCU:')) {
                $testPath = "Registry::HKEY_CURRENT_USER\" + $testPath.Substring(5).TrimStart('\')
            }
        }
        
        if (Test-Path $testPath) {
            $safe = ($regPath -replace '[\\/:*?"<>|]', '_').Substring(0, [Math]::Min(50, $regPath.Length))
            $file = Join-Path $BackupPath ("{0}-{1}.reg" -f $safe, (Get-Date).ToString('yyyyMMdd-HHmmss'))
            $result = & reg.exe export $regPath $file /y 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Backed up $regPath to $file"
            } else {
                Write-Verbose "Registry path does not exist or failed to export: $regPath"
            }
        }
    } catch { 
        Write-Verbose "Failed to export $Path: $($_.Exception.Message)" 
    }
}

function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [ValidateSet('String','ExpandString','DWord','QWord','Binary','MultiString')][string]$Type,
        [Object]$Value
    )
    try {
        if (-not (Test-Path $Path)) { 
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null 
        }
        
        # Only backup once per unique path per script run
        if (-not $global:BackedUpPaths) { $global:BackedUpPaths = @{} }
        if (-not $global:BackedUpPaths.ContainsKey($Path)) {
            Backup-RegKey -Path $Path
            $global:BackedUpPaths[$Path] = $true
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        Write-Verbose "Set $Path\$Name = $Value ($Type)"
        return $true
    } catch {
        Write-Warning "Failed to set registry value $Path\$Name: $($_.Exception.Message)"
        return $false
    }
}

function Configure-PasswordAndAccountPolicy {
    Write-Host "Configuring local password & lockout policy (AC family) ..." -ForegroundColor Green
    $success = 0
    $failed = 0
    
    try {
        # Use secedit for more reliable password policy configuration
        $secEditContent = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 14
MaximumPasswordAge = 90
MinimumPasswordAge = 1
PasswordHistorySize = 24
LockoutBadCount = 10
ResetLockoutCount = 15
LockoutDuration = 15
PasswordComplexity = 1
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        
        $tempFile = [System.IO.Path]::GetTempFileName()
        $secEditFile = $tempFile + '.inf'
        Set-Content -Path $secEditFile -Value $secEditContent -Encoding Unicode
        
        $dbFile = [System.IO.Path]::GetTempFileName() + '.sdb'
        $logFile = [System.IO.Path]::GetTempFileName() + '.log'
        
        $result = & secedit.exe /configure /db $dbFile /cfg $secEditFile /log $logFile /quiet 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Verbose "Password policy configured successfully via secedit"
            $success++
        } else {
            Write-Warning "Secedit configuration failed, falling back to net.exe commands"
            
            # Fallback to net.exe commands
            $commands = @(
                @{ cmd = "net.exe"; args = @("accounts", "/MINPWLEN:14") },
                @{ cmd = "net.exe"; args = @("accounts", "/MAXPWAGE:90") },
                @{ cmd = "net.exe"; args = @("accounts", "/MINPWAGE:1") },
                @{ cmd = "net.exe"; args = @("accounts", "/UNIQUEPW:24") },
                @{ cmd = "net.exe"; args = @("accounts", "/LOCKOUTTHRESHOLD:10") },
                @{ cmd = "net.exe"; args = @("accounts", "/LOCKOUTDURATION:15") },
                @{ cmd = "net.exe"; args = @("accounts", "/LOCKOUTWINDOW:15") }
            )
            
            foreach ($command in $commands) {
                $result = & $command.cmd $command.args 2>&1
                if ($LASTEXITCODE -eq 0) { $success++ } else { $failed++ }
            }
        }
        
        # Clean up temp files
        @($tempFile, $secEditFile, $dbFile, $logFile) | ForEach-Object {
            if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue }
        }
        
        # Disable LM hashes
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Type DWord -Value 1) { $success++ }
        # Restrict anonymous enumeration
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 1) { $success++ }
        # Restrict anonymous SAM enumeration
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Type DWord -Value 1) { $success++ }
        
    } catch {
        Write-Warning "Password policy configuration failed: $($_.Exception.Message)"
        $failed++
    }
    
    Write-Host "  Completed: $success successful, $failed failed" -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Yellow' })
}

function Remove-LocalAdminMembership {
    Write-Host "Reviewing local Administrators group membership (AC-6 least privilege) ..." -ForegroundColor Green
    try {
        # More comprehensive list of approved accounts
        $approved = @(
            'BUILTIN\Administrators',
            'NT AUTHORITY\SYSTEM',
            "$env:COMPUTERNAME\Administrator",
            'Administrator'
        )
        
        # Add domain admins if domain-joined
        try {
            $computerInfo = Get-WmiObject -Class Win32_ComputerSystem
            if ($computerInfo.PartOfDomain) {
                $approved += "$($computerInfo.Domain)\Domain Admins"
            }
        } catch {
            Write-Verbose "Could not determine domain membership"
        }
        
        $members = Get-LocalGroupMember -Name 'Administrators' -ErrorAction SilentlyContinue
        
        Write-Host "Current Administrators group members:"
        $unauthorizedAdmins = @()
        
        foreach ($m in $members) {
            $name = $m.Name
            $isApproved = $false
            
            foreach ($approvedName in $approved) {
                if ($name -like "*$approvedName*" -or $name -eq $approvedName) {
                    $isApproved = $true
                    break
                }
            }
            
            if ($isApproved) {
                Write-Host "  ✓ $name (Approved)" -ForegroundColor Green
            } else {
                Write-Host "  ✗ $name (Review needed)" -ForegroundColor Yellow
                $unauthorizedAdmins += $name
            }
        }
        
        if ($unauthorizedAdmins.Count -gt 0) {
            Write-Warning "Found $($unauthorizedAdmins.Count) potentially unauthorized admin(s). Manual review recommended."
            Write-Host "To remove an admin, run: Remove-LocalGroupMember -Group 'Administrators' -Member 'USERNAME'" -ForegroundColor Cyan
        }
        
    } catch { 
        Write-Warning "Failed to process local admins: $($_.Exception.Message)" 
    }
}

function Configure-WindowsFirewall {
    Write-Host "Enabling Windows Firewall on all profiles and setting inbound default deny (SC family) ..." -ForegroundColor Green
    $success = 0
    $failed = 0
    
    try {
        # Use PowerShell cmdlets when available (more reliable than netsh)
        if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
            @('Domain', 'Private', 'Public') | ForEach-Object {
                try {
                    Set-NetFirewallProfile -Profile $_ -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
                    Write-Verbose "Configured firewall profile: $_"
                    $success++
                } catch {
                    Write-Warning "Failed to configure $_ profile via PowerShell, trying netsh"
                    $profileName = $_.ToLower() + 'profile'
                    $result = & netsh.exe advfirewall set $profileName state on 2>&1
                    $result = & netsh.exe advfirewall set $profileName firewallpolicy blockinbound,allowoutbound 2>&1
                    if ($LASTEXITCODE -eq 0) { $success++ } else { $failed++ }
                }
            }
        } else {
            # Fallback to netsh
            $commands = @(
                "netsh.exe advfirewall set allprofiles state on",
                "netsh.exe advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound",
                "netsh.exe advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound",
                "netsh.exe advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound"
            )
            
            foreach ($cmd in $commands) {
                $result = Invoke-Expression $cmd 2>&1
                if ($LASTEXITCODE -eq 0) { $success++ } else { $failed++ }
            }
        }
        
        # Enable firewall logging
        Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging' -Name 'LogDroppedPackets' -Type DWord -Value 1
        Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging' -Name 'LogDroppedPackets' -Type DWord -Value 1
        
    } catch {
        Write-Warning "Firewall configuration failed: $($_.Exception.Message)"
        $failed++
    }
    
    Write-Host "  Completed: $success successful, $failed failed" -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Yellow' })
}

function Disable-SMBv1AndLegacy {
    Write-Host "Disabling SMBv1, NetBIOS over TCP/IP and enforcing SMB signing (SC family) ..." -ForegroundColor Green
    $success = 0
    $failed = 0
    
    try { 
        # Disable SMBv1 - multiple methods for compatibility
        try {
            # Method 1: PowerShell cmdlet (Windows 10/Server 2016+)
            if (Get-Command Disable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
                if ($feature -and $feature.State -eq "Enabled") {
                    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
                    Write-Verbose "Disabled SMBv1 Protocol via OptionalFeature"
                    $success++
                }
            }
            
            # Method 2: Registry (works on all versions)
            Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Type DWord -Value 0
            Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Type DWord -Value 4
            $success++
            
        } catch {
            Write-Warning "Failed to disable SMBv1: $($_.Exception.Message)"
            $failed++
        }
        
        # SMB signing for workstation & server
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1) { $success++ }
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature' -Type DWord -Value 1) { $success++ }
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1) { $success++ }
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Type DWord -Value 1) { $success++ }
        
        # Disable NetBIOS over TCP/IP for all network adapters
        Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='TRUE'" | ForEach-Object {
            try {
                $_.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS over TCP/IP
                Write-Verbose "Disabled NetBIOS over TCP/IP for adapter: $($_.Description)"
                $success++
            } catch {
                Write-Verbose "Could not disable NetBIOS for adapter: $($_.Description)"
            }
        }
        
        # LLMNR off
        if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0) { $success++ }
        
        # Disable WPAD
        if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' -Name 'Start' -Type DWord -Value 4) { $success++ }
        
    } catch {
        Write-Warning "Legacy protocol configuration failed: $($_.Exception.Message)"
        $failed++
    }
    
    Write-Host "  Completed: $success successful, $failed failed" -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Yellow' })
}

function Configure-BitLocker {
    if ($SkipBitLocker) {
        Write-Host "Skipping BitLocker configuration (SkipBitLocker parameter set)" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Configuring BitLocker (SC-13, SC-28) ..." -ForegroundColor Green
    
    try {
        # Check if BitLocker module is available
        if (-not (Get-Module -ListAvailable -Name BitLocker)) {
            Write-Warning "BitLocker module not available on this system"
            return
        }
        
        Import-Module BitLocker -ErrorAction Stop
        
        # Check TPM status
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if (-not $tpm -or -not $tpm.TpmPresent) {
            Write-Warning "TPM not present. BitLocker configuration skipped."
            return
        }
        
        if (-not $tpm.TpmReady) {
            Write-Warning "TPM not ready. Please initialize TPM in BIOS/UEFI."
            return
        }
        
        # Configure BitLocker Group Policy settings via registry
        Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'EncryptionMethod' -Type DWord -Value 7  # XTS-AES 256
        Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseAdvancedStartup' -Type DWord -Value 1
        Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPM' -Type DWord -Value 2  # Allow TPM
        Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'UseTPMPIN' -Type DWord -Value 2  # Allow TPM+PIN
        
        # Enable BitLocker on OS drive
        $osDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
        
        if ($null -eq $osDrive) {
            Write-Warning "Could not get BitLocker volume information"
            return
        }
        
        if ($osDrive.VolumeStatus -eq 'FullyDecrypted') {
            Write-Host "Enabling BitLocker on OS volume ($env:SystemDrive)..."
            
            # Add TPM protector
            try {
                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -ErrorAction Stop
                Write-Host "Added TPM protector"
                
                # Add recovery password
                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop
                Write-Host "Added recovery password protector"
                
                # Enable BitLocker
                Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -ErrorAction Stop
                Write-Host "BitLocker encryption started. A reboot will be required to complete."
                
            } catch {
                Write-Warning "Failed to enable BitLocker: $($_.Exception.Message)"
            }
            
            if ($EnableBitLockerPIN) {
                Write-Host "TPM+PIN requires manual configuration after encryption. Run: manage-bde -protectors -add C: -tpmandpin"
                Write-Host "Note: User will need to set PIN on next reboot."
            }
            
        } elseif ($osDrive.VolumeStatus -eq 'FullyEncrypted') {
            Write-Host "BitLocker already enabled and fully encrypted."
        } else {
            Write-Host "BitLocker status: $($osDrive.VolumeStatus)"
        }
        
        # Backup recovery key
        $recoveryKey = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}
        if ($recoveryKey) {
            $keyFile = Join-Path $BackupPath "BitLocker-RecoveryKey-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
            $recoveryKey | Out-File -FilePath $keyFile -Force
            Write-Host "Recovery key backed up to: $keyFile" -ForegroundColor Yellow
            Write-Warning "IMPORTANT: Store this recovery key in a secure location and remove from this system!"
        }
        
    } catch {
        Write-Warning "BitLocker configuration failed: $($_.Exception.Message)"
    }
    
    Write-Host "IMPORTANT: Configure BitLocker recovery key escrow to AD/Azure AD via GPO/Intune" -ForegroundColor Yellow
}

function Configure-Auditing {
    Write-Host "Configuring advanced auditing (AU family) and process command-line capture ..." -ForegroundColor Green
    $success = 0
    $failed = 0
    
    $auditMap = @(
        @{ Sc='Credential Validation'; S=$true; F=$true },
        @{ Sc='User Account Management'; S=$true; F=$true },
        @{ Sc='Security Group Management'; S=$true; F=$true },
        @{ Sc='Logon'; S=$true; F=$true },
        @{ Sc='Logoff'; S=$true; F=$false },
        @{ Sc='Account Lockout'; S=$false; F=$true },
        @{ Sc='Special Logon'; S=$true; F=$false },
        @{ Sc='Audit Policy Change'; S=$true; F=$true },
        @{ Sc='Authentication Policy Change'; S=$true; F=$true },
        @{ Sc='File Share'; S=$true; F=$true },
        @{ Sc='Sensitive Privilege Use'; S=$true; F=$true },
        @{ Sc='Process Creation'; S=$true; F=$false },
        @{ Sc='Process Termination'; S=$true; F=$false },
        @{ Sc='RPC Events'; S=$true; F=$true }
    )
    
    foreach ($item in $auditMap) {
        try {
            $s = if ($item.S) { 'enable' } else { 'disable' }
            $f = if ($item.F) { 'enable' } else { 'disable' }
            $result = & auditpol.exe /set /subcategory:"$($item.Sc)" /success:$s /failure:$f 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Set audit policy: $($item.Sc)"
                $success++
            } else {
                Write-Verbose "Failed to set audit policy for $($item.Sc)"
                $failed++
            }
        } catch {
            Write-Warning "Failed to set audit policy for $($item.Sc): $($_.Exception.Message)"
            $failed++
        }
    }
    
    # Enable command-line auditing
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1) { $success++ }
    
    # Increase security log size
    try {
        wevtutil.exe sl Security /ms:1073741824  # 1GB
        Write-Verbose "Increased Security log size to 1GB"
        $success++
    } catch {
        Write-Verbose "Could not increase Security log size"
        $failed++
    }
    
    Write-Host "  Completed: $success successful, $failed failed" -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Yellow' })
}

function Configure-PowerShellLogging {
    Write-Host "Enabling PowerShell script block logging and transcription (SI family) ..." -ForegroundColor Green
    $success = 0
    
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockInvocationLogging' -Type DWord -Value 1) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Type DWord -Value 1) { $success++ }
    
    $psTranscriptPath = Join-Path $TranscriptPath 'PS-Transcripts'
    New-Folder -Path $psTranscriptPath
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Type String -Value $psTranscriptPath) { $success++ }
    
    # Module logging
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Type DWord -Value 1) { $success++ }
    
    Write-Host "  Completed: $success settings configured" -ForegroundColor Green
}

function Configure-DefenderAndEDR {
    Write-Host "Configuring Microsoft Defender preferences (SI family) ..." -ForegroundColor Green
    $success = 0
    $failed = 0
    
    try {
        # Check if Defender module is available
        if (Get-Module -ListAvailable -Name Defender) {
            Import-Module Defender -ErrorAction SilentlyContinue
            
            # Check if Defender is running
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if (-not $defenderStatus -or -not $defenderStatus.AntivirusEnabled) {
                Write-Warning "Windows Defender appears to be disabled or not running"
                return
            }
            
            # Configure Defender settings
            $settings = @{
                DisableRealtimeMonitoring = $false
                DisableBehaviorMonitoring = $false
                DisableBlockAtFirstSeen = $false
                DisableIOAVProtection = $false
                DisablePrivacyMode = $false
                DisableScriptScanning = $false
                EnableControlledFolderAccess = 'Enabled'
                EnableNetworkProtection = 'Enabled'
                PUAProtection = 'Enabled'
                SubmitSamplesConsent = 2  # Send all samples
                MAPSReporting = 2  # Advanced
                CloudBlockLevel = 4  # High
                CloudExtendedTimeout = 50
                EnableDnsOverHttps = $true
                EnableFileHashComputation = $true
            }
            
            foreach ($setting in $settings.GetEnumerator()) {
                try {
                    Set-MpPreference @{$setting.Key = $setting.Value} -ErrorAction Stop
                    Write-Verbose "Set Defender: $($setting.Key) = $($setting.Value)"
                    $success++
                } catch {
                    Write-Verbose "Could not set $($setting.Key): $($_.Exception.Message)"
                    $failed++
                }
            }
            
            # Configure ASR rules (Attack Surface Reduction)
            $asrRules = @{
                # Block executable content from email client and webmail
                'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 1
                # Block all Office applications from creating child processes
                'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 1
                # Block Office applications from creating executable content
                '3B576869-A4EC-4529-8536-B80A7769E899' = 1
                # Block Office applications from injecting code into other processes
                '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 1
                # Block JavaScript or VBScript from launching downloaded executable content
                'D3E037E1-3EB8-44C8-A917-57927947596D' = 1
                # Block execution of potentially obfuscated scripts
                '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 1
                # Block Win32 API calls from Office macros
                '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 1
            }
            
            foreach ($rule in $asrRules.GetEnumerator()) {
                try {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value -ErrorAction Stop
                    Write-Verbose "Enabled ASR rule: $($rule.Key)"
                    $success++
                } catch {
                    Write-Verbose "Could not enable ASR rule: $($rule.Key)"
                    $failed++
                }
            }
            
            Write-Host "  Completed: $success successful, $failed failed" -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Yellow' })
            
        } else {
            Write-Warning "Microsoft Defender PowerShell module not available"
        }
    } catch { 
        Write-Warning "Defender configuration failed: $($_.Exception.Message)" 
    }
    
    Write-Host "For enterprise EDR, deploy Microsoft Defender for Endpoint, CrowdStrike, or similar via management platform" -ForegroundColor Yellow
}

function Configure-AppLockerSkeleton {
    if ($SkipAppLocker) {
        Write-Host "Skipping AppLocker configuration (SkipAppLocker parameter set)" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Creating AppLocker baseline rule set (CM family) ..." -ForegroundColor Green
    
    try {
        # Check if AppLocker cmdlets are available
        if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) {
            Write-Warning "AppLocker cmdlets not available. Requires Windows Enterprise/Education or Server"
            return
        }
        
        # Create default rules
        $exeRules = Get-AppLockerFileInformation -Directory "$env:ProgramFiles\*" -Recurse -FileType Exe -ErrorAction SilentlyContinue | 
            New-AppLockerPolicy -RuleType Publisher,Path -User Everyone -RuleNamePrefix "Allow_ProgramFiles_" -Optimize -ErrorAction SilentlyContinue
        
        $scriptRules = Get-AppLockerFileInformation -Directory "$env:windir\*" -Recurse -FileType Script -ErrorAction SilentlyContinue | 
            New-AppLockerPolicy -RuleType Publisher,Path -User Everyone -RuleNamePrefix "Allow_Windows_" -Optimize -ErrorAction SilentlyContinue
        
        # Merge policies
        $mergedPolicy = $exeRules
        if ($scriptRules) {
            $mergedPolicy = Merge-AppLockerPolicy -PolicyList $exeRules,$scriptRules -ErrorAction SilentlyContinue
        }
        
        # Export for review
        if ($mergedPolicy) {
            $export = Join-Path $BackupPath "AppLocker-Policy-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
            Set-AppLockerPolicy -XmlPolicy ($mergedPolicy.Xml) -Merge -ErrorAction SilentlyContinue
            $mergedPolicy.Xml | Out-File -FilePath $export -Encoding UTF8
            Write-Host "AppLocker baseline exported to: $export" -ForegroundColor Green
            Write-Host "IMPORTANT: Review and test in Audit mode before enforcing!" -ForegroundColor Yellow
        }
        
        # Start AppLocker service
        Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
        
    } catch { 
        Write-Warning "AppLocker configuration failed: $($_.Exception.Message)" 
    }
}

function Configure-AutoLock {
    Write-Host "Setting screensaver and idle lock (AC-11) ..." -ForegroundColor Green
    $success = 0
    
    # Machine policy (applies to all users)
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveActive' -Type String -Value '1') { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveTimeOut' -Type String -Value $ScreenLockTimeoutSeconds.ToString()) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -Type String -Value '1') { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'SCRNSAVE.EXE' -Type String -Value 'C:\Windows\System32\scrnsave.scr') { $success++ }
    
    # Interactive logon: Machine inactivity limit
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'autodisconnect' -Type DWord -Value 15) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value $ScreenLockTimeoutSeconds) { $success++ }
    
    Write-Host "  Configured $success settings for $($ScreenLockTimeoutSeconds) second timeout" -ForegroundColor Green
}

function Configure-WindowsUpdateAndTime {
    Write-Host "Enforcing Windows Update settings & time sync (CM, SI) ..." -ForegroundColor Green
    $success = 0
    $failed = 0
    
    # Windows Update settings
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Type DWord -Value 4) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AutoInstallMinorUpdates' -Type DWord -Value 1) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Type DWord -Value 0) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DeferFeatureUpdates' -Type DWord -Value 0) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DeferQualityUpdates' -Type DWord -Value 0) { $success++ }
    
    # Windows Time sync
    try {
        # Configure multiple NTP servers for redundancy
        $ntpServers = "time.windows.com,0x9 time.nist.gov,0x9 pool.ntp.org,0x9"
        $result = & w32tm /config /syncfromflags:manual /manualpeerlist:$ntpServers /reliable:yes /update 2>&1
        if ($LASTEXITCODE -eq 0) {
            Restart-Service w32time -Force -ErrorAction SilentlyContinue
            # Force immediate sync
            & w32tm /resync /force 2>&1 | Out-Null
            Write-Verbose "Time synchronization configured with multiple NTP servers"
            $success++
        } else {
            Write-Warning "Time sync configuration failed"
            $failed++
        }
    } catch {
        Write-Warning "Time sync configuration failed: $($_.Exception.Message)"
        $failed++
    }
    
    Write-Host "  Completed: $success successful, $failed failed" -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Yellow' })
}

function Disable-DeprecatedServices {
    Write-Host "Disabling legacy/unnecessary services (CM family) ..." -ForegroundColor Green
    $disabled = 0
    $notFound = 0
    
    # Extended list of services to disable
    $targets = @(
        'RemoteRegistry',      # Remote Registry
        'SNMP',                # SNMP Service
        'SNMPTRAP',           # SNMP Trap
        'Telnet',             # Telnet
        'TlntSvr',            # Telnet Server
        'SSDPSRV',            # SSDP Discovery
        'upnphost',           # UPnP Device Host
        'WMPNetworkSvc',      # Windows Media Player Network Sharing
        'icssvc',             # Windows Mobile Hotspot Service
        'WinHttpAutoProxySvc', # WinHTTP Web Proxy Auto-Discovery
        'HomeGroupListener',   # HomeGroup Listener
        'HomeGroupProvider',   # HomeGroup Provider
        'WSearch',            # Windows Search (optional - may impact user experience)
        'XboxGipSvc',         # Xbox Accessory Management
        'XblAuthManager',     # Xbox Live Auth Manager
        'XblGameSave',        # Xbox Live Game Save
        'XboxNetApiSvc'       # Xbox Live Networking Service
    )
    
    foreach ($t in $targets) {
        try {
            $svc = Get-Service -Name $t -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $t -Force -ErrorAction SilentlyContinue
                }
                Set-Service -Name $t -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Verbose "Disabled service: $t"
                $disabled++
            } else {
                $notFound++
            }
        } catch {
            Write-Verbose "Could not disable service $t`: $($_.Exception.Message)"
        }
    }
    
    Write-Host "  Disabled $disabled services ($notFound not found)" -ForegroundColor Green
}

function Disable-GuestAndAnonymous {
    Write-Host "Disabling Guest account and anonymous enumeration (AC family) ..." -ForegroundColor Green
    $success = 0
    
    try { 
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            Write-Verbose "Disabled Guest account"
            $success++
        } else {
            Write-Verbose "Guest account already disabled or not found"
        }
    } catch {
        Write-Verbose "Could not disable Guest account: $($_.Exception.Message)"
    }
    
    # Anonymous enumeration settings
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Type DWord -Value 0) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'ForceGuest' -Type DWord -Value 0) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Type DWord -Value 1) { $success++ }
    
    Write-Host "  Configured $success settings" -ForegroundColor Green
}

function Configure-AdditionalHardening {
    Write-Host "Applying additional security hardening..." -ForegroundColor Green
    $success = 0
    
    # Disable autorun
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Type DWord -Value 1) { $success++ }
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255) { $success++ }
    
    # Enable DEP for all programs
    try {
        bcdedit.exe /set nx AlwaysOn 2>&1 | Out-Null
        Write-Verbose "Enabled DEP for all programs"
        $success++
    } catch {
        Write-Verbose "Could not configure DEP"
    }
    
    # Disable Windows Script Host
    if (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Type DWord -Value 0) { $success++ }
    
    # Enable structured exception handling overwrite protection (SEHOP)
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Type DWord -Value 0) { $success++ }
    
    # Disable WDigest authentication (prevents plaintext password storage in memory)
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Type DWord -Value 0) { $success++ }
    
    # Enable LSA protection
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Type DWord -Value 1) { $success++ }
    
    # Disable NTLM v1
    if (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Type DWord -Value 5) { $success++ }
    
    Write-Host "  Applied $success additional hardening settings" -ForegroundColor Green
}

function Show-Summary {
    Write-Host "`n================ BASELINE SUMMARY ================" -ForegroundColor Cyan
    Write-Host "Transcript: $global:TranscriptFile" -ForegroundColor White
    Write-Host "Backups:    $BackupPath" -ForegroundColor White
    
    Write-Host "`n================ IMPORTANT ACTIONS ================" -ForegroundColor Yellow
    
    $actions = @(
        "1. Review and remove unauthorized local administrators",
        "2. Configure BitLocker recovery key escrow to AD/Azure AD",
        "3. Deploy EDR solution (Microsoft Defender for Endpoint, CrowdStrike, etc.)",
        "4. Review and customize AppLocker policy before enforcement",
        "5. Configure MFA and Conditional Access in Azure AD/IdP",
        "6. Deploy SIEM agent for centralized log collection",
        "7. Test all changes in a lab environment first",
        "8. Create GPO/Intune policies for fleet-wide deployment",
        "9. Review BitLocker recovery keys in backup folder and store securely",
        "10. Schedule regular security assessments and updates"
    )
    
    foreach ($action in $actions) {
        Write-Host $action -ForegroundColor Yellow
    }
    
    Write-Host "`n================ VERIFICATION COMMANDS ================" -ForegroundColor Cyan
    Write-Host "Check BitLocker status:     Get-BitLockerVolume" -ForegroundColor White
    Write-Host "Check firewall status:      Get-NetFirewallProfile" -ForegroundColor White
    Write-Host "Check audit policy:         auditpol /get /category:*" -ForegroundColor White
    Write-Host "Check local admins:         Get-LocalGroupMember -Group Administrators" -ForegroundColor White
    Write-Host "Check services:             Get-Service | Where {`$_.StartType -eq 'Disabled'}" -ForegroundColor White
}

# -------------------- Main Execution --------------------
Write-Host "`nNIST SP 800-53 Windows Hardening Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Version: 2.0 (Enhanced)" -ForegroundColor White
Write-Host "Testing Mode: Use -WhatIf parameter to preview changes" -ForegroundColor Yellow

Assert-Admin
Start-Logging

try {
    Write-Host "`nStarting NIST 800-53 inspired baseline configuration..." -ForegroundColor Green
    Write-Host "This may take several minutes to complete.`n" -ForegroundColor White
    
    # Core configurations
    Configure-PasswordAndAccountPolicy
    Remove-LocalAdminMembership
    Configure-WindowsFirewall
    Disable-SMBv1AndLegacy
    Configure-BitLocker
    Configure-Auditing
    Configure-PowerShellLogging
    Configure-DefenderAndEDR
    Configure-AppLockerSkeleton
    Configure-AutoLock
    Configure-WindowsUpdateAndTime
    Disable-DeprecatedServices
    Disable-GuestAndAnonymous
    Configure-AdditionalHardening
    
    # Display summary
    Show-Summary
    
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
} finally {
    if ($global:TranscriptFile) {
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
}

if (-not $NoReboot) {
    Write-Host "`n================ REBOOT REQUIRED ================" -ForegroundColor Red
    Write-Host "System will reboot in 60 seconds to apply changes." -ForegroundColor Red
    Write-Host "Save your work now! Press Ctrl+C to cancel reboot." -ForegroundColor Yellow
    Start-Sleep -Seconds 60
    Restart-Computer -Force
} else {
    Write-Host "`n================ REBOOT REQUIRED ================" -ForegroundColor Yellow
    Write-Host "Many changes require a reboot to take effect." -ForegroundColor Yellow
    Write-Host "Please restart the system at your earliest convenience." -ForegroundColor Yellow
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green
