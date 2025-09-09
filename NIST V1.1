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

.NOTES
  - Some controls (MFA, Azure AD Conditional Access, BitLocker escrow to AD/Azure) require Azure AD/Intune/AD DS or GPO. The script marks those sections and provides guidance.
  - Use Group Policy / Intune for fleet-wide enforcement where possible.
  - Run as Administrator.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$NoReboot = $true,
    [switch]$EnableBitLockerPIN = $false,   # If true, will attempt to enable TPM+PIN (requires user interaction for PIN creation)
    [string]$TranscriptPath = "$env:ProgramData\NIST80053-Baseline\Logs",
    [string]$BackupPath = "$env:ProgramData\NIST80053-Baseline\Backups"
)

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
        if (Test-Path "HKLM:$($Path.Replace('HKLM\',''))") {
            $safe = $Path -replace '[\\/:*?""<>|]', '_'
            $file = Join-Path $BackupPath ("{0}-{1}.reg" -f $safe, (Get-Date).ToString('yyyyMMdd-HHmmss'))
            $result = reg.exe export $Path $file /y 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Backed up $Path to $file"
            } else {
                Write-Warning "Failed to export $Path`: $result"
            }
        }
    } catch { 
        Write-Warning "Failed to export $Path`: $($_.Exception.Message)" 
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
            New-Item -Path $Path -Force | Out-Null 
        }
        Backup-RegKey -Path $Path
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Verbose "Set $Path\$Name = $Value ($Type)"
    } catch {
        Write-Warning "Failed to set registry value $Path\$Name`: $($_.Exception.Message)"
    }
}

function Configure-PasswordAndAccountPolicy {
    Write-Host "Configuring local password & lockout policy (AC family) ..." -ForegroundColor Green
    try {
        $commands = @(
            @{ cmd = "net.exe"; args = "accounts /MINPWLEN:14" },
            @{ cmd = "net.exe"; args = "accounts /MAXPWAGE:90" },
            @{ cmd = "net.exe"; args = "accounts /MINPWAGE:1" },
            @{ cmd = "net.exe"; args = "accounts /UNIQUEPW:24" },
            @{ cmd = "net.exe"; args = "accounts /LOCKOUTTHRESHOLD:10" },
            @{ cmd = "net.exe"; args = "accounts /LOCKOUTDURATION:15" },
            @{ cmd = "net.exe"; args = "accounts /LOCKOUTWINDOW:15" }
        )
        
        foreach ($command in $commands) {
            $result = & $command.cmd $command.args.Split(' ') 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Command failed: $($command.cmd) $($command.args)"
            }
        }
        
        # Disable LM hashes
        Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Type DWord -Value 1
        # Restrict anonymous enumeration
        Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 1
    } catch {
        Write-Warning "Password policy configuration failed: $($_.Exception.Message)"
    }
}

function Remove-LocalAdminMembership {
    Write-Host "Reviewing local Administrators group membership (AC-6 least privilege) ..." -ForegroundColor Green
    try {
        $approved = @('BUILTIN\Administrators','NT AUTHORITY\SYSTEM','Administrator') # Add any service accounts or approved admins here
        $members = Get-LocalGroupMember -Name 'Administrators' -ErrorAction SilentlyContinue
        
        Write-Host "Current Administrators group members:"
        foreach ($m in $members) {
            $name = $m.Name
            Write-Host "  - $name"
            if ($approved -notcontains $name -and $name -notmatch "Administrator$") {
                Write-Warning "Non-approved admin found: $name - Consider removing manually after review"
                # Uncomment below to actually remove (DANGEROUS - test first!)
                # if ($PSCmdlet.ShouldProcess("Local Administrators","Remove $name")) {
                #     Remove-LocalGroupMember -Name 'Administrators' -Member $name -ErrorAction SilentlyContinue
                # }
            }
        }
    } catch { 
        Write-Warning "Failed to process local admins: $($_.Exception.Message)" 
    }
    Write-Host "NOTE: Admin removal is commented out for safety. Review members above and manually remove if needed." -ForegroundColor Yellow
}

function Configure-WindowsFirewall {
    Write-Host "Enabling Windows Firewall on all profiles and setting inbound default deny (SC family) ..." -ForegroundColor Green
    try {
        $commands = @(
            "netsh.exe advfirewall set allprofiles state on",
            "netsh.exe advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound",
            "netsh.exe advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound",
            "netsh.exe advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound"
        )
        
        foreach ($cmd in $commands) {
            $result = Invoke-Expression $cmd 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Firewall command failed: $cmd"
            }
        }
    } catch {
        Write-Warning "Firewall configuration failed: $($_.Exception.Message)"
    }
}

function Disable-SMBv1AndLegacy {
    Write-Host "Disabling SMBv1, NetBIOS over TCP/IP and enforcing SMB signing (SC family) ..." -ForegroundColor Green
    try { 
        # Disable SMBv1
        $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($feature -and $feature.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-Verbose "Disabled SMBv1 Protocol"
        }
    } catch {
        Write-Warning "Failed to disable SMBv1: $($_.Exception.Message)"
    }
    
    # SMB signing for workstation & server
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1
    
    # Disable NetBIOS over TCP/IP
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'TransportBindName' -Type String -Value ''
    
    # LLMNR off
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0
}

function Configure-BitLocker {
    Write-Host "Configuring BitLocker (SC-13, CP) ..." -ForegroundColor Green
    try {
        # Check if BitLocker module is available
        if (-not (Get-Module -ListAvailable -Name BitLocker)) {
            Write-Warning "BitLocker module not available on this system"
            return
        }
        
        # Enable BitLocker with TPM protector for OS drive if not already enabled
        $os = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
        if ($null -eq $os -or $os.ProtectionStatus -ne 'On') {
            Write-Host "Enabling BitLocker on OS volume using TPM protector."
            # Check TPM status first
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            if ($tpm -and $tpm.TpmPresent -and $tpm.TpmEnabled) {
                Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -ErrorAction Stop
                Write-Host "BitLocker enable requested; user interaction or reboot may be required."
            } else {
                Write-Warning "TPM not available or not enabled. BitLocker setup skipped."
            }
        } else {
            Write-Host "BitLocker already enabled."
        }
        
        if ($EnableBitLockerPIN) {
            Write-Host "Attempting to add TPM+PIN protector (user will be prompted to set a PIN) ..."
            try {
                Add-BitLockerKeyProtector -MountPoint 'C:' -TpmPinProtector -ErrorAction Stop
            } catch { 
                Write-Warning "Could not add TPM+PIN protector: $($_.Exception.Message)" 
            }
        }
    } catch {
        Write-Warning "BitLocker configuration failed: $($_.Exception.Message)"
    }
    Write-Host "IMPORTANT: Escrow BitLocker recovery keys to AD/Azure AD or Intune. This requires AD/Azure configuration." -ForegroundColor Yellow
}

function Configure-Auditing {
    Write-Host "Configuring advanced auditing (AU family) and process command-line capture ..." -ForegroundColor Green
    
    # First, let's get available subcategories to ensure correct names
    Write-Verbose "Getting available audit subcategories..."
    
    $auditMap = @(
        @{ Sc='Credential Validation'; S=$true; F=$true },
        @{ Sc='User Account Management'; S=$true; F=$true },
        @{ Sc='Logon'; S=$true; F=$true },
        @{ Sc='Logoff'; S=$true; F=$true },
        @{ Sc='Account Lockout'; S=$true; F=$true },
        @{ Sc='Audit Policy Change'; S=$true; F=$true },
        @{ Sc='File Share'; S=$true; F=$true },
        @{ Sc='Process Creation'; S=$true; F=$false }
    )
    
    foreach ($item in $auditMap) {
        try {
            $s = if ($item.S) { 'enable' } else { 'disable' }
            $f = if ($item.F) { 'enable' } else { 'disable' }
            
            # Try with subcategory name only first
            $result = & auditpol.exe /set /subcategory:"$($item.Sc)" /success:$s /failure:$f 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Successfully configured audit policy: $($item.Sc)"
            } else {
                Write-Warning "Audit policy setting failed for '$($item.Sc)': $result"
                Write-Host "  Trying alternative method..." -ForegroundColor Yellow
                
                # Try alternative approach with category\subcategory format
                $alternativeNames = @{
                    'Credential Validation' = 'Account Logon\Credential Validation'
                    'User Account Management' = 'Account Management\User Account Management' 
                    'Logon' = 'Logon/Logoff\Logon'
                    'Logoff' = 'Logon/Logoff\Logoff'
                    'Account Lockout' = 'Logon/Logoff\Account Lockout'
                    'Audit Policy Change' = 'Policy Change\Audit Policy Change'
                    'File Share' = 'Object Access\File Share'
                    'Process Creation' = 'Detailed Tracking\Process Creation'
                }
                
                if ($alternativeNames.ContainsKey($item.Sc)) {
                    $altResult = & auditpol.exe /set /subcategory:"$($alternativeNames[$item.Sc])" /success:$s /failure:$f 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Verbose "Successfully configured with alternative name: $($alternativeNames[$item.Sc])"
                    } else {
                        Write-Warning "Both attempts failed for $($item.Sc)"
                    }
                }
            }
        } catch {
            Write-Warning "Exception setting audit policy for $($item.Sc): $($_.Exception.Message)"
        }
    }
    
    # Show current audit policy for verification
    Write-Host "Current audit policy settings:" -ForegroundColor Cyan
    $currentPolicy = & auditpol.exe /get /category:* 2>&1
    if ($LASTEXITCODE -eq 0) {
        $currentPolicy | Where-Object { $_ -match "(Credential Validation|User Account Management|Logon|Account Lockout|Audit Policy Change|File Share|Process Creation)" } | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    }
    
    Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1
}

function Configure-PowerShellLogging {
    Write-Host "Enabling PowerShell script block logging and transcription (SI family) ..." -ForegroundColor Green
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockInvocationLogging' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Type String -Value (Join-Path $TranscriptPath 'PS-Transcripts')
    New-Folder -Path (Join-Path $TranscriptPath 'PS-Transcripts')
}

function Configure-DefenderAndEDR {
    Write-Host "Configuring Microsoft Defender preferences (SI family) ..." -ForegroundColor Green
    try {
        # Check if Defender module is available
        if (Get-Module -ListAvailable -Name Defender) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
            Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
            Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
            Write-Host "Microsoft Defender preferences configured successfully."
        } else {
            Write-Warning "Microsoft Defender PowerShell module not available"
        }
    } catch { 
        Write-Warning "Set-MpPreference not available or failed: $($_.Exception.Message)" 
    }
    Write-Host "For enterprise EDR (recommended) deploy an EDR agent (CrowdStrike, Defender for Endpoint, etc.) via your management platform." -ForegroundColor Yellow
}

function Configure-AppLockerSkeleton {
    Write-Host "Creating AppLocker allow-default rule set (test-only skeleton, CM family) ..." -ForegroundColor Green
    try {
        # Check if AppLocker cmdlets are available
        if (-not (Get-Command New-AppLockerPolicy -ErrorAction SilentlyContinue)) {
            Write-Warning "AppLocker cmdlets not available on this system"
            return
        }
        
        $policy = New-AppLockerPolicy -RuleType Executable, Script -User Everyone -RuleNamePrefix "NIST_" -Optimize
        # Export for review
        $export = Join-Path $BackupPath "AppLocker-Policy.xml"
        $policy | Export-Clixml -Path $export
        Write-Host "AppLocker baseline exported to $export. Review and deploy via GPO/Intune in Audit mode first." -ForegroundColor Yellow
    } catch { 
        Write-Warning "AppLocker baseline creation failed: $($_.Exception.Message)" 
    }
}

function Configure-AutoLock {
    Write-Host "Setting screensaver and idle lock (AC-11) ..." -ForegroundColor Green
    # Set screen saver timeout to 900 seconds (15 min) and require password on resume
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveActive' -Type String -Value '1'
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveTimeOut' -Type String -Value '900'
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -Type String -Value '1'
}

function Configure-WindowsUpdateAndTime {
    Write-Host "Enforcing Windows Update settings & time sync (CM, SI) ..." -ForegroundColor Green
    # Set auto update to download and install automatically
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0
    Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Type DWord -Value 4
    
    # Enforce Windows Time sync
    try {
        $result = w32tm /config /syncfromflags:manual /manualpeerlist:"time.windows.com" 2>&1
        $result = w32tm /config /update 2>&1
        Restart-Service w32time -Force -ErrorAction SilentlyContinue
        Write-Verbose "Time synchronization configured"
    } catch {
        Write-Warning "Time sync configuration failed: $($_.Exception.Message)"
    }
}

function Disable-DeprecatedServices {
    Write-Host "Disabling legacy/unnecessary services (CM family) ..." -ForegroundColor Green
    $targets = @('RemoteRegistry','SNMP','Telnet','SSDPSRV')
    foreach ($t in $targets) {
        try {
            $svc = Get-Service -Name $t -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Set-Service -Name $t -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $t -Force -ErrorAction SilentlyContinue
                Write-Verbose "Disabled service: $t"
            }
        } catch {
            Write-Verbose "Service $t not found or already disabled"
        }
    }
}

function Disable-GuestAndAnonymous {
    Write-Host "Disabling Guest account and anonymous enumeration (AC family) ..." -ForegroundColor Green
    try { 
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            Write-Verbose "Disabled Guest account"
        }
    } catch {
        Write-Verbose "Guest account not found or already disabled"
    }
    Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Type DWord -Value 0
}

function Show-CentralLoggingNote {
    Write-Host "`nCENTRAL LOGGING REQUIREMENTS:" -ForegroundColor Cyan
    Write-Host "Ensure SIEM/Log forwarder is installed and forwarding:" -ForegroundColor Yellow
    Write-Host " - Security, Sysmon (if used), PowerShell, Application, System logs." -ForegroundColor Yellow
    Write-Host "This script does not install a SIEM agent; deploy via your management tool." -ForegroundColor Yellow
}

# -------------------- Main Execution --------------------
Write-Host "NIST 800-53 Laptop Baseline Script" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan

Assert-Admin
Start-Logging

try {
    Write-Host "`nStarting NIST 800-53 inspired laptop baseline..." -ForegroundColor Green
    
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
    Show-CentralLoggingNote

    Write-Host "`n================ SUMMARY ================" -ForegroundColor Green
    Write-Host "Transcript: $global:TranscriptFile" -ForegroundColor White
    Write-Host "Backups:    $BackupPath" -ForegroundColor White
    Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "- Review AppLocker policy exported in backups before enabling enforce mode" -ForegroundColor Yellow
    Write-Host "- BitLocker: If enabled, escrow recovery keys to AD DS / Azure AD / Intune" -ForegroundColor Yellow
    Write-Host "- MFA / Conditional Access: Configure in Azure AD/IdP" -ForegroundColor Yellow
    Write-Host "- For fleet policy management, convert these settings to GPO/Intune configuration profiles" -ForegroundColor Yellow
    
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
} finally {
    if ($global:TranscriptFile) {
        Stop-Transcript | Out-Null
    }
}

if (-not $NoReboot) {
    Write-Host "`nRebooting to apply some changes..." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "`nNoReboot specified: Changes applied where possible. Some settings require reboot." -ForegroundColor Yellow
}
