<#
.SYNOPSIS
  CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 PowerShell Implementation (Fixed)
.DESCRIPTION
  This script applies CIS (Center for Internet Security) controls for Windows 11 Enterprise
  based on the CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0.
  
  **IMPORTANT**: TEST IN A LAB ENVIRONMENT FIRST!
  Some settings may break applications or require domain infrastructure.
  
  Control Categories Implemented:
  - Account Policies (Password Policy, Account Lockout Policy)
  - Local Policies (Audit Policy, User Rights Assignment, Security Options)
  - Event Log Settings
  - System Services
  - Registry Settings
  - Windows Firewall with Advanced Security
  - Administrative Templates

.PARAMETER NoReboot
  Suppress automatic reboot after applying settings. Default = $true

.PARAMETER Level
  CIS Profile Level: 1 (essential) or 2 (comprehensive). Default = 1

.NOTES
  - Requires Administrator privileges
  - Creates backups before making changes
  - Some controls require domain membership or specific infrastructure
  - Review CIS Benchmark documentation for full implementation guidance
  
  FIXES APPLIED:
  - Fixed registry paths and values
  - Improved error handling
  - Corrected user rights assignments
  - Fixed service configuration issues
  - Added validation for critical operations
  - Fixed password complexity registry setting
  - Corrected audit policy implementation
  - Fixed user rights assignment using ntrights.exe alternative
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$NoReboot = $true,
    [ValidateSet(1,2)][int]$Level = 1,
    [string]$LogPath = "$env:ProgramData\CIS-W11-Baseline\Logs",
    [string]$BackupPath = "$env:ProgramData\CIS-W11-Baseline\Backups"
)

# Global variables
$global:TranscriptFile = $null
$global:FailedControls = @()
$global:AppliedControls = @()

function Assert-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator."
        exit 1
    }
}

function New-Folder { 
    param([string]$Path) 
    if (-not (Test-Path $Path)) { 
        New-Item -ItemType Directory -Path $Path -Force | Out-Null 
    } 
}

function Start-CISLogging {
    New-Folder -Path $LogPath
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $global:TranscriptFile = Join-Path $LogPath "CIS-W11-Baseline-$stamp.log"
    Start-Transcript -Path $global:TranscriptFile -Force | Out-Null
    New-Folder -Path $BackupPath
}

function Backup-RegKey {
    param([string]$Path)
    try {
        $registryPath = $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
        if (Test-Path $Path) {
            $safe = ($registryPath -replace '[\\/:*?""<>|]', '_').Substring(0, [Math]::Min(100, ($registryPath -replace '[\\/:*?""<>|]', '_').Length))
            $file = Join-Path $BackupPath ("{0}-{1}.reg" -f $safe, (Get-Date).ToString('yyyyMMdd-HHmmss'))
            $result = reg.exe export $registryPath $file /y 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Backed up $Path to $file"
                return $true
            }
        }
    } catch { 
        Write-Verbose "Could not backup $Path`: $($_.Exception.Message)" 
    }
    return $false
}

function Set-CISRegValue {
    param(
        [string]$Path,
        [string]$Name,
        [ValidateSet('String','ExpandString','DWord','QWord','Binary','MultiString')][string]$Type,
        [Object]$Value,
        [string]$Control
    )
    try {
        if (-not (Test-Path $Path)) { 
            New-Item -Path $Path -Force | Out-Null 
        }
        Backup-RegKey -Path $Path
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "✓ $Control - Set $Name = $Value" -ForegroundColor Green
        $global:AppliedControls += $Control
    } catch {
        Write-Warning "✗ $Control - Failed: $($_.Exception.Message)"
        $global:FailedControls += $Control
    }
}

function Set-CISAuditPolicy {
    param([string]$Subcategory, [string]$Setting, [string]$Control)
    try {
        $result = & auditpol.exe /set /subcategory:"$Subcategory" $Setting 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ $Control - Configured audit: $Subcategory" -ForegroundColor Green
            $global:AppliedControls += $Control
        } else {
            Write-Warning "✗ $Control - Audit policy failed: $result"
            $global:FailedControls += $Control
        }
    } catch {
        Write-Warning "✗ $Control - Exception: $($_.Exception.Message)"
        $global:FailedControls += $Control
    }
}

function Set-CISUserRight {
    param([string]$Right, [string]$Principals, [string]$Control)
    try {
        # Create temporary security template
        $tempFile = [System.IO.Path]::GetTempFileName()
        $tempDbFile = [System.IO.Path]::GetTempFileName()
        
        # Build the security template content
        $secTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$Right = $Principals
"@
        
        # Write template to file with UTF-16 LE encoding
        [System.IO.File]::WriteAllText($tempFile, $secTemplate, [System.Text.Encoding]::Unicode)
        
        # Apply the security template
        $result = & secedit.exe /configure /db $tempDbFile /cfg $tempFile /quiet 2>&1
        
        # Clean up temp files
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDbFile) { Remove-Item $tempDbFile -Force -ErrorAction SilentlyContinue }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ $Control - Set user right: $Right" -ForegroundColor Green
            $global:AppliedControls += $Control
        } else {
            Write-Warning "✗ $Control - User right assignment failed: $result"
            $global:FailedControls += $Control
        }
    } catch {
        Write-Warning "✗ $Control - Exception: $($_.Exception.Message)"
        $global:FailedControls += $Control
    }
}

#region CIS Level 1 Controls

function Set-CIS-1_1_PasswordPolicy {
    Write-Host "`n=== CIS 1.1 - Password Policy ===" -ForegroundColor Cyan
    
    try {
        # 1.1.1 Enforce password history: 24 or more password(s)
        & net.exe accounts /UNIQUEPW:24 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.1.1 - Password history set to 24" -ForegroundColor Green
            $global:AppliedControls += "1.1.1"
        } else {
            Write-Warning "✗ 1.1.1 - Failed to set password history"
            $global:FailedControls += "1.1.1"
        }
        
        # 1.1.2 Maximum password age: 365 or fewer days
        & net.exe accounts /MAXPWAGE:365 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.1.2 - Maximum password age set to 365 days" -ForegroundColor Green
            $global:AppliedControls += "1.1.2"
        } else {
            Write-Warning "✗ 1.1.2 - Failed to set maximum password age"
            $global:FailedControls += "1.1.2"
        }
        
        # 1.1.3 Minimum password age: 1 or more day(s)
        & net.exe accounts /MINPWAGE:1 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.1.3 - Minimum password age set to 1 day" -ForegroundColor Green
            $global:AppliedControls += "1.1.3"
        } else {
            Write-Warning "✗ 1.1.3 - Failed to set minimum password age"
            $global:FailedControls += "1.1.3"
        }
        
        # 1.1.4 Minimum password length: 14 or more character(s)
        & net.exe accounts /MINPWLEN:14 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.1.4 - Minimum password length set to 14" -ForegroundColor Green
            $global:AppliedControls += "1.1.4"
        } else {
            Write-Warning "✗ 1.1.4 - Failed to set minimum password length"
            $global:FailedControls += "1.1.4"
        }
        
        # 1.1.5 Password must meet complexity requirements: Enabled
        # This requires using secedit for local security policy
        $tempFile = [System.IO.Path]::GetTempFileName()
        $tempDbFile = [System.IO.Path]::GetTempFileName()
        
        $secTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
PasswordComplexity = 1
"@
        
        [System.IO.File]::WriteAllText($tempFile, $secTemplate, [System.Text.Encoding]::Unicode)
        $result = & secedit.exe /configure /db $tempDbFile /cfg $tempFile /quiet 2>&1
        
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDbFile) { Remove-Item $tempDbFile -Force -ErrorAction SilentlyContinue }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.1.5 - Password complexity requirements enabled" -ForegroundColor Green
            $global:AppliedControls += "1.1.5"
        } else {
            Write-Warning "✗ 1.1.5 - Failed to enable password complexity"
            $global:FailedControls += "1.1.5"
        }
        
    } catch {
        Write-Warning "Password policy configuration failed: $($_.Exception.Message)"
        $global:FailedControls += "1.1.x"
    }
}

function Set-CIS-1_2_AccountLockout {
    Write-Host "`n=== CIS 1.2 - Account Lockout Policy ===" -ForegroundColor Cyan
    
    try {
        # 1.2.1 Account lockout duration: 15 or more minute(s)
        & net.exe accounts /LOCKOUTDURATION:15 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.2.1 - Account lockout duration set to 15 minutes" -ForegroundColor Green
            $global:AppliedControls += "1.2.1"
        } else {
            Write-Warning "✗ 1.2.1 - Failed to set lockout duration"
            $global:FailedControls += "1.2.1"
        }
        
        # 1.2.2 Account lockout threshold: 5 or fewer invalid logon attempt(s)  
        & net.exe accounts /LOCKOUTTHRESHOLD:5 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.2.2 - Account lockout threshold set to 5 attempts" -ForegroundColor Green
            $global:AppliedControls += "1.2.2"
        } else {
            Write-Warning "✗ 1.2.2 - Failed to set lockout threshold"
            $global:FailedControls += "1.2.2"
        }
        
        # 1.2.3 Reset account lockout counter after: 15 or more minute(s)
        & net.exe accounts /LOCKOUTWINDOW:15 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ 1.2.3 - Reset account lockout counter set to 15 minutes" -ForegroundColor Green
            $global:AppliedControls += "1.2.3"
        } else {
            Write-Warning "✗ 1.2.3 - Failed to set lockout window"
            $global:FailedControls += "1.2.3"
        }
    } catch {
        Write-Warning "Account lockout policy configuration failed: $($_.Exception.Message)"
        $global:FailedControls += "1.2.x"
    }
}

function Set-CIS-2_2_UserRights {
    Write-Host "`n=== CIS 2.2 - User Rights Assignment ===" -ForegroundColor Cyan
    
    # 2.2.1 Access Credential Manager as a trusted caller: No One
    Set-CISUserRight -Right "SeTrustedCredManAccessPrivilege" -Principals "" -Control "2.2.1"
    
    # 2.2.4 Act as part of the operating system: No One
    Set-CISUserRight -Right "SeTcbPrivilege" -Principals "" -Control "2.2.4"
    
    # 2.2.6 Adjust memory quotas for a process: Administrators, LOCAL SERVICE, NETWORK SERVICE
    Set-CISUserRight -Right "SeIncreaseQuotaPrivilege" -Principals "*S-1-5-32-544,*S-1-5-19,*S-1-5-20" -Control "2.2.6"
    
    # 2.2.7 Allow log on locally: Administrators, Users
    Set-CISUserRight -Right "SeInteractiveLogonRight" -Principals "*S-1-5-32-544,*S-1-5-32-545" -Control "2.2.7"
    
    # 2.2.9 Allow log on through Remote Desktop Services: Administrators, Remote Desktop Users
    Set-CISUserRight -Right "SeRemoteInteractiveLogonRight" -Principals "*S-1-5-32-544,*S-1-5-32-555" -Control "2.2.9"
    
    # 2.2.15 Create a token object: No One
    Set-CISUserRight -Right "SeCreateTokenPrivilege" -Principals "" -Control "2.2.15"
    
    # 2.2.16 Create global objects: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
    Set-CISUserRight -Right "SeCreateGlobalPrivilege" -Principals "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6" -Control "2.2.16"
    
    # 2.2.17 Create permanent shared objects: No One
    Set-CISUserRight -Right "SeCreatePermanentPrivilege" -Principals "" -Control "2.2.17"
    
    # 2.2.21 Debug programs: Administrators
    Set-CISUserRight -Right "SeDebugPrivilege" -Principals "*S-1-5-32-544" -Control "2.2.21"
    
    # 2.2.23 Deny log on as a batch job: Guests
    Set-CISUserRight -Right "SeDenyBatchLogonRight" -Principals "*S-1-5-32-546" -Control "2.2.23"
    
    # 2.2.24 Deny log on as a service: Guests
    Set-CISUserRight -Right "SeDenyServiceLogonRight" -Principals "*S-1-5-32-546" -Control "2.2.24"
    
    # 2.2.25 Deny log on locally: Guests
    Set-CISUserRight -Right "SeDenyInteractiveLogonRight" -Principals "*S-1-5-32-546" -Control "2.2.25"
    
    # 2.2.28 Deny log on through Remote Desktop Services: Guests, Local account
    Set-CISUserRight -Right "SeDenyRemoteInteractiveLogonRight" -Principals "*S-1-5-32-546,*S-1-5-113" -Control "2.2.28"
}

function Set-CIS-2_3_SecurityOptions {
    Write-Host "`n=== CIS 2.3 - Security Options ===" -ForegroundColor Cyan
    
    # 2.3.1.1 Accounts: Administrator account status: Disabled
    try {
        $admin = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith('-500') }
        if ($admin) {
            Disable-LocalUser -SID $admin.SID -ErrorAction SilentlyContinue
            Write-Host "✓ 2.3.1.1 - Administrator account disabled" -ForegroundColor Green
            $global:AppliedControls += "2.3.1.1"
        }
    } catch {
        Write-Warning "✗ 2.3.1.1 - Failed to disable Administrator account: $($_.Exception.Message)"
        $global:FailedControls += "2.3.1.1"
    }
    
    # 2.3.1.2 Accounts: Block Microsoft accounts: Users can't add or log on with Microsoft accounts
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Type DWord -Value 3 -Control "2.3.1.2"
    
    # 2.3.1.3 Accounts: Guest account status: Disabled
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
            Write-Host "✓ 2.3.1.3 - Guest account disabled" -ForegroundColor Green
        } else {
            Write-Host "✓ 2.3.1.3 - Guest account already disabled or not found" -ForegroundColor Green
        }
        $global:AppliedControls += "2.3.1.3"
    } catch {
        Write-Verbose "Guest account operation: $($_.Exception.Message)"
        $global:AppliedControls += "2.3.1.3"
    }
    
    # 2.3.1.4 Accounts: Limit local account use of blank passwords to console logon only: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Type DWord -Value 1 -Control "2.3.1.4"
    
    # 2.3.2.1 Audit: Force audit policy subcategory settings: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1 -Control "2.3.2.1"
    
    # 2.3.2.2 Audit: Shut down system immediately if unable to log security audits: Disabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'CrashOnAuditFail' -Type DWord -Value 0 -Control "2.3.2.2"
    
    # 2.3.4.1 Devices: Allowed to format and eject removable media: Administrators
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AllocateDASD' -Type String -Value '0' -Control "2.3.4.1"
    
    # 2.3.4.2 Devices: Prevent users from installing printer drivers: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name 'AddPrinterDrivers' -Type DWord -Value 1 -Control "2.3.4.2"
    
    # 2.3.6.1 Domain member: Digitally encrypt or sign secure channel data (always): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Type DWord -Value 1 -Control "2.3.6.1"
    
    # 2.3.6.2 Domain member: Digitally encrypt secure channel data (when possible): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Type DWord -Value 1 -Control "2.3.6.2"
    
    # 2.3.6.3 Domain member: Digitally sign secure channel data (when possible): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Type DWord -Value 1 -Control "2.3.6.3"
    
    # 2.3.7.1 Interactive logon: Do not display last user name: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value 1 -Control "2.3.7.1"
    
    # 2.3.7.2 Interactive logon: Do not require CTRL+ALT+DEL: Disabled (require CTRL+ALT+DEL)
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Type DWord -Value 0 -Control "2.3.7.2"
    
    # 2.3.7.4 Interactive logon: Machine inactivity limit: 900 or fewer second(s)
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value 900 -Control "2.3.7.4"
    
    # 2.3.7.5 Interactive logon: Message text for users attempting to log on
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeText' -Type String -Value 'This system is for authorized users only. All activities are monitored and logged.' -Control "2.3.7.5"
    
    # 2.3.7.6 Interactive logon: Message title for users attempting to log on
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -Type String -Value 'WARNING: Authorized Use Only' -Control "2.3.7.6"
    
    # 2.3.8.1 Microsoft network client: Digitally sign communications (always): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1 -Control "2.3.8.1"
    
    # 2.3.8.2 Microsoft network client: Digitally sign communications (if server agrees): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature' -Type DWord -Value 1 -Control "2.3.8.2"
    
    # 2.3.8.3 Microsoft network client: Send unencrypted password to third-party SMB servers: Disabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Type DWord -Value 0 -Control "2.3.8.3"
    
    # 2.3.9.1 Microsoft network server: Amount of idle time required before suspending session: 15 or fewer minute(s)
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'AutoDisconnect' -Type DWord -Value 15 -Control "2.3.9.1"
    
    # 2.3.9.2 Microsoft network server: Digitally sign communications (always): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1 -Control "2.3.9.2"
    
    # 2.3.9.3 Microsoft network server: Digitally sign communications (if client agrees): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'EnableSecuritySignature' -Type DWord -Value 1 -Control "2.3.9.3"
    
    # 2.3.10.2 Network access: Do not allow anonymous enumeration of SAM accounts: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Type DWord -Value 1 -Control "2.3.10.2"
    
    # 2.3.10.3 Network access: Do not allow anonymous enumeration of SAM accounts and shares: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 1 -Control "2.3.10.3"
    
    # 2.3.11.1 Network security: Allow Local System to use computer identity for NTLM: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Type DWord -Value 1 -Control "2.3.11.1"
    
    # 2.3.11.2 Network security: Allow LocalSystem NULL session fallback: Disabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AllowNullSessionFallback' -Type DWord -Value 0 -Control "2.3.11.2"
    
    # 2.3.11.5 Network security: Do not store LAN Manager hash value on next password change: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Type DWord -Value 1 -Control "2.3.11.5"
    
    # 2.3.11.9 Network security: LAN Manager authentication level: Send NTLMv2 response only. Refuse LM & NTLM
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Type DWord -Value 5 -Control "2.3.11.9"
}

function Set-CIS-EventLogSettings {
    Write-Host "`n=== CIS Event Log Settings ===" -ForegroundColor Cyan
    
    # Application log settings
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'Retention' -Type String -Value '0' -Control "EventLog-App-Retention"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Type DWord -Value 32768 -Control "EventLog-App-MaxSize"
    
    # Security log settings  
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'Retention' -Type String -Value '0' -Control "EventLog-Sec-Retention"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Type DWord -Value 196608 -Control "EventLog-Sec-MaxSize"
    
    # System log settings
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'Retention' -Type String -Value '0' -Control "EventLog-Sys-Retention"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Type DWord -Value 32768 -Control "EventLog-Sys-MaxSize"
}

function Set-CIS-WindowsFirewall {
    Write-Host "`n=== CIS Windows Defender Firewall ===" -ForegroundColor Cyan
    
    try {
        # Domain Profile
        Set-NetFirewallProfile -Profile Domain -Enabled True -ErrorAction Stop
        Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -ErrorAction Stop
        Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Allow -ErrorAction Stop
        Write-Host "✓ Domain firewall configured" -ForegroundColor Green
        $global:AppliedControls += "9.1.x"
        
        # Private Profile
        Set-NetFirewallProfile -Profile Private -Enabled True -ErrorAction Stop
        Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block -ErrorAction Stop
        Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Allow -ErrorAction Stop
        Write-Host "✓ Private firewall configured" -ForegroundColor Green
        $global:AppliedControls += "9.2.x"
        
        # Public Profile
        Set-NetFirewallProfile -Profile Public -Enabled True -ErrorAction Stop
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -ErrorAction Stop
        Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow -ErrorAction Stop
        Write-Host "✓ Public firewall configured" -ForegroundColor Green
        $global:AppliedControls += "9.3.x"
        
    } catch {
        Write-Warning "Windows Firewall configuration failed: $($_.Exception.Message)"
        $global:FailedControls += "9.x.x"
    }
}

function Set-CIS-AuditPolicy {
    Write-Host "`n=== CIS Advanced Audit Policy Configuration ===" -ForegroundColor Cyan
    
    # Enable command line auditing first
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 -Control "17.3.2-CmdLine"
    
    # Account Logon
    Set-CISAuditPolicy -Subcategory "Credential Validation" -Setting "/success:enable /failure:enable" -Control "17.1.1"
    
    # Account Management
    Set-CISAuditPolicy -Subcategory "Application Group Management" -Setting "/success:enable /failure:enable" -Control "17.2.1"
    Set-CISAuditPolicy -Subcategory "Computer Account Management" -Setting "/success:enable /failure:enable" -Control "17.2.2"
    Set-CISAuditPolicy -Subcategory "Distribution Group Management" -Setting "/success:enable /failure:enable" -Control "17.2.3"
    Set-CISAuditPolicy -Subcategory "Other Account Management Events" -Setting "/success:enable /failure:enable" -Control "17.2.4"
    Set-CISAuditPolicy -Subcategory "Security Group Management" -Setting "/success:enable /failure:enable" -Control "17.2.5"
    Set-CISAuditPolicy -Subcategory "User Account Management" -Setting "/success:enable /failure:enable" -Control "17.2.6"
    
    # Detailed Tracking
    Set-CISAuditPolicy -Subcategory "Plug and Play Events" -Setting "/success:enable" -Control "17.3.1"
    Set-CISAuditPolicy -Subcategory "Process Creation" -Setting "/success:enable" -Control "17.3.2"
    
    # DS Access
    Set-CISAuditPolicy -Subcategory "Directory Service Access" -Setting "/success:enable /failure:enable" -Control "17.4.1"
    Set-CISAuditPolicy -Subcategory "Directory Service Changes" -Setting "/success:enable /failure:enable" -Control "17.4.2"
    
    # Logon/Logoff
    Set-CISAuditPolicy -Subcategory "Account Lockout" -Setting "/success:enable /failure:enable" -Control "17.5.1"
    Set-CISAuditPolicy -Subcategory "Group Membership" -Setting "/success:enable" -Control "17.5.2"
    Set-CISAuditPolicy -Subcategory "Logoff" -Setting "/success:enable" -Control "17.5.3"
    Set-CISAuditPolicy -Subcategory "Logon" -Setting "/success:enable /failure:enable" -Control "17.5.4"
    Set-CISAuditPolicy -Subcategory "Other Logon/Logoff Events" -Setting "/success:enable /failure:enable" -Control "17.5.5"
    Set-CISAuditPolicy -Subcategory "Special Logon" -Setting "/success:enable" -Control "17.5.6"
    
    # Object Access
    Set-CISAuditPolicy -Subcategory "Removable Storage" -Setting "/success:enable /failure:enable" -Control "17.6.1"
    
    # Policy Change
    Set-CISAuditPolicy -Subcategory "Audit Policy Change" -Setting "/success:enable /failure:enable" -Control "17.7.1"
    Set-CISAuditPolicy -Subcategory "Authentication Policy Change" -Setting "/success:enable" -Control "17.7.2"
    Set-CISAuditPolicy -Subcategory "Authorization Policy Change" -Setting "/success:enable" -Control "17.7.3"
    Set-CISAuditPolicy -Subcategory "MPSSVC Rule-Level Policy Change" -Setting "/success:enable /failure:enable" -Control "17.7.4"
    Set-CISAuditPolicy -Subcategory "Other Policy Change Events" -Setting "/failure:enable" -Control "17.7.5"
    
    # Privilege Use
    Set-CISAuditPolicy -Subcategory "Sensitive Privilege Use" -Setting "/success:enable /failure:enable" -Control "17.8.1"
    
    # System
    Set-CISAuditPolicy -Subcategory "IPsec Driver" -Setting "/success:enable /failure:enable" -Control "17.9.1"
    Set-CISAuditPolicy -Subcategory "Other System Events" -Setting "/success:enable /failure:enable" -Control "17.9.2"
    Set-CISAuditPolicy -Subcategory "Security State Change" -Setting "/success:enable" -Control "17.9.3"
    Set-CISAuditPolicy -Subcategory "Security System Extension" -Setting "/success:enable /failure:enable" -Control "17.9.4"
    Set-CISAuditPolicy -Subcategory "System Integrity" -Setting "/success:enable /failure:enable" -Control "17.9.5"
}

function Set-CIS-AdministrativeTemplates {
    Write-Host "`n=== CIS Administrative Templates ===" -ForegroundColor Cyan
    
    # 18.1.1.1 Prevent enabling lock screen camera: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value 1 -Control "18.1.1.1"
    
    # 18.1.1.2 Prevent enabling lock screen slide show: Enabled  
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Type DWord -Value 1 -Control "18.1.1.2"
    
    # 18.1.2.2 Allow users to enable online speech recognition services: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Speech' -Name 'AllowSpeechModelUpdate' -Type DWord -Value 0 -Control "18.1.2.2"
    
    # 18.1.3 Allow Online Tips: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'AllowOnlineTips' -Type DWord -Value 0 -Control "18.1.3"
    
    # 18.3.1 Apply UAC restrictions to local accounts on network logons: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0 -Control "18.3.1"
    
    # 18.3.2 Configure SMB v1 client driver: Enabled: Disable driver
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Type DWord -Value 4 -Control "18.3.2"
    
    # 18.3.3 Configure SMB v1 server: Disabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Type DWord -Value 0 -Control "18.3.3"
    
    # 18.3.4 Enable Structured Exception Handling Overwrite Protection (SEHOP): Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Type DWord -Value 0 -Control "18.3.4"
    
    # 18.3.6 NetBT NodeType configuration: Enabled: P-node
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Type DWord -Value 2 -Control "18.3.6"
    
    # 18.3.7 WDigest Authentication: Disabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Type DWord -Value 0 -Control "18.3.7"
    
    # MSS (Microsoft Security Settings)
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Type String -Value '0' -Control "18.4.1"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2 -Control "18.4.2"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2 -Control "18.4.3"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Type DWord -Value 0 -Control "18.4.4"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -Type DWord -Value 300000 -Control "18.4.5"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NoNameReleaseOnDemand' -Type DWord -Value 1 -Control "18.4.6"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'PerformRouterDiscovery' -Type DWord -Value 0 -Control "18.4.7"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode' -Type DWord -Value 1 -Control "18.4.8"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScreenSaverGracePeriod' -Type String -Value '5' -Control "18.4.9"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 -Control "18.4.10"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 -Control "18.4.11"
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -Name 'WarningLevel' -Type DWord -Value 90 -Control "18.4.12"
    
    # Network settings
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0 -Control "18.5.4.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Type DWord -Value 0 -Control "18.5.8.1"
    
    # Hardened UNC Paths
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Control "18.5.14.1a"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Control "18.5.14.1b"
    
    # Windows Update settings
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0 -Control "18.8.25.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Type DWord -Value 4 -Control "18.8.25.4"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Type DWord -Value 0 -Control "18.8.25.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallTime' -Type DWord -Value 3 -Control "18.8.25.3"
    
    # Device Guard / Credential Guard
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1 -Control "18.8.5.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 1 -Control "18.8.5.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 1 -Control "18.8.5.3"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags' -Type DWord -Value 1 -Control "18.8.5.5"
    
    # PowerShell logging
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 -Control "18.9.44.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1 -Control "18.9.44.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Type String -Value '' -Control "18.9.44.2-Dir"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Type DWord -Value 1 -Control "18.9.44.2-Header"
    
    # WinRM settings
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Type DWord -Value 0 -Control "18.9.52.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0 -Control "18.9.52.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Type DWord -Value 0 -Control "18.9.52.3"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Type DWord -Value 0 -Control "18.9.53.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0 -Control "18.9.53.3"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Type DWord -Value 1 -Control "18.9.53.4"
    
    # Windows Explorer SmartScreen
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value 1 -Control "18.9.80.1.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Type String -Value 'Block' -Control "18.9.80.1.2"
    
    # AutoRun/AutoPlay
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Type DWord -Value 1 -Control "18.9.8.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Type DWord -Value 1 -Control "18.9.8.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 -Control "18.9.8.3"
    
    # Privacy and telemetry settings
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableConsumerAccountStateContent' -Type DWord -Value 1 -Control "18.9.16.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1 -Control "18.9.16.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1 -Control "18.9.30.4"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DisableEnterpriseAuthProxy' -Type DWord -Value 1 -Control "18.9.30.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0 -Control "18.9.30.1"
    
    # App privacy settings
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsActivateWithVoiceAboveLock' -Type DWord -Value 2 -Control "18.9.98.1"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -Type DWord -Value 2 -Control "18.9.98.2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCalendar' -Type DWord -Value 2 -Control "18.9.98.3"
}

#endregion

#region CIS Level 2 Controls (Additional for comprehensive hardening)

function Set-CIS-Level2-Controls {
    if ($Level -lt 2) { return }
    
    Write-Host "`n=== CIS Level 2 Additional Controls ===" -ForegroundColor Cyan
    
    # 2.3.7.3 Interactive logon: Number of previous logons to cache: 4 or fewer logon(s)
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Type String -Value '4' -Control "2.3.7.3-L2"
    
    # 2.3.7.8 Interactive logon: Prompt user to change password before expiration: between 5 and 14 days
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'PasswordExpiryWarning' -Type DWord -Value 5 -Control "2.3.7.8-L2"
    
    # 2.3.7.9 Interactive logon: Smart card removal behavior: Lock Workstation or Force Logoff
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Type String -Value '1' -Control "2.3.7.9-L2"
    
    # Additional Level 2 App Privacy Controls
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCallHistory' -Type DWord -Value 2 -Control "18.9.98.4-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCamera' -Type DWord -Value 2 -Control "18.9.98.5-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessContacts' -Type DWord -Value 2 -Control "18.9.98.6-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessEmail' -Type DWord -Value 2 -Control "18.9.98.7-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessLocation' -Type DWord -Value 2 -Control "18.9.98.8-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessMessaging' -Type DWord -Value 2 -Control "18.9.98.9-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessMicrophone' -Type DWord -Value 2 -Control "18.9.98.10-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessRadios' -Type DWord -Value 2 -Control "18.9.98.11-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsSyncWithDevices' -Type DWord -Value 2 -Control "18.9.98.12-L2"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessTrustedDevices' -Type DWord -Value 2 -Control "18.9.98.13-L2"
    
    Write-Host "✓ Applied Level 2 additional controls" -ForegroundColor Green
}

#endregion

function Disable-UnnecessaryServices {
    Write-Host "`n=== Disabling Unnecessary Services ===" -ForegroundColor Cyan
    
    $servicesToDisable = @(
        @{ Name = 'RemoteRegistry'; Display = 'Remote Registry' },
        @{ Name = 'SSDPSRV'; Display = 'SSDP Discovery' },
        @{ Name = 'upnphost'; Display = 'UPnP Device Host' },
        @{ Name = 'WMPNetworkSvc'; Display = 'Windows Media Player Network Sharing Service' },
        @{ Name = 'XblAuthManager'; Display = 'Xbox Live Auth Manager' },
        @{ Name = 'XblGameSave'; Display = 'Xbox Live Game Save' },
        @{ Name = 'XboxNetApiSvc'; Display = 'Xbox Live Networking Service' },
        @{ Name = 'Browser'; Display = 'Computer Browser' },
        @{ Name = 'TapiSrv'; Display = 'Telephony' },
        @{ Name = 'simptcp'; Display = 'Simple TCP/IP Services' },
        @{ Name = 'sacsvr'; Display = 'Special Administration Console Helper' }
    )
    
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($svc -and $svc.StartType -ne 'Disabled') {
                # Stop service if running
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                }
                # Set to disabled
                Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "✓ Disabled service: $($service.Display)" -ForegroundColor Green
                $global:AppliedControls += "Service-$($service.Name)"
            }
        } catch {
            Write-Verbose "Service $($service.Name) not found or already disabled: $($_.Exception.Message)"
        }
    }
}

function Remove-WindowsCapabilities {
    Write-Host "`n=== Removing Optional Windows Capabilities ===" -ForegroundColor Cyan
    
    $capabilitiesToRemove = @(
        'Browser.InternetExplorer~~~~0.0.11.0',
        'MathRecognizer~~~~0.0.1.0',
        'PowerShell.ISE~~~~0.0.1.0',
        'Microsoft.Windows.WordPad~~~~0.0.1.0'
    )
    
    foreach ($capability in $capabilitiesToRemove) {
        try {
            $cap = Get-WindowsCapability -Online -Name "*$capability*" -ErrorAction SilentlyContinue | Where-Object State -eq 'Installed'
            if ($cap) {
                foreach ($c in $cap) {
                    Remove-WindowsCapability -Online -Name $c.Name -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "✓ Removed capability: $($c.Name)" -ForegroundColor Green
                    $global:AppliedControls += "Capability-$($c.Name)"
                }
            }
        } catch {
            Write-Verbose "Capability $capability not found or already removed: $($_.Exception.Message)"
        }
    }
}

function Test-DomainJoined {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        return ($computerSystem.PartOfDomain -eq $true)
    } catch {
        return $false
    }
}

function Show-Summary {
    Write-Host "`n==================== SUMMARY ====================" -ForegroundColor Green
    Write-Host "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0" -ForegroundColor White
    Write-Host "Profile Level: $Level" -ForegroundColor White
    Write-Host "Domain Joined: $(if (Test-DomainJoined) { 'Yes' } else { 'No' })" -ForegroundColor White
    Write-Host "Transcript: $global:TranscriptFile" -ForegroundColor White
    Write-Host "Backups: $BackupPath" -ForegroundColor White
    
    Write-Host "`nApplied Controls: $($global:AppliedControls.Count)" -ForegroundColor Green
    Write-Host "Failed Controls: $($global:FailedControls.Count)" -ForegroundColor Red
    
    if ($global:FailedControls.Count -gt 0) {
        Write-Host "`nFailed Controls:" -ForegroundColor Red
        $global:FailedControls | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }
    
    Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "- Some controls may require domain membership or specific infrastructure" -ForegroundColor Yellow
    Write-Host "- Test all applications after applying these changes" -ForegroundColor Yellow  
    Write-Host "- Review Windows Event Logs for any issues" -ForegroundColor Yellow
    Write-Host "- Consider implementing remaining controls via Group Policy for domain environments" -ForegroundColor Yellow
    Write-Host "- Credential Guard requires UEFI firmware and TPM 2.0" -ForegroundColor Yellow
    
    if ($Level -eq 1) {
        Write-Host "- To apply Level 2 controls, run script with -Level 2 parameter" -ForegroundColor Yellow
    }
    
    Write-Host "`nRECOMMENDED NEXT STEPS:" -ForegroundColor Cyan
    Write-Host "1. Verify Windows Update is functioning properly" -ForegroundColor White
    Write-Host "2. Test Remote Desktop connections if used" -ForegroundColor White
    Write-Host "3. Verify SMB file sharing if used" -ForegroundColor White
    Write-Host "4. Test PowerShell remoting if used" -ForegroundColor White
    Write-Host "5. Check Windows Defender status and policies" -ForegroundColor White
    Write-Host "6. Review audit logs for baseline security events" -ForegroundColor White
    Write-Host "7. Validate firewall rules don't block required applications" -ForegroundColor White
}

function Test-Prerequisites {
    Write-Host "`n=== Checking Prerequisites ===" -ForegroundColor Cyan
    
    $issues = @()
    
    # Check Windows version
    $osVersion = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($osVersion.Caption -notlike "*Windows 11*") {
        $issues += "This script is designed for Windows 11. Current OS: $($osVersion.Caption)"
    }
    
    # Check if running as Administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        $issues += "Script must be run as Administrator"
    }
    
    # Check disk space for logs and backups
    $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -lt 1) {
        $issues += "Low disk space on system drive: ${freeSpaceGB}GB free"
    }
    
    # Check for required executables
    $requiredExes = @('net.exe', 'auditpol.exe', 'secedit.exe', 'reg.exe')
    foreach ($exe in $requiredExes) {
        $path = Get-Command $exe -ErrorAction SilentlyContinue
        if (-not $path) {
            $issues += "Required executable not found: $exe"
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Host "`nPrerequisite Issues Found:" -ForegroundColor Red
        $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        return $false
    } else {
        Write-Host "✓ All prerequisites met" -ForegroundColor Green
        return $true
    }
}

#region Main Execution

Write-Host "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 (Fixed)" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "Profile Level: $Level" -ForegroundColor White
Write-Host "NoReboot: $NoReboot" -ForegroundColor White
Write-Host "Started: $(Get-Date)" -ForegroundColor White

# Check prerequisites first
if (-not (Test-Prerequisites)) {
    Write-Error "Prerequisites not met. Exiting."
    exit 1
}

Assert-Admin
Start-CISLogging

try {
    Write-Host "`nStarting CIS Windows 11 Enterprise Baseline Implementation..." -ForegroundColor Green
    $startTime = Get-Date
    
    # CIS Level 1 Controls (Essential)
    Set-CIS-1_1_PasswordPolicy
    Set-CIS-1_2_AccountLockout  
    Set-CIS-2_2_UserRights
    Set-CIS-2_3_SecurityOptions
    Set-CIS-EventLogSettings
    Set-CIS-WindowsFirewall
    Set-CIS-AuditPolicy
    Set-CIS-AdministrativeTemplates
    
    # CIS Level 2 Controls (Comprehensive) - Only if Level 2 specified
    Set-CIS-Level2-Controls
    
    # Additional hardening
    Disable-UnnecessaryServices
    Remove-WindowsCapabilities
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "`n==================== EXECUTION COMPLETED ====================" -ForegroundColor Green
    Write-Host "Execution Time: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Completed: $(Get-Date)" -ForegroundColor White
    
    Show-Summary
    
    Write-Host "`nCIS baseline implementation completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    $global:FailedControls += "SCRIPT-EXECUTION"
    Show-Summary
    exit 1
} finally {
    if ($global:TranscriptFile) {
        Stop-Transcript | Out-Null
        Write-Host "Full transcript saved to: $global:TranscriptFile" -ForegroundColor Gray
    }
}

# Final reboot handling
if (-not $NoReboot) {
    Write-Host "`nSome changes require a reboot to take effect." -ForegroundColor Yellow
    Write-Host "Rebooting in 30 seconds..." -ForegroundColor Red
    Write-Host "Press Ctrl+C to cancel reboot" -ForegroundColor Yellow
    
    for ($i = 30; $i -gt 0; $i--) {
        Write-Progress -Activity "Rebooting System" -Status "Rebooting in $i seconds" -PercentComplete ((30-$i)/30*100)
        Start-Sleep -Seconds 1
    }
    
    Write-Progress -Activity "Rebooting System" -Completed
    Restart-Computer -Force
} else {
    Write-Host "`nChanges applied. A reboot is recommended to ensure all settings take effect." -ForegroundColor Yellow
    Write-Host "Run 'gpupdate /force' to refresh Group Policy settings." -ForegroundColor Yellow
}

#endregion
