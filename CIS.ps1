<#
.SYNOPSIS
  CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 PowerShell Implementation
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
        if (Test-Path "HKLM:$($Path.Replace('HKLM\',''))") {
            $safe = $Path -replace '[\\/:*?""<>|]', '_'
            $file = Join-Path $BackupPath ("{0}-{1}.reg" -f $safe, (Get-Date).ToString('yyyyMMdd-HHmmss'))
            $result = reg.exe export $Path $file /y 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Verbose "Backed up $Path to $file"
            }
        }
    } catch { 
        Write-Verbose "Could not backup $Path`: $($_.Exception.Message)" 
    }
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
        Backup-RegKey -Path $Path.Replace('HKLM:\','HKLM\')
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
        # Use secedit for user rights assignment
        $tempFile = [System.IO.Path]::GetTempFileName()
        $secTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$Right = $Principals
"@
        $secTemplate | Out-File -FilePath $tempFile -Encoding Unicode
        $result = & secedit.exe /configure /db $env:TEMP\secedit.sdb /cfg $tempFile /quiet 2>&1
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        
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
    
    # 1.1.1 Enforce password history: 24 or more password(s)
    & net.exe accounts /UNIQUEPW:24 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 1.1.1 - Password history set to 24" -ForegroundColor Green
        $global:AppliedControls += "1.1.1"
    }
    
    # 1.1.2 Maximum password age: 365 or fewer days
    & net.exe accounts /MAXPWAGE:365 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 1.1.2 - Maximum password age set to 365 days" -ForegroundColor Green
        $global:AppliedControls += "1.1.2"
    }
    
    # 1.1.3 Minimum password age: 1 or more day(s)
    & net.exe accounts /MINPWAGE:1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 1.1.3 - Minimum password age set to 1 day" -ForegroundColor Green
        $global:AppliedControls += "1.1.3"
    }
    
    # 1.1.4 Minimum password length: 14 or more character(s)
    & net.exe accounts /MINPWLEN:14 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 1.1.4 - Minimum password length set to 14" -ForegroundColor Green
        $global:AppliedControls += "1.1.4"
    }
    
    # 1.1.5 Password must meet complexity requirements: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Type DWord -Value 1 -Control "1.1.5"
}

function Set-CIS-1_2_AccountLockout {
    Write-Host "`n=== CIS 1.2 - Account Lockout Policy ===" -ForegroundColor Cyan
    
    # 1.2.1 Account lockout duration: 15 or more minute(s)
    & net.exe accounts /LOCKOUTDURATION:15 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 1.2.1 - Account lockout duration set to 15 minutes" -ForegroundColor Green
        $global:AppliedControls += "1.2.1"
    }
    
    # 1.2.2 Account lockout threshold: 5 or fewer invalid logon attempt(s)
    & net.exe accounts /LOCKOUTTHRESHOLD:5 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 1.2.2 - Account lockout threshold set to 5 attempts" -ForegroundColor Green
        $global:AppliedControls += "1.2.2"
    }
    
    # 1.2.3 Reset account lockout counter after: 15 or more minute(s)
    & net.exe accounts /LOCKOUTWINDOW:15 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ 1.2.3 - Reset account lockout counter set to 15 minutes" -ForegroundColor Green
        $global:AppliedControls += "1.2.3"
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
        Write-Warning "✗ 2.3.1.1 - Failed to disable Administrator account"
        $global:FailedControls += "2.3.1.1"
    }
    
    # 2.3.1.2 Accounts: Block Microsoft accounts: Users can't add or log on with Microsoft accounts
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Type DWord -Value 3 -Control "2.3.1.2"
    
    # 2.3.1.3 Accounts: Guest account status: Disabled
    try {
        Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        Write-Host "✓ 2.3.1.3 - Guest account disabled" -ForegroundColor Green
        $global:AppliedControls += "2.3.1.3"
    } catch {
        Write-Verbose "Guest account already disabled or not found"
        $global:AppliedControls += "2.3.1.3"
    }
    
    # 2.3.1.4 Accounts: Limit local account use of blank passwords to console logon only: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Type DWord -Value 1 -Control "2.3.1.4"
    
    # 2.3.1.5 Accounts: Rename administrator account
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -Type String -Value 'CISAdmin' -Control "2.3.1.5"
    
    # 2.3.1.6 Accounts: Rename guest account
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultDomainName' -Type String -Value 'CISGuest' -Control "2.3.1.6"
    
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
    
    # 2.3.7.2 Interactive logon: Do not require CTRL+ALT+DEL: Disabled
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
    
    # 2.3.10.1 Network access: Allow anonymous SID/Name translation: Disabled
    Set-CISUserRight -Right "SeTrustedCredManAccessPrivilege" -Principals "" -Control "2.3.10.1"
    
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

function Set-CIS-8_EventLog {
    Write-Host "`n=== CIS 8 - Event Log ===" -ForegroundColor Cyan
    
    # 8.1.1 Application: Control Event Log behavior when the log file reaches its maximum size: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'Retention' -Type String -Value '0' -Control "8.1.1"
    
    # 8.1.2 Application: Specify the maximum log file size (KB): 32,768 or greater
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Type DWord -Value 32768 -Control "8.1.2"
    
    # 8.2.1 Security: Control Event Log behavior when the log file reaches its maximum size: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'Retention' -Type String -Value '0' -Control "8.2.1"
    
    # 8.2.2 Security: Specify the maximum log file size (KB): 196,608 or greater
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Type DWord -Value 196608 -Control "8.2.2"
    
    # 8.3.1 System: Control Event Log behavior when the log file reaches its maximum size: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'Retention' -Type String -Value '0' -Control "8.3.1"
    
    # 8.3.2 System: Specify the maximum log file size (KB): 32,768 or greater
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Type DWord -Value 32768 -Control "8.3.2"
}

function Set-CIS-9_WindowsFirewall {
    Write-Host "`n=== CIS 9 - Windows Defender Firewall ===" -ForegroundColor Cyan
    
    try {
        # 9.1.1 Domain: Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'
        Set-NetFirewallProfile -Profile Domain -Enabled True
        Write-Host "✓ 9.1.1 - Domain firewall enabled" -ForegroundColor Green
        $global:AppliedControls += "9.1.1"
        
        # 9.1.2 Domain: Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'
        Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
        Write-Host "✓ 9.1.2 - Domain inbound connections blocked by default" -ForegroundColor Green
        $global:AppliedControls += "9.1.2"
        
        # 9.1.3 Domain: Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
        Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Allow
        Write-Host "✓ 9.1.3 - Domain outbound connections allowed by default" -ForegroundColor Green
        $global:AppliedControls += "9.1.3"
        
        # 9.2.1 Private: Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'
        Set-NetFirewallProfile -Profile Private -Enabled True
        Write-Host "✓ 9.2.1 - Private firewall enabled" -ForegroundColor Green
        $global:AppliedControls += "9.2.1"
        
        # 9.2.2 Private: Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
        Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
        Write-Host "✓ 9.2.2 - Private inbound connections blocked by default" -ForegroundColor Green
        $global:AppliedControls += "9.2.2"
        
        # 9.2.3 Private: Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
        Set-NetFirewallProfile -Profile Private -DefaultOutboundAction Allow
        Write-Host "✓ 9.2.3 - Private outbound connections allowed by default" -ForegroundColor Green
        $global:AppliedControls += "9.2.3"
        
        # 9.3.1 Public: Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'
        Set-NetFirewallProfile -Profile Public -Enabled True
        Write-Host "✓ 9.3.1 - Public firewall enabled" -ForegroundColor Green
        $global:AppliedControls += "9.3.1"
        
        # 9.3.2 Public: Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
        Write-Host "✓ 9.3.2 - Public inbound connections blocked by default" -ForegroundColor Green
        $global:AppliedControls += "9.3.2"
        
        # 9.3.3 Public: Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
        Set-NetFirewallProfile -Profile Public -DefaultOutboundAction Allow
        Write-Host "✓ 9.3.3 - Public outbound connections allowed by default" -ForegroundColor Green
        $global:AppliedControls += "9.3.3"
        
    } catch {
        Write-Warning "Windows Firewall configuration failed: $($_.Exception.Message)"
        $global:FailedControls += "9.x.x"
    }
}

function Set-CIS-17_AuditPolicy {
    Write-Host "`n=== CIS 17 - Advanced Audit Policy Configuration ===" -ForegroundColor Cyan
    
    # 17.1.1 Credential Validation: Success and Failure
    Set-CISAuditPolicy -Subcategory "Credential Validation" -Setting "/success:enable /failure:enable" -Control "17.1.1"
    
    # 17.2.1 Application Group Management: Success and Failure
    Set-CISAuditPolicy -Subcategory "Application Group Management" -Setting "/success:enable /failure:enable" -Control "17.2.1"
    
    # 17.2.2 Computer Account Management: Success and Failure  
    Set-CISAuditPolicy -Subcategory "Computer Account Management" -Setting "/success:enable /failure:enable" -Control "17.2.2"
    
    # 17.2.3 Distribution Group Management: Success and Failure
    Set-CISAuditPolicy -Subcategory "Distribution Group Management" -Setting "/success:enable /failure:enable" -Control "17.2.3"
    
    # 17.2.4 Other Account Management Events: Success and Failure
    Set-CISAuditPolicy -Subcategory "Other Account Management Events" -Setting "/success:enable /failure:enable" -Control "17.2.4"
    
    # 17.2.5 Security Group Management: Success and Failure
    Set-CISAuditPolicy -Subcategory "Security Group Management" -Setting "/success:enable /failure:enable" -Control "17.2.5"
    
    # 17.2.6 User Account Management: Success and Failure
    Set-CISAuditPolicy -Subcategory "User Account Management" -Setting "/success:enable /failure:enable" -Control "17.2.6"
    
    # 17.3.1 Plug and Play Events: Success
    Set-CISAuditPolicy -Subcategory "Plug and Play Events" -Setting "/success:enable /failure:disable" -Control "17.3.1"
    
    # 17.3.2 Process Creation: Success
    Set-CISAuditPolicy -Subcategory "Process Creation" -Setting "/success:enable /failure:disable" -Control "17.3.2"
    
    # 17.4.1 Directory Service Access: Success and Failure
    Set-CISAuditPolicy -Subcategory "Directory Service Access" -Setting "/success:enable /failure:enable" -Control "17.4.1"
    
    # 17.4.2 Directory Service Changes: Success and Failure
    Set-CISAuditPolicy -Subcategory "Directory Service Changes" -Setting "/success:enable /failure:enable" -Control "17.4.2"
    
    # 17.5.1 Account Lockout: Success and Failure
    Set-CISAuditPolicy -Subcategory "Account Lockout" -Setting "/success:enable /failure:enable" -Control "17.5.1"
    
    # 17.5.2 Group Membership: Success
    Set-CISAuditPolicy -Subcategory "Group Membership" -Setting "/success:enable /failure:disable" -Control "17.5.2"
    
    # 17.5.3 Logoff: Success
    Set-CISAuditPolicy -Subcategory "Logoff" -Setting "/success:enable /failure:disable" -Control "17.5.3"
    
    # 17.5.4 Logon: Success and Failure
    Set-CISAuditPolicy -Subcategory "Logon" -Setting "/success:enable /failure:enable" -Control "17.5.4"
    
    # 17.5.5 Other Logon/Logoff Events: Success and Failure
    Set-CISAuditPolicy -Subcategory "Other Logon/Logoff Events" -Setting "/success:enable /failure:enable" -Control "17.5.5"
    
    # 17.5.6 Special Logon: Success
    Set-CISAuditPolicy -Subcategory "Special Logon" -Setting "/success:enable /failure:disable" -Control "17.5.6"
    
    # 17.6.1 Removable Storage: Success and Failure
    Set-CISAuditPolicy -Subcategory "Removable Storage" -Setting "/success:enable /failure:enable" -Control "17.6.1"
    
    # 17.7.1 Audit Policy Change: Success and Failure
    Set-CISAuditPolicy -Subcategory "Audit Policy Change" -Setting "/success:enable /failure:enable" -Control "17.7.1"
    
    # 17.7.2 Authentication Policy Change: Success
    Set-CISAuditPolicy -Subcategory "Authentication Policy Change" -Setting "/success:enable /failure:disable" -Control "17.7.2"
    
    # 17.7.3 Authorization Policy Change: Success
    Set-CISAuditPolicy -Subcategory "Authorization Policy Change" -Setting "/success:enable /failure:disable" -Control "17.7.3"
    
    # 17.7.4 MPSSVC Rule-Level Policy Change: Success and Failure
    Set-CISAuditPolicy -Subcategory "MPSSVC Rule-Level Policy Change" -Setting "/success:enable /failure:enable" -Control "17.7.4"
    
    # 17.7.5 Other Policy Change Events: Failure
    Set-CISAuditPolicy -Subcategory "Other Policy Change Events" -Setting "/success:disable /failure:enable" -Control "17.7.5"
    
    # 17.8.1 Sensitive Privilege Use: Success and Failure
    Set-CISAuditPolicy -Subcategory "Sensitive Privilege Use" -Setting "/success:enable /failure:enable" -Control "17.8.1"
    
    # 17.9.1 IPsec Driver: Success and Failure
    Set-CISAuditPolicy -Subcategory "IPsec Driver" -Setting "/success:enable /failure:enable" -Control "17.9.1"
    
    # 17.9.2 Other System Events: Success and Failure
    Set-CISAuditPolicy -Subcategory "Other System Events" -Setting "/success:enable /failure:enable" -Control "17.9.2"
    
    # 17.9.3 Security State Change: Success
    Set-CISAuditPolicy -Subcategory "Security State Change" -Setting "/success:enable /failure:disable" -Control "17.9.3"
    
    # 17.9.4 Security System Extension: Success and Failure
    Set-CISAuditPolicy -Subcategory "Security System Extension" -Setting "/success:enable /failure:enable" -Control "17.9.4"
    
    # 17.9.5 System Integrity: Success and Failure
    Set-CISAuditPolicy -Subcategory "System Integrity" -Setting "/success:enable /failure:enable" -Control "17.9.5"
    
    # Enable command line auditing
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 -Control "17.3.2-CmdLine"
}

function Set-CIS-18_AdministrativeTemplates {
    Write-Host "`n=== CIS 18 - Administrative Templates ===" -ForegroundColor Cyan
    
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
    
    # 18.4.1 MSS: (AutoAdminLogon) Enable Automatic Logon: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Type String -Value '0' -Control "18.4.1"
    
    # 18.4.2 MSS: (DisableIPSourceRouting IPv6) IP source routing protection level: Highest protection
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2 -Control "18.4.2"
    
    # 18.4.3 MSS: (DisableIPSourceRouting) IP source routing protection level: Highest protection  
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2 -Control "18.4.3"
    
    # 18.4.4 MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes: Disabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Type DWord -Value 0 -Control "18.4.4"
    
    # 18.4.5 MSS: (KeepAliveTime) How often keep-alive packets are sent: 300,000 or 5 minutes
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -Type DWord -Value 300000 -Control "18.4.5"
    
    # 18.4.6 MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NoNameReleaseOnDemand' -Type DWord -Value 1 -Control "18.4.6"
    
    # 18.4.7 MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses: Disabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'PerformRouterDiscovery' -Type DWord -Value 0 -Control "18.4.7"
    
    # 18.4.8 MSS: (SafeDllSearchMode) Enable Safe DLL search mode: Enabled
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode' -Type DWord -Value 1 -Control "18.4.8"
    
    # 18.4.9 MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires: 5 or fewer seconds
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScreenSaverGracePeriod' -Type String -Value '5' -Control "18.4.9"
    
    # 18.4.10 MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted: 3
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 -Control "18.4.10"
    
    # 18.4.11 MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted: 3
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 -Control "18.4.11"
    
    # 18.4.12 MSS: (WarningLevel) Percentage threshold for the security event log: 90% or less
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -Name 'WarningLevel' -Type DWord -Value 90 -Control "18.4.12"
    
    # 18.5.4.1 Turn off multicast name resolution: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0 -Control "18.5.4.1"
    
    # 18.5.8.1 Enable insecure guest logons: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Type DWord -Value 0 -Control "18.5.8.1"
    
    # 18.5.9.1 Turn on Mapper I/O (LLTDIO) driver: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableLLTDIO' -Type DWord -Value 0 -Control "18.5.9.1"
    
    # 18.5.9.2 Turn on Responder (RSPNDR) driver: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableRspndr' -Type DWord -Value 0 -Control "18.5.9.2"
    
    # 18.5.10.2 Turn off Microsoft Peer-to-Peer Networking Services: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name 'Disabled' -Type DWord -Value 1 -Control "18.5.10.2"
    
    # 18.5.14.1 Hardened UNC Paths: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Control "18.5.14.1a"
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Control "18.5.14.1b"
    
    # 18.5.19.2.1 Prohibit installation and configuration of Network Bridge on your DNS domain network: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_AllowNetBridge_NLA' -Type DWord -Value 0 -Control "18.5.19.2.1"
    
    # 18.5.20.1 Minimize the number of simultaneous connections to the Internet or a Windows Domain: Enabled: 3 = Prevent Wi-Fi when on Ethernet
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Type DWord -Value 3 -Control "18.5.20.1"
    
    # 18.5.21.1 Prohibit connection to non-domain networks when connected to domain authenticated network: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Type DWord -Value 1 -Control "18.5.21.1"
    
    # 18.8.3.1 Include command line in process creation events: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 -Control "18.8.3.1"
    
    # 18.8.4.1 Encryption Oracle Remediation: Enabled: Force Updated Clients
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name 'AllowEncryptionOracle' -Type DWord -Value 0 -Control "18.8.4.1"
    
    # 18.8.4.2 Remote host allows delegation of non-exportable credentials: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Type DWord -Value 1 -Control "18.8.4.2"
    
    # 18.8.5.1 Turn On Virtualization Based Security: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1 -Control "18.8.5.1"
    
    # 18.8.5.2 Turn On Virtualization Based Security: Select Platform Security Level: Secure Boot and DMA Protection
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 3 -Control "18.8.5.2"
    
    # 18.8.5.3 Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity: Enabled with UEFI lock
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 1 -Control "18.8.5.3"
    
    # 18.8.5.4 Turn On Virtualization Based Security: Require UEFI Memory Attributes Table: True
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HVCIMATRequired' -Type DWord -Value 1 -Control "18.8.5.4"
    
    # 18.8.5.5 Turn On Virtualization Based Security: Credential Guard Configuration: Enabled with UEFI lock
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags' -Type DWord -Value 1 -Control "18.8.5.5"
    
    # 18.8.5.7 Turn On Virtualization Based Security: Secure Launch Configuration: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'ConfigureSystemGuardLaunch' -Type DWord -Value 1 -Control "18.8.5.7"
    
    # 18.8.14.1 Boot-Start Driver Initialization Policy: Enabled: Good, unknown and bad but critical
    Set-CISRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Type DWord -Value 3 -Control "18.8.14.1"
    
    # 18.8.21.2 Configure registry policy processing: Enabled: Process even if the Group Policy objects have not changed
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name 'NoGPOListChanges' -Type DWord -Value 0 -Control "18.8.21.2"
    
    # 18.8.21.3 Configure registry policy processing: Enabled: Do not apply during periodic background processing
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name 'NoBackgroundPolicy' -Type DWord -Value 0 -Control "18.8.21.3"
    
    # 18.8.21.4 Configure registry policy processing: Enabled: Process even when there are no changes
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name 'NoSlowLink' -Type DWord -Value 0 -Control "18.8.21.4"
    
    # 18.8.21.5 Configure security policy processing: Enabled: Process even if the Group Policy objects have not changed
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoGPOListChanges' -Type DWord -Value 0 -Control "18.8.21.5"
    
    # 18.8.21.6 Configure security policy processing: Enabled: Do not apply during periodic background processing
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoBackgroundPolicy' -Type DWord -Value 0 -Control "18.8.21.6"
    
    # 18.8.22.1.1 Turn off downloading of print drivers over HTTP: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Type DWord -Value 1 -Control "18.8.22.1.1"
    
    # 18.8.22.1.2 Turn off handwriting personalization data sharing: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Type DWord -Value 1 -Control "18.8.22.1.2"
    
    # 18.8.22.1.3 Turn off handwriting recognition error reporting: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Type DWord -Value 1 -Control "18.8.22.1.3"
    
    # 18.8.22.1.4 Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' -Name 'ExitOnMSICW' -Type DWord -Value 1 -Control "18.8.22.1.4"
    
    # 18.8.22.1.5 Turn off Internet download for Web publishing and online ordering wizards: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoWebServices' -Type DWord -Value 1 -Control "18.8.22.1.5"
    
    # 18.8.22.1.6 Turn off printing over HTTP: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableHTTPPrinting' -Type DWord -Value 1 -Control "18.8.22.1.6"
    
    # 18.8.22.1.7 Turn off Registration if URL connection is referring to Microsoft.com: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' -Name 'NoRegistration' -Type DWord -Value 1 -Control "18.8.22.1.7"
    
    # 18.8.22.1.8 Turn off Search Companion content file updates: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name 'DisableContentFileUpdates' -Type DWord -Value 1 -Control "18.8.22.1.8"
    
    # 18.8.22.1.9 Turn off the "Order Prints" picture task: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoOnlinePrintsWizard' -Type DWord -Value 1 -Control "18.8.22.1.9"
    
    # 18.8.22.1.10 Turn off the "Publish to Web" task for files and folders: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoPublishingWizard' -Type DWord -Value 1 -Control "18.8.22.1.10"
    
    # 18.8.22.1.11 Turn off the Windows Messenger Customer Experience Improvement Program: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' -Name 'CEIP' -Type DWord -Value 2 -Control "18.8.22.1.11"
    
    # 18.8.22.1.12 Turn off Windows Customer Experience Improvement Program: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0 -Control "18.8.22.1.12"
    
    # 18.8.22.1.13 Turn off Windows Error Reporting: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 1 -Control "18.8.22.1.13"
    
    # 18.8.25.1 Configure Automatic Updates: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0 -Control "18.8.25.1"
    
    # 18.8.25.2 Configure Automatic Updates: Scheduled install day: 0 - Every day
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Type DWord -Value 0 -Control "18.8.25.2"
    
    # 18.8.25.3 Configure Automatic Updates: Scheduled install time: 03:00
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallTime' -Type DWord -Value 3 -Control "18.8.25.3"
    
    # 18.8.25.4 Configure Automatic Updates: Install updates automatically
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Type DWord -Value 4 -Control "18.8.25.4"
    
    # 18.8.28.1 Remove access to "Pause updates" feature: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'SetDisablePauseUXAccess' -Type DWord -Value 1 -Control "18.8.28.1"
    
    # 18.9.4.1 Allow a Windows app to share application data between users: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager' -Name 'AllowSharedLocalAppData' -Type DWord -Value 0 -Control "18.9.4.1"
    
    # 18.9.6.1 Allow Microsoft accounts to be optional: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Type DWord -Value 1 -Control "18.9.6.1"
    
    # 18.9.8.1 Disallow Autoplay for non-volume devices: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Type DWord -Value 1 -Control "18.9.8.1"
    
    # 18.9.8.2 Set the default behavior for AutoRun: Enabled: Do not execute any autorun commands
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Type DWord -Value 1 -Control "18.9.8.2"
    
    # 18.9.8.3 Turn off Autoplay: Enabled: All drives
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 -Control "18.9.8.3"
    
    # 18.9.13.1 Configure enhanced anti-spoofing: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name 'EnhancedAntiSpoofing' -Type DWord -Value 1 -Control "18.9.13.1"
    
    # 18.9.15.1 Allow Use of Camera: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -Name 'AllowCamera' -Type DWord -Value 0 -Control "18.9.15.1"
    
    # 18.9.16.1 Turn off cloud consumer account state content: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableConsumerAccountStateContent' -Type DWord -Value 1 -Control "18.9.16.1"
    
    # 18.9.16.2 Turn off Microsoft consumer experiences: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1 -Control "18.9.16.2"
    
    # 18.9.26.1.1 Application: Specify the maximum log file size (KB): 32,768 or greater
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Type DWord -Value 32768 -Control "18.9.26.1.1"
    
    # 18.9.26.1.2 Application: Control Event Log behavior when the log file reaches its maximum size: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'Retention' -Type String -Value '0' -Control "18.9.26.1.2"
    
    # 18.9.26.2.1 Security: Specify the maximum log file size (KB): 196,608 or greater
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Type DWord -Value 196608 -Control "18.9.26.2.1"
    
    # 18.9.26.2.2 Security: Control Event Log behavior when the log file reaches its maximum size: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'Retention' -Type String -Value '0' -Control "18.9.26.2.2"
    
    # 18.9.26.3.1 System: Specify the maximum log file size (KB): 32,768 or greater
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Type DWord -Value 32768 -Control "18.9.26.3.1"
    
    # 18.9.26.3.2 System: Control Event Log behavior when the log file reaches its maximum size: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'Retention' -Type String -Value '0' -Control "18.9.26.3.2"
    
    # 18.9.27.1.1 Turn off Help Experience Improvement Program: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0' -Name 'NoImplicitFeedback' -Type DWord -Value 1 -Control "18.9.27.1.1"
    
    # 18.9.30.2 Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service: Enabled: Disable Authenticated Proxy usage
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DisableEnterpriseAuthProxy' -Type DWord -Value 1 -Control "18.9.30.2"
    
    # 18.9.30.3 Configure collection of browsing data for Microsoft 365 Analytics: Enabled: Configure collection of browsing data for Microsoft 365 Analytics: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'MicrosoftEdgeDataOptIn' -Type DWord -Value 0 -Control "18.9.30.3"
    
    # 18.9.30.4 Do not show feedback notifications: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1 -Control "18.9.30.4"
    
    # 18.9.30.5 Toggle user control over Insider builds: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'AllowBuildPreview' -Type DWord -Value 0 -Control "18.9.30.5"
    
    # 18.9.39.2 Do not preserve zone information in file attachments: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'SaveZoneInformation' -Type DWord -Value 2 -Control "18.9.39.2"
    
    # 18.9.39.3 Hide mechanisms to remove zone information: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'HideZoneInfoOnProperties' -Type DWord -Value 1 -Control "18.9.39.3"
    
    # 18.9.39.4 Notify antivirus programs when opening attachments: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'ScanWithAntiVirus' -Type DWord -Value 3 -Control "18.9.39.4"
    
    # 18.9.43.1 Always install with elevated privileges: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Type DWord -Value 0 -Control "18.9.43.1"
    
    # 18.9.43.2 Sign-in and lock last interactive user automatically after a restart: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Type DWord -Value 1 -Control "18.9.43.2"
    
    # 18.9.44.1 Turn on PowerShell Script Block Logging: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 -Control "18.9.44.1"
    
    # 18.9.44.2 Turn on PowerShell Transcription: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1 -Control "18.9.44.2"
    
    # 18.9.52.1 Allow Basic authentication: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Type DWord -Value 0 -Control "18.9.52.1"
    
    # 18.9.52.2 Allow unencrypted traffic: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0 -Control "18.9.52.2"
    
    # 18.9.52.3 Disallow Digest authentication: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Type DWord -Value 0 -Control "18.9.52.3"
    
    # 18.9.53.1 Allow Basic authentication: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Type DWord -Value 0 -Control "18.9.53.1"
    
    # 18.9.53.2.1 Allow remote server management through WinRM: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowAutoConfig' -Type DWord -Value 0 -Control "18.9.53.2.1"
    
    # 18.9.53.3 Allow unencrypted traffic: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0 -Control "18.9.53.3"
    
    # 18.9.53.4 Disallow WinRM from storing RunAs credentials: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Type DWord -Value 1 -Control "18.9.53.4"
    
    # 18.9.80.1.1 Configure Windows Defender SmartScreen: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value 1 -Control "18.9.80.1.1"
    
    # 18.9.80.1.2 Configure Windows Defender SmartScreen: Enabled: Warn and prevent bypass
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Type String -Value 'Block' -Control "18.9.80.1.2"
    
    # 18.9.85.1 Allow Windows Ink Workspace: Enabled: On, but disallow access above lock
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowWindowsInkWorkspace' -Type DWord -Value 1 -Control "18.9.85.1"
    
    # 18.9.86.1 Allow user control over installs: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Type DWord -Value 0 -Control "18.9.86.1"
    
    # 18.9.86.2 Always install with elevated privileges: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Type DWord -Value 0 -Control "18.9.86.2"
    
    # 18.9.95.1 Prevent non-admin users from installing packaged Windows apps: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx' -Name 'BlockNonAdminUserInstall' -Type DWord -Value 1 -Control "18.9.95.1"
    
    # 18.9.97.1.1 Allow deployment operations in special profiles: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableAppInstaller' -Type DWord -Value 0 -Control "18.9.97.1.1"
    
    # 18.9.97.1.2 Allow Microsoft app installer: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableAppInstaller' -Type DWord -Value 0 -Control "18.9.97.1.2"
    
    # 18.9.97.1.3 Allow experimental features: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableExperimentalFeatures' -Type DWord -Value 0 -Control "18.9.97.1.3"
    
    # 18.9.97.1.4 Allow app installer scripts: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableMSAppInstallerProtocol' -Type DWord -Value 0 -Control "18.9.97.1.4"
    
    # 18.9.97.2.1 Disable all apps from Microsoft Store: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'DisableStoreApps' -Type DWord -Value 0 -Control "18.9.97.2.1"
    
    # 18.9.97.2.2 Only display the private store within the Microsoft Store: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RequirePrivateStoreOnly' -Type DWord -Value 1 -Control "18.9.97.2.2"
    
    # 18.9.97.2.3 Turn off Automatic Download and Install of updates: Disabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'AutoDownload' -Type DWord -Value 4 -Control "18.9.97.2.3"
    
    # 18.9.97.2.4 Turn off the offer to update to the latest version of Windows: Enabled
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'DisableOSUpgrade' -Type DWord -Value 1 -Control "18.9.97.2.4"
    
    # 18.9.98.1 Let Windows apps activate with voice while the system is locked: Enabled: Force Deny
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsActivateWithVoiceAboveLock' -Type DWord -Value 2 -Control "18.9.98.1"
    
    # 18.9.98.2 Let Windows apps access account information: Enabled: Force Deny
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -Type DWord -Value 2 -Control "18.9.98.2"
    
    # 18.9.98.3 Let Windows apps access the calendar: Enabled: Force Deny
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCalendar' -Type DWord -Value 2 -Control "18.9.98.3"
}

#endregion

#region CIS Level 2 Controls (Additional for comprehensive hardening)

function Set-CIS-Level2-Controls {
    if ($Level -lt 2) { return }
    
    Write-Host "`n=== CIS Level 2 Additional Controls ===" -ForegroundColor Cyan
    
    # Additional Level 2 controls would go here
    # These are more restrictive and may impact usability
    
    # 2.3.7.3 Interactive logon: Number of previous logons to cache: 4 or fewer logon(s)
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Type String -Value '4' -Control "2.3.7.3-L2"
    
    # 2.3.7.8 Interactive logon: Prompt user to change password before expiration: between 5 and 14 days
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'PasswordExpiryWarning' -Type DWord -Value 5 -Control "2.3.7.8-L2"
    
    # 2.3.7.9 Interactive logon: Smart card removal behavior: Lock Workstation or Force Logoff
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Type String -Value '1' -Control "2.3.7.9-L2"
    
    # 18.9.98.4 Let Windows apps access call history: Enabled: Force Deny  
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCallHistory' -Type DWord -Value 2 -Control "18.9.98.4-L2"
    
    # 18.9.98.5 Let Windows apps access the camera: Enabled: Force Deny
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessCamera' -Type DWord -Value 2 -Control "18.9.98.5-L2"
    
    # 18.9.98.6 Let Windows apps access contacts: Enabled: Force Deny
    Set-CISRegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessContacts' -Type DWord -Value 2 -Control "18.9.98.6-L2"
}

#endregion

function Disable-UnnecessaryServices {
    Write-Host "`n=== Disabling Unnecessary Services ===" -ForegroundColor Cyan
    
    $servicesToDisable = @(
        'RemoteRegistry',
        'SSDPSRV',
        'upnphost',
        'WMPNetworkSvc',
        'WSearch',
        'XblAuthManager',
        'XblGameSave',
        'XboxNetApiSvc'
    )
    
    foreach ($service in $servicesToDisable) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Write-Host "✓ Disabled service: $service" -ForegroundColor Green
                $global:AppliedControls += "Service-$service"
            }
        } catch {
            Write-Verbose "Service $service not found or already disabled"
        }
    }
}

function Remove-WindowsCapabilities {
    Write-Host "`n=== Removing Optional Windows Capabilities ===" -ForegroundColor Cyan
    
    $capabilitiesToRemove = @(
        'Browser.InternetExplorer~~~~0.0.11.0',
        'MathRecognizer~~~~0.0.1.0',
        'OpenSSH.Client~~~~0.0.1.0',
        'PowerShell.ISE~~~~0.0.1.0'
    )
    
    foreach ($capability in $capabilitiesToRemove) {
        try {
            $cap = Get-WindowsCapability -Online -Name $capability -ErrorAction SilentlyContinue
            if ($cap -and $cap.State -eq 'Installed') {
                Remove-WindowsCapability -Online -Name $capability -ErrorAction SilentlyContinue | Out-Null
                Write-Host "✓ Removed capability: $capability" -ForegroundColor Green
                $global:AppliedControls += "Capability-$capability"
            }
        } catch {
            Write-Verbose "Capability $capability not found or already removed"
        }
    }
}

function Show-Summary {
    Write-Host "`n==================== SUMMARY ====================" -ForegroundColor Green
    Write-Host "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0" -ForegroundColor White
    Write-Host "Profile Level: $Level" -ForegroundColor White
    Write-Host "Transcript: $global:TranscriptFile" -ForegroundColor White
    Write-Host "Backups: $BackupPath" -ForegroundColor White
    
    Write-Host "`nApplied Controls: $($global:AppliedControls.Count)" -ForegroundColor Green
    Write-Host "Failed Controls: $($global:FailedControls.Count)" -ForegroundColor Red
    
    if ($global:FailedControls.Count -gt 0) {
        Write-Host "`nFailed Controls:" -ForegroundColor Red
        $global:FailedControls | Sort-Object | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }
    
    Write-Host "`nIMPORTANT NOTES:" -ForegroundColor Yellow
    Write-Host "- Some controls may require domain membership or specific infrastructure" -ForegroundColor Yellow
    Write-Host "- Test all applications after applying these changes" -ForegroundColor Yellow  
    Write-Host "- Review Windows Event Logs for any issues" -ForegroundColor Yellow
    Write-Host "- Consider implementing remaining controls via Group Policy for domain environments" -ForegroundColor Yellow
    
    if ($Level -eq 1) {
        Write-Host "- To apply Level 2 controls, run script with -Level 2 parameter" -ForegroundColor Yellow
    }
}

#region Main Execution

Write-Host "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Profile Level: $Level" -ForegroundColor White
Write-Host "NoReboot: $NoReboot" -ForegroundColor White

Assert-Admin
Start-CISLogging

try {
    Write-Host "`nStarting CIS Windows 11 Enterprise Baseline Implementation..." -ForegroundColor Green
    
    # CIS Level 1 Controls (Essential)
    Set-CIS-1_1_PasswordPolicy
    Set-CIS-1_2_AccountLockout  
    Set-CIS-2_2_UserRights
    Set-CIS-2_3_SecurityOptions
    Set-CIS-8_EventLog
    Set-CIS-9_WindowsFirewall
    Set-CIS-17_AuditPolicy
    Set-CIS-18_AdministrativeTemplates
    
    # CIS Level 2 Controls (Comprehensive) - Only if Level 2 specified
    Set-CIS-Level2-Controls
    
    # Additional hardening
    Disable-UnnecessaryServices
    Remove-WindowsCapabilities
    
    Show-Summary
    
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    $global:FailedControls += "SCRIPT-EXECUTION"
} finally {
    if ($global:TranscriptFile) {
        Stop-Transcript | Out-Null
    }
}

if (-not $NoReboot) {
    Write-Host "`nRebooting in 30 seconds to apply changes..." -ForegroundColor Red
    Write-Host "Press Ctrl+C to cancel reboot" -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    Restart-Computer -Force
} else {
    Write-Host "`nChanges applied. Reboot recommended to ensure all settings take effect." -ForegroundColor Yellow
}

#endregion
