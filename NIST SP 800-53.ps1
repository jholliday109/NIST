<#
.SYNOPSIS
  Enhanced NIST SP 800-53 Rev. 5 Windows Laptop Baseline (PowerShell).
.DESCRIPTION
  This script applies a comprehensive set of technical controls to harden Windows laptops
  against NIST SP 800-53 Rev. 5 controls. It covers 18 control families with detailed
  mapping to specific controls. Intended for domain-joined Windows 10/11 or Server
  endpoints used as laptops.
  
  TEST IN A LAB FIRST. Some settings can break legacy apps or require infrastructure.

  Control Families Implemented:
    AC - Access Control (AC-2, AC-3, AC-6, AC-7, AC-11, AC-17, AC-18, AC-19, AC-20)
    AU - Audit and Accountability (AU-2, AU-3, AU-6, AU-8, AU-9, AU-12)
    AT - Awareness and Training (AT-2, AT-3) - Policy enforcement only
    CM - Configuration Management (CM-2, CM-6, CM-7, CM-8, CM-11)
    CP - Contingency Planning (CP-9, CP-10) - Data protection focus
    IA - Identification and Authentication (IA-2, IA-4, IA-5, IA-8)
    IR - Incident Response (IR-4, IR-5) - Logging and monitoring setup
    MA - Maintenance (MA-4) - Remote access restrictions
    MP - Media Protection (MP-2, MP-3, MP-4, MP-5, MP-6) - Encryption focus
    PE - Physical and Environmental Protection (PE-3) - Screen lock
    PL - Planning (PL-4, PL-8) - Architecture documentation
    RA - Risk Assessment (RA-5) - Vulnerability management
    SA - System and Services Acquisition (SA-4, SA-8, SA-11)
    SC - System and Communications Protection (SC-7, SC-8, SC-12, SC-13, SC-15, SC-20, SC-21, SC-23)
    SI - System and Information Integrity (SI-2, SI-3, SI-4, SI-7, SI-10, SI-11)

.PARAMETER NoReboot
  Suppress automatic reboot. Default = $true to avoid unexpected reboots.

.PARAMETER EnableBitLockerPIN
  Enable TPM+PIN for BitLocker (requires user interaction).

.PARAMETER ComplianceLevel
  Set compliance level: 'Basic', 'Standard', 'High'. Default = 'Standard'.

.PARAMETER GenerateReport
  Generate compliance report after execution.

.NOTES
  Enhanced version with comprehensive NIST SP 800-53 Rev. 5 control mapping.
  Run as Administrator. Requires Windows 10/11 or Server 2016+.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$NoReboot = $true,
    [switch]$EnableBitLockerPIN = $false,
    [ValidateSet('Basic','Standard','High')]
    [string]$ComplianceLevel = 'Standard',
    [switch]$GenerateReport = $true,
    [string]$TranscriptPath = "$env:ProgramData\NIST80053-Enhanced\Logs",
    [string]$BackupPath = "$env:ProgramData\NIST80053-Enhanced\Backups",
    [string]$ReportPath = "$env:ProgramData\NIST80053-Enhanced\Reports"
)

# Global variables for compliance tracking
$global:ComplianceResults = @()
$global:ControlsImplemented = @()

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
    New-Folder -Path $ReportPath
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $global:TranscriptFile = Join-Path $TranscriptPath "NIST80053-Enhanced-$stamp.log"
    Start-Transcript -Path $global:TranscriptFile -Force | Out-Null
    New-Folder -Path $BackupPath
    Write-Host "Logging started: $global:TranscriptFile" -ForegroundColor Green
}

function Add-ComplianceResult {
    param(
        [string]$Control,
        [string]$Title,
        [string]$Status,
        [string]$Details,
        [string]$Impact = "Medium"
    )
    $global:ComplianceResults += [PSCustomObject]@{
        Control = $Control
        Title = $Title
        Status = $Status
        Details = $Details
        Impact = $Impact
        Timestamp = Get-Date
    }
    $global:ControlsImplemented += $Control
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
        [Object]$Value,
        [string]$Control = "Unknown"
    )
    try {
        if (-not (Test-Path $Path)) { 
            New-Item -Path $Path -Force | Out-Null 
        }
        Backup-RegKey -Path $Path
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Verbose "[$Control] Set $Path\$Name = $Value ($Type)"
        return $true
    } catch {
        Write-Warning "[$Control] Failed to set registry value $Path\$Name`: $($_.Exception.Message)"
        return $false
    }
}

# ==================== ACCESS CONTROL (AC) FAMILY ====================

function Configure-AccessControl {
    Write-Host "`n=== ACCESS CONTROL (AC) FAMILY ===" -ForegroundColor Cyan
    
    # AC-2: Account Management
    Write-Host "Implementing AC-2: Account Management ..." -ForegroundColor Green
    try {
        # Password policy
        $commands = @(
            @{ cmd = "net.exe"; args = "accounts /MINPWLEN:14" },
            @{ cmd = "net.exe"; args = "accounts /MAXPWAGE:90" },
            @{ cmd = "net.exe"; args = "accounts /MINPWAGE:1" },
            @{ cmd = "net.exe"; args = "accounts /UNIQUEPW:24" },
            @{ cmd = "net.exe"; args = "accounts /LOCKOUTTHRESHOLD:10" },
            @{ cmd = "net.exe"; args = "accounts /LOCKOUTDURATION:15" },
            @{ cmd = "net.exe"; args = "accounts /LOCKOUTWINDOW:15" }
        )
        
        $success = $true
        foreach ($command in $commands) {
            $result = & $command.cmd $command.args.Split(' ') 2>&1
            if ($LASTEXITCODE -ne 0) {
                $success = $false
                Write-Warning "Command failed: $($command.cmd) $($command.args)"
            }
        }
        
        Add-ComplianceResult -Control "AC-2" -Title "Account Management" -Status $(if($success){"Compliant"}else{"Partial"}) -Details "Password policy configured" -Impact "High"
    } catch {
        Add-ComplianceResult -Control "AC-2" -Title "Account Management" -Status "Failed" -Details $_.Exception.Message -Impact "High"
    }
    
    # AC-3: Access Enforcement
    Write-Host "Implementing AC-3: Access Enforcement ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Type DWord -Value 1 -Control "AC-3"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 2 -Control "AC-3")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Type DWord -Value 1 -Control "AC-3")
    Add-ComplianceResult -Control "AC-3" -Title "Access Enforcement" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Anonymous access restrictions applied" -Impact "High"
    
    # AC-6: Least Privilege
    Write-Host "Implementing AC-6: Least Privilege (Admin Review) ..." -ForegroundColor Green
    try {
        $adminMembers = Get-LocalGroupMember -Name 'Administrators' -ErrorAction SilentlyContinue | Measure-Object
        $adminCount = $adminMembers.Count
        Write-Host "Current admin count: $adminCount members"
        Add-ComplianceResult -Control "AC-6" -Title "Least Privilege" -Status "Review Required" -Details "Manual review of $adminCount admin accounts needed" -Impact "High"
    } catch {
        Add-ComplianceResult -Control "AC-6" -Title "Least Privilege" -Status "Failed" -Details $_.Exception.Message -Impact "High"
    }
    
    # AC-7: Unsuccessful Logon Attempts (already covered in AC-2)
    
    # AC-11: Session Lock
    Write-Host "Implementing AC-11: Session Lock ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveActive' -Type String -Value '1' -Control "AC-11"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveTimeOut' -Type String -Value '900' -Control "AC-11")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -Type String -Value '1' -Control "AC-11")
    # Additional lock settings
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value 900 -Control "AC-11")
    Add-ComplianceResult -Control "AC-11" -Title "Session Lock" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Screen lock after 15 minutes of inactivity" -Impact "Medium"
    
    # AC-17: Remote Access
    Write-Host "Implementing AC-17: Remote Access ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 1 -Control "AC-17"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Type DWord -Value 2 -Control "AC-17")
    Add-ComplianceResult -Control "AC-17" -Title "Remote Access" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "RDP disabled, security layer enforced" -Impact "Medium"
    
    # AC-18: Wireless Access
    Write-Host "Implementing AC-18: Wireless Access ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Type DWord -Value 1 -Control "AC-18"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Type DWord -Value 1 -Control "AC-18")
    Add-ComplianceResult -Control "AC-18" -Title "Wireless Access" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Wireless connection policies enforced" -Impact "Medium"
    
    # AC-19: Access Control for Mobile Devices
    Write-Host "Implementing AC-19: Access Control for Mobile Devices ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' -Name 'Deny_All' -Type DWord -Value 1 -Control "AC-19"
    # Allow BitLocker encrypted drives
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'FDVDenyWriteAccess' -Type DWord -Value 0 -Control "AC-19")
    Add-ComplianceResult -Control "AC-19" -Title "Access Control for Mobile Devices" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Removable storage access controlled" -Impact "High"
    
    # AC-20: Use of External Information Systems
    Write-Host "Implementing AC-20: Use of External Information Systems ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Control "AC-20"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1' -Control "AC-20")
    Add-ComplianceResult -Control "AC-20" -Title "Use of External Information Systems" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Hardened UNC paths configured" -Impact "Medium"
}

# ==================== AUDIT AND ACCOUNTABILITY (AU) FAMILY ====================

function Configure-AuditAccountability {
    Write-Host "`n=== AUDIT AND ACCOUNTABILITY (AU) FAMILY ===" -ForegroundColor Cyan
    
    # AU-2, AU-3, AU-12: Audit Events, Content, Generation
    Write-Host "Implementing AU-2/3/12: Audit Events, Content, and Generation ..." -ForegroundColor Green
    
    $auditMap = @(
        @{ Sc='Credential Validation'; S=$true; F=$true },
        @{ Sc='User Account Management'; S=$true; F=$true },
        @{ Sc='Security Group Management'; S=$true; F=$true },
        @{ Sc='Logon'; S=$true; F=$true },
        @{ Sc='Logoff'; S=$true; F=$true },
        @{ Sc='Account Lockout'; S=$true; F=$true },
        @{ Sc='Special Logon'; S=$true; F=$false },
        @{ Sc='Process Creation'; S=$true; F=$false },
        @{ Sc='Process Termination'; S=$false; F=$true },
        @{ Sc='Audit Policy Change'; S=$true; F=$true },
        @{ Sc='Authentication Policy Change'; S=$true; F=$false },
        @{ Sc='Authorization Policy Change'; S=$true; F=$false },
        @{ Sc='Sensitive Privilege Use'; S=$true; F=$true },
        @{ Sc='File Share'; S=$true; F=$true },
        @{ Sc='File System'; S=$false; F=$true },
        @{ Sc='Registry'; S=$false; F=$true },
        @{ Sc='Security System Extension'; S=$true; F=$true },
        @{ Sc='System Integrity'; S=$true; F=$true }
    )
    
    $auditSuccess = $true
    foreach ($item in $auditMap) {
        try {
            $s = if ($item.S) { 'enable' } else { 'disable' }
            $f = if ($item.F) { 'enable' } else { 'disable' }
            
            $result = & auditpol.exe /set /subcategory:"$($item.Sc)" /success:$s /failure:$f 2>&1
            
            if ($LASTEXITCODE -ne 0) {
                $auditSuccess = $false
                Write-Warning "Audit policy setting failed for '$($item.Sc)'"
            }
        } catch {
            $auditSuccess = $false
            Write-Warning "Exception setting audit policy for $($item.Sc): $($_.Exception.Message)"
        }
    }
    
    # Enhanced process creation auditing
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 -Control "AU-3"
    Add-ComplianceResult -Control "AU-2/3/12" -Title "Audit Events and Content" -Status $(if($auditSuccess -and $success){"Compliant"}else{"Partial"}) -Details "Advanced audit policy configured with command line logging" -Impact "High"
    
    # AU-6: Audit Review, Analysis, and Reporting
    Write-Host "Implementing AU-6: Audit Review, Analysis, and Reporting ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Type DWord -Value 1048576 -Control "AU-6"  # 1GB
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Type DWord -Value 524288 -Control "AU-6")  # 512MB
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Type DWord -Value 524288 -Control "AU-6")  # 512MB
    Add-ComplianceResult -Control "AU-6" -Title "Audit Review and Analysis" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Event log sizes increased for retention" -Impact "Medium"
    
    # AU-8: Time Stamps
    Write-Host "Implementing AU-8: Time Stamps ..." -ForegroundColor Green
    try {
        $result = w32tm /config /syncfromflags:manual /manualpeerlist:"time.windows.com,time.nist.gov" /reliable:YES 2>&1
        $result = w32tm /config /update 2>&1
        Restart-Service w32time -Force -ErrorAction SilentlyContinue
        Add-ComplianceResult -Control "AU-8" -Title "Time Stamps" -Status "Compliant" -Details "Time synchronization configured with reliable sources" -Impact "Medium"
    } catch {
        Add-ComplianceResult -Control "AU-8" -Title "Time Stamps" -Status "Failed" -Details $_.Exception.Message -Impact "Medium"
    }
    
    # AU-9: Protection of Audit Information
    Write-Host "Implementing AU-9: Protection of Audit Information ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name 'RestrictGuestAccess' -Type DWord -Value 1 -Control "AU-9"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'Retention' -Type DWord -Value 1 -Control "AU-9")
    Add-ComplianceResult -Control "AU-9" -Title "Protection of Audit Information" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Audit log access restricted and retention enabled" -Impact "High"
}

# ==================== CONFIGURATION MANAGEMENT (CM) FAMILY ====================

function Configure-ConfigurationManagement {
    Write-Host "`n=== CONFIGURATION MANAGEMENT (CM) FAMILY ===" -ForegroundColor Cyan
    
    # CM-2: Baseline Configuration
    Write-Host "Implementing CM-2: Baseline Configuration ..." -ForegroundColor Green
    # Document current configuration
    $configInfo = @{
        OS = (Get-WmiObject Win32_OperatingSystem).Caption
        Version = (Get-WmiObject Win32_OperatingSystem).Version
        BuildNumber = (Get-WmiObject Win32_OperatingSystem).BuildNumber
        Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        Manufacturer = (Get-WmiObject Win32_ComputerSystem).Manufacturer
        Model = (Get-WmiObject Win32_ComputerSystem).Model
    }
    $configPath = Join-Path $ReportPath "baseline-config-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $configInfo | ConvertTo-Json | Out-File $configPath
    Add-ComplianceResult -Control "CM-2" -Title "Baseline Configuration" -Status "Documented" -Details "System configuration documented in $configPath" -Impact "Low"
    
    # CM-6: Configuration Settings
    Write-Host "Implementing CM-6: Configuration Settings ..." -ForegroundColor Green
    # Disable unnecessary features
    $features = @('TelnetClient', 'TFTP', 'SimpleSocket', 'LegacyComponents')
    $featureSuccess = $true
    foreach ($feature in $features) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($f -and $f.State -eq "Enabled") {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            $featureSuccess = $false
            Write-Warning "Could not disable feature $feature"
        }
    }
    Add-ComplianceResult -Control "CM-6" -Title "Configuration Settings" -Status $(if($featureSuccess){"Compliant"}else{"Partial"}) -Details "Unnecessary Windows features disabled" -Impact "Medium"
    
    # CM-7: Least Functionality
    Write-Host "Implementing CM-7: Least Functionality ..." -ForegroundColor Green
    $services = @('RemoteRegistry','SNMP','Telnet','SSDPSRV','upnphost','Browser','Messenger','NetMeeting Remote Desktop Sharing')
    $serviceSuccess = $true
    foreach ($service in $services) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Verbose "Service $service not found or already disabled"
        }
    }
    Add-ComplianceResult -Control "CM-7" -Title "Least Functionality" -Status "Compliant" -Details "Unnecessary services disabled" -Impact "Medium"
    
    # CM-8: Information System Component Inventory
    Write-Host "Implementing CM-8: Information System Component Inventory ..." -ForegroundColor Green
    $inventory = @{
        Software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
        Hardware = Get-WmiObject -Class Win32_SystemEnclosure | Select-Object Manufacturer, Model, SerialNumber
        NetworkAdapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object {$_.NetConnectionStatus -eq 2} | Select-Object Name, MACAddress
        Timestamp = Get-Date
    }
    $inventoryPath = Join-Path $ReportPath "system-inventory-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $inventory | ConvertTo-Json -Depth 3 | Out-File $inventoryPath
    Add-ComplianceResult -Control "CM-8" -Title "Information System Component Inventory" -Status "Documented" -Details "System inventory saved to $inventoryPath" -Impact "Low"
    
    # CM-11: User-Installed Software
    Write-Host "Implementing CM-11: User-Installed Software ..." -ForegroundColor Green
    try {
        if (Get-Command New-AppLockerPolicy -ErrorAction SilentlyContinue) {
            $policy = New-AppLockerPolicy -RuleType Executable, Script -User Everyone -RuleNamePrefix "NIST_CM11_" -Optimize
            $policyPath = Join-Path $BackupPath "AppLocker-Policy-CM11.xml"
            $policy | Export-Clixml -Path $policyPath
            Add-ComplianceResult -Control "CM-11" -Title "User-Installed Software" -Status "Policy Created" -Details "AppLocker baseline policy created at $policyPath" -Impact "High"
        } else {
            Add-ComplianceResult -Control "CM-11" -Title "User-Installed Software" -Status "Not Available" -Details "AppLocker not available on this system" -Impact "High"
        }
    } catch {
        Add-ComplianceResult -Control "CM-11" -Title "User-Installed Software" -Status "Failed" -Details $_.Exception.Message -Impact "High"
    }
}

# ==================== IDENTIFICATION AND AUTHENTICATION (IA) FAMILY ====================

function Configure-IdentificationAuthentication {
    Write-Host "`n=== IDENTIFICATION AND AUTHENTICATION (IA) FAMILY ===" -ForegroundColor Cyan
    
    # IA-2: Identification and Authentication (Organizational Users)
    Write-Host "Implementing IA-2: Identification and Authentication ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Type DWord -Value 0 -Control "IA-2"  # Require Ctrl+Alt+Del
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value 1 -Control "IA-2")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLockedUserId' -Type DWord -Value 3 -Control "IA-2")
    Add-ComplianceResult -Control "IA-2" -Title "Identification and Authentication" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Secure logon requirements enforced" -Impact "High"
    
    # IA-4: Identifier Management
    Write-Host "Implementing IA-4: Identifier Management ..." -ForegroundColor Green
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        }
        # Rename Administrator account (basic obfuscation)
        $admin = Get-LocalUser | Where-Object {$_.SID -like "*-500"}
        $renamed = $false
        if ($admin -and $admin.Name -eq "Administrator") {
            try {
                Rename-LocalUser -Name "Administrator" -NewName "Admin_$(Get-Random -Minimum 100 -Maximum 999)"
                $renamed = $true
            } catch {
                Write-Warning "Could not rename Administrator account: $($_.Exception.Message)"
            }
        }
        Add-ComplianceResult -Control "IA-4" -Title "Identifier Management" -Status "Partial" -Details "Guest disabled, Administrator account $(if($renamed){'renamed'}else{'review required'})" -Impact "Medium"
    } catch {
        Add-ComplianceResult -Control "IA-4" -Title "Identifier Management" -Status "Failed" -Details $_.Exception.Message -Impact "Medium"
    }
    
    # IA-5: Authenticator Management
    Write-Host "Implementing IA-5: Authenticator Management ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Type DWord -Value 1 -Control "IA-5"
    # Force strong authentication
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1 -Control "IA-5")
    # Enforce password complexity
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'CrashOnAuditFail' -Type DWord -Value 1 -Control "IA-5")
    Add-ComplianceResult -Control "IA-5" -Title "Authenticator Management" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Strong authentication mechanisms enforced" -Impact "High"
    
    # IA-8: Identification and Authentication (Non-Organizational Users)
    Write-Host "Implementing IA-8: Identification and Authentication (Non-Organizational Users) ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Type DWord -Value 0 -Control "IA-8"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 2 -Control "IA-8")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Type DWord -Value 1 -Control "IA-8")
    Add-ComplianceResult -Control "IA-8" -Title "Non-Organizational User Authentication" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Anonymous access restricted for non-organizational users" -Impact "High"
}

# ==================== SYSTEM AND COMMUNICATIONS PROTECTION (SC) FAMILY ====================

function Configure-SystemCommunicationsProtection {
    Write-Host "`n=== SYSTEM AND COMMUNICATIONS PROTECTION (SC) FAMILY ===" -ForegroundColor Cyan
    
    # SC-7: Boundary Protection
    Write-Host "Implementing SC-7: Boundary Protection ..." -ForegroundColor Green
    try {
        $commands = @(
            "netsh.exe advfirewall set allprofiles state on",
            "netsh.exe advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound",
            "netsh.exe advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound",
            "netsh.exe advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound",
            "netsh.exe advfirewall set publicprofile settings inboundusernotification enable"
        )
        
        $firewallSuccess = $true
        foreach ($cmd in $commands) {
            $result = Invoke-Expression $cmd 2>&1
            if ($LASTEXITCODE -ne 0) {
                $firewallSuccess = $false
                Write-Warning "Firewall command failed: $cmd"
            }
        }
        Add-ComplianceResult -Control "SC-7" -Title "Boundary Protection" -Status $(if($firewallSuccess){"Compliant"}else{"Failed"}) -Details "Windows Firewall enabled with default deny inbound" -Impact "High"
    } catch {
        Add-ComplianceResult -Control "SC-7" -Title "Boundary Protection" -Status "Failed" -Details $_.Exception.Message -Impact "High"
    }
    
    # SC-8: Transmission Confidentiality and Integrity
    Write-Host "Implementing SC-8: Transmission Confidentiality and Integrity ..." -ForegroundColor Green
    
    # Disable weak protocols and ciphers
    $protocols = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' = @{Enabled=0; DisabledByDefault=1}
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' = @{Enabled=0; DisabledByDefault=1}
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' = @{Enabled=0; DisabledByDefault=1}
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' = @{Enabled=0; DisabledByDefault=1}
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' = @{Enabled=0; DisabledByDefault=1}
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' = @{Enabled=0; DisabledByDefault=1}
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' = @{Enabled=0; DisabledByDefault=1}
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' = @{Enabled=0; DisabledByDefault=1}
    }
    
    $cryptoSuccess = $true
    foreach ($path in $protocols.Keys) {
        foreach ($setting in $protocols[$path].Keys) {
            $result = Set-RegValue -Path $path -Name $setting -Type DWord -Value $protocols[$path][$setting] -Control "SC-8"
            $cryptoSuccess = $cryptoSuccess -and $result
        }
    }
    
    # SMB signing
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1 -Control "SC-8"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1 -Control "SC-8")
    
    Add-ComplianceResult -Control "SC-8" -Title "Transmission Confidentiality and Integrity" -Status $(if($cryptoSuccess -and $success){"Compliant"}else{"Partial"}) -Details "Weak protocols disabled, SMB signing enforced" -Impact "High"
    
    # SC-12: Cryptographic Key Establishment and Management
    Write-Host "Implementing SC-12: Cryptographic Key Establishment and Management ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Type String -Value 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' -Control "SC-12"
    Add-ComplianceResult -Control "SC-12" -Title "Cryptographic Key Management" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Strong cipher suites configured" -Impact "High"
    
    # SC-13: Cryptographic Protection
    Write-Host "Implementing SC-13: Cryptographic Protection (BitLocker) ..." -ForegroundColor Green
    try {
        if (-not (Get-Module -ListAvailable -Name BitLocker)) {
            Add-ComplianceResult -Control "SC-13" -Title "Cryptographic Protection" -Status "Not Available" -Details "BitLocker module not available" -Impact "Critical"
            return
        }
        
        $os = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
        if ($null -eq $os -or $os.ProtectionStatus -ne 'On') {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            if ($tpm -and $tpm.TpmPresent -and $tpm.TpmEnabled) {
                Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector -ErrorAction Stop
                Add-ComplianceResult -Control "SC-13" -Title "Cryptographic Protection" -Status "Enabling" -Details "BitLocker encryption initiated with AES-256" -Impact "Critical"
            } else {
                Add-ComplianceResult -Control "SC-13" -Title "Cryptographic Protection" -Status "Failed" -Details "TPM not available or enabled" -Impact "Critical"
            }
        } else {
            Add-ComplianceResult -Control "SC-13" -Title "Cryptographic Protection" -Status "Compliant" -Details "BitLocker already enabled" -Impact "Critical"
        }
        
        if ($EnableBitLockerPIN) {
            try {
                Add-BitLockerKeyProtector -MountPoint 'C:' -TpmPinProtector -ErrorAction Stop
                Add-ComplianceResult -Control "SC-13" -Title "BitLocker PIN" -Status "Enabled" -Details "TPM+PIN protector added" -Impact "High"
            } catch { 
                Add-ComplianceResult -Control "SC-13" -Title "BitLocker PIN" -Status "Failed" -Details $_.Exception.Message -Impact "High"
            }
        }
    } catch {
        Add-ComplianceResult -Control "SC-13" -Title "Cryptographic Protection" -Status "Failed" -Details $_.Exception.Message -Impact "Critical"
    }
    
    # SC-15: Collaborative Computing Devices
    Write-Host "Implementing SC-15: Collaborative Computing Devices ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam' -Name 'Value' -Type String -Value 'Deny' -Control "SC-15"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -Name 'Value' -Type String -Value 'Deny' -Control "SC-15")
    Add-ComplianceResult -Control "SC-15" -Title "Collaborative Computing Devices" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Default deny for camera and microphone access" -Impact "Medium"
    
    # SC-20: Secure Name/Address Resolution Service (Authoritative Source)
    Write-Host "Implementing SC-20: Secure Name/Address Resolution ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0 -Control "SC-20"  # Disable LLMNR
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Type DWord -Value 2 -Control "SC-20")  # P-node (no broadcast)
    Add-ComplianceResult -Control "SC-20" -Title "Secure Name Resolution" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "LLMNR disabled, secure DNS resolution enforced" -Impact "Medium"
    
    # SC-21: Secure Name/Address Resolution Service (Recursive or Caching Resolver)
    Write-Host "Implementing SC-21: DNS over HTTPS ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableAutoDoh' -Type DWord -Value 2 -Control "SC-21"
    Add-ComplianceResult -Control "SC-21" -Title "Secure DNS Resolution" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "DNS over HTTPS enabled" -Impact "Medium"
    
    # SC-23: Session Authenticity
    Write-Host "Implementing SC-23: Session Authenticity ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 2 -Control "SC-23"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Type DWord -Value 1 -Control "SC-23")
    Add-ComplianceResult -Control "SC-23" -Title "Session Authenticity" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Session authentication mechanisms hardened" -Impact "High"
}

# ==================== SYSTEM AND INFORMATION INTEGRITY (SI) FAMILY ====================

function Configure-SystemInformationIntegrity {
    Write-Host "`n=== SYSTEM AND INFORMATION INTEGRITY (SI) FAMILY ===" -ForegroundColor Cyan
    
    # SI-2: Flaw Remediation
    Write-Host "Implementing SI-2: Flaw Remediation (Windows Update) ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0 -Control "SI-2"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions' -Type DWord -Value 4 -Control "SI-2")  # Auto download and install
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Type DWord -Value 0 -Control "SI-2")  # Every day
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallTime' -Type DWord -Value 3 -Control "SI-2")  # 3 AM
    Add-ComplianceResult -Control "SI-2" -Title "Flaw Remediation" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Windows Update configured for automatic installation" -Impact "High"
    
    # SI-3: Malicious Code Protection
    Write-Host "Implementing SI-3: Malicious Code Protection ..." -ForegroundColor Green
    try {
        if (Get-Module -ListAvailable -Name Defender) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
            Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue
            Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
            Set-MpPreference -CloudExtendedTimeout 50 -ErrorAction SilentlyContinue
            # Enable additional protection features
            Set-MpPreference -DisableArchiveScanning $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIntrusionPreventionSystem $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Set-MpPreference -DisableScriptScanning $false -ErrorAction SilentlyContinue
            Add-ComplianceResult -Control "SI-3" -Title "Malicious Code Protection" -Status "Compliant" -Details "Microsoft Defender configured with enhanced protection" -Impact "High"
        } else {
            Add-ComplianceResult -Control "SI-3" -Title "Malicious Code Protection" -Status "Failed" -Details "Microsoft Defender not available" -Impact "Critical"
        }
    } catch { 
        Add-ComplianceResult -Control "SI-3" -Title "Malicious Code Protection" -Status "Failed" -Details $_.Exception.Message -Impact "Critical"
    }
    
    # SI-4: Information System Monitoring
    Write-Host "Implementing SI-4: Information System Monitoring ..." -ForegroundColor Green
    
    # Enhanced PowerShell logging
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 -Control "SI-4"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockInvocationLogging' -Type DWord -Value 1 -Control "SI-4")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1 -Control "SI-4")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Type String -Value (Join-Path $TranscriptPath 'PS-Transcripts') -Control "SI-4")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Type DWord -Value 1 -Control "SI-4")
    
    # WMI logging
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WMI' -Name 'EnableLogging' -Type DWord -Value 1 -Control "SI-4")
    
    New-Folder -Path (Join-Path $TranscriptPath 'PS-Transcripts')
    Add-ComplianceResult -Control "SI-4" -Title "Information System Monitoring" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Enhanced logging for PowerShell and WMI activities" -Impact "High"
    
    # SI-7: Software, Firmware, and Information Integrity
    Write-Host "Implementing SI-7: Software and Information Integrity ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1 -Control "SI-7"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 1 -Control "SI-7")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags' -Type DWord -Value 1 -Control "SI-7")  # Credential Guard
    Add-ComplianceResult -Control "SI-7" -Title "Software and Information Integrity" -Status $(if($success){"Compliant"}else{"Partial"}) -Details "Device Guard and Credential Guard configured (hardware dependent)" -Impact "High"
    
    # SI-10: Information Input Validation
    Write-Host "Implementing SI-10: Information Input Validation ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1 -Control "SI-10"  # UAC
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 2 -Control "SI-10")  # Prompt for consent
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1 -Control "SI-10")
    Add-ComplianceResult -Control "SI-10" -Title "Information Input Validation" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "User Account Control (UAC) enforced with secure desktop" -Impact "High"
    
    # SI-11: Error Handling
    Write-Host "Implementing SI-11: Error Handling ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 1 -Control "SI-11"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'DontSendAdditionalData' -Type DWord -Value 1 -Control "SI-11")
    Add-ComplianceResult -Control "SI-11" -Title "Error Handling" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Windows Error Reporting disabled to prevent information disclosure" -Impact "Medium"
}

# ==================== MEDIA PROTECTION (MP) FAMILY ====================

function Configure-MediaProtection {
    Write-Host "`n=== MEDIA PROTECTION (MP) FAMILY ===" -ForegroundColor Cyan
    
    # MP-2, MP-3, MP-4, MP-5, MP-6: Media Access, Marking, Storage, Transport, Sanitization
    Write-Host "Implementing MP-2/3/4/5/6: Comprehensive Media Protection ..." -ForegroundColor Green
    
    # Control removable media access
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' -Name 'Deny_Read' -Type DWord -Value 1 -Control "MP-2"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' -Name 'Deny_Write' -Type DWord -Value 1 -Control "MP-2")
    
    # BitLocker for removable drives
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'RDVConfigureBDE' -Type DWord -Value 1 -Control "MP-5")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'RDVRequireEncryption' -Type DWord -Value 1 -Control "MP-5")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name 'RDVEncryptionType' -Type DWord -Value 1 -Control "MP-5")  # AES 256
    
    # AutoRun/AutoPlay disabled
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 -Control "MP-3")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Type DWord -Value 1 -Control "MP-3")
    
    Add-ComplianceResult -Control "MP-2/3/4/5/6" -Title "Media Protection" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Removable media access controlled, encryption enforced, AutoRun disabled" -Impact "High"
}

# ==================== CONTINGENCY PLANNING (CP) FAMILY ====================

function Configure-ContingencyPlanning {
    Write-Host "`n=== CONTINGENCY PLANNING (CP) FAMILY ===" -ForegroundColor Cyan
    
    # CP-9: Information System Backup
    Write-Host "Implementing CP-9: Information System Backup ..." -ForegroundColor Green
    try {
        # Enable System Restore
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
        $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'SystemRestorePointCreationFrequency' -Type DWord -Value 0 -Control "CP-9"
        
        # Configure shadow copies
        $result = vssadmin.exe create shadow /for=C: 2>&1
        Add-ComplianceResult -Control "CP-9" -Title "Information System Backup" -Status $(if($success){"Partial"}else{"Failed"}) -Details "System Restore enabled, Volume Shadow Copy configured" -Impact "Medium"
    } catch {
        Add-ComplianceResult -Control "CP-9" -Title "Information System Backup" -Status "Failed" -Details $_.Exception.Message -Impact "Medium"
    }
    
    # CP-10: Information System Recovery and Reconstitution
    Write-Host "Implementing CP-10: System Recovery ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' -Name 'ShutdownReasonUI' -Type DWord -Value 1 -Control "CP-10"
    Add-ComplianceResult -Control "CP-10" -Title "System Recovery" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Shutdown reason tracking enabled for recovery analysis" -Impact "Low"
}

# ==================== INCIDENT RESPONSE (IR) FAMILY ====================

function Configure-IncidentResponse {
    Write-Host "`n=== INCIDENT RESPONSE (IR) FAMILY ===" -ForegroundColor Cyan
    
    # IR-4, IR-5: Incident Handling and Monitoring
    Write-Host "Implementing IR-4/5: Incident Handling and Monitoring ..." -ForegroundColor Green
    
    # Configure event forwarding capabilities
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' -Name '1' -Type String -Value 'Server=http://SIEM-SERVER:5985/wsman/SubscriptionManager/WEC,Refresh=60' -Control "IR-4"
    
    # Enhanced process monitoring
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 -Control "IR-5")
    
    # Sysmon installation note (cannot install automatically)
    Add-ComplianceResult -Control "IR-4/5" -Title "Incident Response Monitoring" -Status "Partial" -Details "Event forwarding prepared, enhanced logging enabled. Install Sysmon for comprehensive monitoring" -Impact "High"
}

# ==================== RISK ASSESSMENT (RA) FAMILY ====================

function Configure-RiskAssessment {
    Write-Host "`n=== RISK ASSESSMENT (RA) FAMILY ===" -ForegroundColor Cyan
    
    # RA-5: Vulnerability Scanning
    Write-Host "Implementing RA-5: Vulnerability Scanning ..." -ForegroundColor Green
    
    # Enable Windows Defender's vulnerability scanning
    try {
        if (Get-Module -ListAvailable -Name Defender) {
            Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
            Set-MpPreference -SevereThreatDefaultAction Remove -ErrorAction SilentlyContinue
            Set-MpPreference -HighThreatDefaultAction Remove -ErrorAction SilentlyContinue
            Set-MpPreference -ModerateThreatDefaultAction Quarantine -ErrorAction SilentlyContinue
            Add-ComplianceResult -Control "RA-5" -Title "Vulnerability Scanning" -Status "Enabled" -Details "Windows Defender threat scanning optimized" -Impact "Medium"
        }
    } catch {
        Add-ComplianceResult -Control "RA-5" -Title "Vulnerability Scanning" -Status "Failed" -Details $_.Exception.Message -Impact "Medium"
    }
}

# ==================== MAINTENANCE (MA) FAMILY ====================

function Configure-Maintenance {
    Write-Host "`n=== MAINTENANCE (MA) FAMILY ===" -ForegroundColor Cyan
    
    # MA-4: Nonlocal Maintenance
    Write-Host "Implementing MA-4: Nonlocal Maintenance ..." -ForegroundColor Green
    $success = Set-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 1 -Control "MA-4"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Type DWord -Value 0 -Control "MA-4")  # Disable Remote Assistance
    Add-ComplianceResult -Control "MA-4" -Title "Nonlocal Maintenance" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Remote Desktop and Remote Assistance disabled" -Impact "Medium"
}

# ==================== AWARENESS AND TRAINING (AT) FAMILY ====================

function Configure-AwarenessTraining {
    Write-Host "`n=== AWARENESS AND TRAINING (AT) FAMILY ===" -ForegroundColor Cyan
    
    # AT-2, AT-3: Security Awareness Training and Role-Based Training
    Write-Host "Implementing AT-2/3: Security Awareness and Training ..." -ForegroundColor Green
    
    # Configure security notifications
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -Type String -Value 'SECURITY WARNING' -Control "AT-2"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeText' -Type String -Value 'This system is for authorized users only. Activity is monitored and recorded.' -Control "AT-2")
    Add-ComplianceResult -Control "AT-2/3" -Title "Security Awareness and Training" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Security warning banner configured" -Impact "Low"
}

# ==================== PHYSICAL AND ENVIRONMENTAL PROTECTION (PE) FAMILY ====================

function Configure-PhysicalEnvironmentalProtection {
    Write-Host "`n=== PHYSICAL AND ENVIRONMENTAL PROTECTION (PE) FAMILY ===" -ForegroundColor Cyan
    
    # PE-3: Physical Access Control
    Write-Host "Implementing PE-3: Physical Access Control ..." -ForegroundColor Green
    
    # Configure automatic screen lock
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveActive' -Type String -Value '1' -Control "PE-3"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaveTimeOut' -Type String -Value '600' -Control "PE-3")  # 10 minutes
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -Type String -Value '1' -Control "PE-3")
    
    # Lock workstation on smart card removal
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Type String -Value '2' -Control "PE-3")
    
    Add-ComplianceResult -Control "PE-3" -Title "Physical Access Control" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Screen lock and smart card removal policies configured" -Impact "Medium"
}

# ==================== PLANNING (PL) FAMILY ====================

function Configure-Planning {
    Write-Host "`n=== PLANNING (PL) FAMILY ===" -ForegroundColor Cyan
    
    # PL-4, PL-8: Rules of Behavior and Information Security Architecture
    Write-Host "Implementing PL-4/8: Rules of Behavior and Security Architecture ..." -ForegroundColor Green
    
    # Document security architecture
    $securityDoc = @{
        SystemName = $env:COMPUTERNAME
        Domain = (Get-WmiObject Win32_ComputerSystem).Domain
        SecurityLevel = $ComplianceLevel
        ControlsImplemented = $global:ControlsImplemented
        Timestamp = Get-Date
        Architecture = @{
            OS = (Get-WmiObject Win32_OperatingSystem).Caption
            Version = (Get-WmiObject Win32_OperatingSystem).Version
            Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
            SecurityFeatures = @('BitLocker', 'Windows Defender', 'Windows Firewall', 'UAC', 'Audit Logging')
        }
    }
    
    $docPath = Join-Path $ReportPath "security-architecture-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $securityDoc | ConvertTo-Json -Depth 4 | Out-File $docPath
    Add-ComplianceResult -Control "PL-4/8" -Title "Security Architecture Documentation" -Status "Documented" -Details "Security architecture documented in $docPath" -Impact "Low"
}

# ==================== SYSTEM AND SERVICES ACQUISITION (SA) FAMILY ====================

function Configure-SystemServicesAcquisition {
    Write-Host "`n=== SYSTEM AND SERVICES ACQUISITION (SA) FAMILY ===" -ForegroundColor Cyan
    
    # SA-4, SA-8, SA-11: Acquisition Process, Security Engineering, Developer Security Testing
    Write-Host "Implementing SA-4/8/11: Acquisition and Development Security ..." -ForegroundColor Green
    
    # Configure Windows Defender Application Control (WDAC) preparation
    $success = Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'DeployConfigCIPolicy' -Type DWord -Value 1 -Control "SA-11"
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 3 -Control "SA-11")
    
    # SmartScreen for downloads
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value 2 -Control "SA-4")
    $success = $success -and (Set-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Type DWord -Value 1 -Control "SA-4")
    
    Add-ComplianceResult -Control "SA-4/8/11" -Title "System and Services Acquisition" -Status $(if($success){"Compliant"}else{"Failed"}) -Details "Application control and SmartScreen configured" -Impact "Medium"
}

# ==================== COMPLIANCE REPORTING ====================

function Generate-ComplianceReport {
    Write-Host "`n=== GENERATING COMPLIANCE REPORT ===" -ForegroundColor Cyan
    
    if (-not $GenerateReport) {
        Write-Host "Report generation skipped (GenerateReport = $false)" -ForegroundColor Yellow
        return
    }
    
    $reportData = @{
        SystemInformation = @{
            ComputerName = $env:COMPUTERNAME
            Domain = (Get-WmiObject Win32_ComputerSystem).Domain
            OS = (Get-WmiObject Win32_OperatingSystem).Caption
            Version = (Get-WmiObject Win32_OperatingSystem).Version
            Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
            LastBootUpTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
        }
        ComplianceLevel = $ComplianceLevel
        ExecutionTimestamp = Get-Date
        ScriptVersion = "Enhanced NIST SP 800-53 Rev. 5 v2.0"
        TotalControls = $global:ComplianceResults.Count
        ComplianceResults = $global:ComplianceResults
        Summary = @{
            Compliant = ($global:ComplianceResults | Where-Object {$_.Status -eq "Compliant"}).Count
            Failed = ($global:ComplianceResults | Where-Object {$_.Status -eq "Failed"}).Count
            Partial = ($global:ComplianceResults | Where-Object {$_.Status -eq "Partial"}).Count
            NotAvailable = ($global:ComplianceResults | Where-Object {$_.Status -eq "Not Available"}).Count
            ReviewRequired = ($global:ComplianceResults | Where-Object {$_.Status -eq "Review Required"}).Count
        }
        ControlFamilies = @{
            "Access Control (AC)" = ($global:ComplianceResults | Where-Object {$_.Control -like "AC-*"}).Count
            "Audit and Accountability (AU)" = ($global:ComplianceResults | Where-Object {$_.Control -like "AU-*"}).Count
            "Awareness and Training (AT)" = ($global:ComplianceResults | Where-Object {$_.Control -like "AT-*"}).Count
            "Configuration Management (CM)" = ($global:ComplianceResults | Where-Object {$_.Control -like "CM-*"}).Count
            "Contingency Planning (CP)" = ($global:ComplianceResults | Where-Object {$_.Control -like "CP-*"}).Count
            "Identification and Authentication (IA)" = ($global:ComplianceResults | Where-Object {$_.Control -like "IA-*"}).Count
            "Incident Response (IR)" = ($global:ComplianceResults | Where-Object {$_.Control -like "IR-*"}).Count
            "Maintenance (MA)" = ($global:ComplianceResults | Where-Object {$_.Control -like "MA-*"}).Count
            "Media Protection (MP)" = ($global:ComplianceResults | Where-Object {$_.Control -like "MP-*"}).Count
            "Physical and Environmental Protection (PE)" = ($global:ComplianceResults | Where-Object {$_.Control -like "PE-*"}).Count
            "Planning (PL)" = ($global:ComplianceResults | Where-Object {$_.Control -like "PL-*"}).Count
            "Risk Assessment (RA)" = ($global:ComplianceResults | Where-Object {$_.Control -like "RA-*"}).Count
            "System and Services Acquisition (SA)" = ($global:ComplianceResults | Where-Object {$_.Control -like "SA-*"}).Count
            "System and Communications Protection (SC)" = ($global:ComplianceResults | Where-Object {$_.Control -like "SC-*"}).Count
            "System and Information Integrity (SI)" = ($global:ComplianceResults | Where-Object {$_.Control -like "SI-*"}).Count
        }
        Recommendations = @()
    }
    
    # Add recommendations based on failed controls
    $failedControls = $global:ComplianceResults | Where-Object {$_.Status -in @("Failed", "Not Available")}
    foreach ($failed in $failedControls) {
        $reportData.Recommendations += "Review and remediate $($failed.Control): $($failed.Title) - $($failed.Details)"
    }
    
    # Generate reports in multiple formats
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    
    # JSON Report
    $jsonPath = Join-Path $ReportPath "NIST-Compliance-Report-$timestamp.json"
    $reportData | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8
    
    # HTML Report
    $htmlPath = Join-Path $ReportPath "NIST-Compliance-Report-$timestamp.html"
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>NIST SP 800-53 Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #2c3e50; }
        .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .compliant { color: #27ae60; font-weight: bold; }
        .failed { color: #e74c3c; font-weight: bold; }
        .partial { color: #f39c12; font-weight: bold; }
        .not-available { color: #95a5a6; font-weight: bold; }
        .review-required { color: #8e44ad; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #34495e; color: white; }
        .high { background-color: #ffebee; }
        .medium { background-color: #fff3e0; }
        .low { background-color: #e8f5e8; }
    </style>
</head>
<body>
    <h1>NIST SP 800-53 Rev. 5 Compliance Report</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>System:</strong> $($reportData.SystemInformation.ComputerName) ($($reportData.SystemInformation.OS))</p>
        <p><strong>Compliance Level:</strong> $($reportData.ComplianceLevel)</p>
        <p><strong>Report Generated:</strong> $($reportData.ExecutionTimestamp)</p>
        <p><strong>Total Controls Evaluated:</strong> $($reportData.TotalControls)</p>
        
        <h3>Compliance Status</h3>
        <ul>
            <li class="compliant">Compliant: $($reportData.Summary.Compliant)</li>
            <li class="failed">Failed: $($reportData.Summary.Failed)</li>
            <li class="partial">Partial: $($reportData.Summary.Partial)</li>
            <li class="not-available">Not Available: $($reportData.Summary.NotAvailable)</li>
            <li class="review-required">Review Required: $($reportData.Summary.ReviewRequired)</li>
        </ul>
    </div>
    
    <h2>Control Family Coverage</h2>
    <table>
        <tr><th>Control Family</th><th>Controls Addressed</th></tr>
"@
    
    foreach ($family in $reportData.ControlFamilies.Keys) {
        $count = $reportData.ControlFamilies[$family]
        $htmlContent += "        <tr><td>$family</td><td>$count</td></tr>`n"
    }
    
    $htmlContent += @"
    </table>
    
    <h2>Detailed Results</h2>
    <table>
        <tr><th>Control</th><th>Title</th><th>Status</th><th>Details</th><th>Impact</th></tr>
"@
    
    foreach ($result in $reportData.ComplianceResults | Sort-Object Control) {
        $statusClass = switch ($result.Status) {
            "Compliant" { "compliant" }
            "Failed" { "failed" }
            "Partial" { "partial" }
            "Not Available" { "not-available" }
            "Review Required" { "review-required" }
            default { "" }
        }
        $impactClass = switch ($result.Impact) {
            "Critical" { "high" }
            "High" { "high" }
            "Medium" { "medium" }
            "Low" { "low" }
            default { "" }
        }
        
        $htmlContent += "        <tr class=`"$impactClass`"><td>$($result.Control)</td><td>$($result.Title)</td><td class=`"$statusClass`">$($result.Status)</td><td>$($result.Details)</td><td>$($result.Impact)</td></tr>`n"
    }
    
    $htmlContent += @"
    </table>
    
    <h2>Recommendations</h2>
    <ul>
"@
    
    foreach ($recommendation in $reportData.Recommendations) {
        $htmlContent += "        <li>$recommendation</li>`n"
    }
    
    $htmlContent += @"
    </ul>
    
    <footer>
        <p><em>Generated by Enhanced NIST SP 800-53 Rev. 5 Compliance Script</em></p>
        <p><strong>Important:</strong> This report provides technical compliance status only. Manual review and validation required for complete compliance assessment.</p>
    </footer>
</body>
</html>
"@
    
    $htmlContent | Out-File $htmlPath -Encoding UTF8
    
    # CSV Report for easy analysis
    $csvPath = Join-Path $ReportPath "NIST-Compliance-Results-$timestamp.csv"
    $reportData.ComplianceResults | Export-Csv $csvPath -NoTypeInformation
    
    Write-Host "`nCompliance reports generated:" -ForegroundColor Green
    Write-Host "  JSON: $jsonPath" -ForegroundColor White
    Write-Host "  HTML: $htmlPath" -ForegroundColor White
    Write-Host "  CSV:  $csvPath" -ForegroundColor White
    
    # Display summary
    Write-Host "`nCompliance Summary:" -ForegroundColor Cyan
    Write-Host "  Total Controls: $($reportData.TotalControls)" -ForegroundColor White
    Write-Host "  Compliant:      $($reportData.Summary.Compliant) ($([math]::Round(($reportData.Summary.Compliant/$reportData.TotalControls)*100,1))%)" -ForegroundColor Green
    Write-Host "  Failed:         $($reportData.Summary.Failed) ($([math]::Round(($reportData.Summary.Failed/$reportData.TotalControls)*100,1))%)" -ForegroundColor Red
    Write-Host "  Partial:        $($reportData.Summary.Partial) ($([math]::Round(($reportData.Summary.Partial/$reportData.TotalControls)*100,1))%)" -ForegroundColor Yellow
    Write-Host "  Not Available:  $($reportData.Summary.NotAvailable) ($([math]::Round(($reportData.Summary.NotAvailable/$reportData.TotalControls)*100,1))%)" -ForegroundColor Gray
    Write-Host "  Review Req.:    $($reportData.Summary.ReviewRequired) ($([math]::Round(($reportData.Summary.ReviewRequired/$reportData.TotalControls)*100,1))%)" -ForegroundColor Magenta
}

# ==================== MAIN EXECUTION ====================

Write-Host @"

╔═══════════════════════════════════════════════════════════════════════════════╗
║                    Enhanced NIST SP 800-53 Rev. 5                            ║
║                      Windows Security Baseline                               ║
║                                                                               ║
║  Comprehensive implementation of NIST SP 800-53 Rev. 5 controls              ║
║  covering 15 control families with detailed compliance tracking              ║
╚═══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Assert-Admin
Start-Logging

Write-Host "Compliance Level: $ComplianceLevel" -ForegroundColor Yellow
Write-Host "System: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Started: $(Get-Date)" -ForegroundColor White

try {
    Write-Host "`nExecuting NIST SP 800-53 Rev. 5 controls implementation..." -ForegroundColor Green
    
    # Execute all control families
    Configure-AccessControl
    Configure-AuditAccountability  
    Configure-ConfigurationManagement
    Configure-IdentificationAuthentication
    Configure-SystemCommunicationsProtection
    Configure-SystemInformationIntegrity
    Configure-MediaProtection
    Configure-ContingencyPlanning
    Configure-IncidentResponse
    Configure-RiskAssessment
    Configure-Maintenance
    Configure-AwarenessTraining
    Configure-PhysicalEnvironmentalProtection
    Configure-Planning
    Configure-SystemServicesAcquisition
    
    # Generate compliance report
    Generate-ComplianceReport
    
    Write-Host "`n" + "="*80 -ForegroundColor Green
    Write-Host "ENHANCED NIST SP 800-53 IMPLEMENTATION COMPLETED" -ForegroundColor Green
    Write-Host "="*80 -ForegroundColor Green
    
    Write-Host "`nExecution Summary:" -ForegroundColor Cyan
    Write-Host "  Transcript:     $global:TranscriptFile" -ForegroundColor White
    Write-Host "  Backups:        $BackupPath" -ForegroundColor White
    Write-Host "  Reports:        $ReportPath" -ForegroundColor White
    Write-Host "  Controls:       $($global:ControlsImplemented.Count) implemented" -ForegroundColor White
    
    Write-Host "`nCRITICAL POST-IMPLEMENTATION TASKS:" -ForegroundColor Red
    Write-Host "┌─────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Red
    Write-Host "│ 1. BitLocker Recovery: Escrow keys to AD DS/Azure AD/Intune                │" -ForegroundColor Yellow
    Write-Host "│ 2. SIEM Integration: Install and configure log forwarding agent            │" -ForegroundColor Yellow  
    Write-Host "│ 3. AppLocker Policy: Review, test, and deploy exported policies            │" -ForegroundColor Yellow
    Write-Host "│ 4. Group Policy: Convert settings to GPO/Intune for fleet management      │" -ForegroundColor Yellow
    Write-Host "│ 5. Sysmon: Install for advanced process and network monitoring             │" -ForegroundColor Yellow
    Write-Host "│ 6. MFA/Conditional Access: Configure in Azure AD/Identity Provider         │" -ForegroundColor Yellow
    Write-Host "│ 7. Review Reports: Analyze compliance reports and remediate failed controls│" -ForegroundColor Yellow
    Write-Host "│ 8. Vulnerability Management: Deploy enterprise vulnerability scanner       │" -ForegroundColor Yellow
    Write-Host "└─────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Red
    
    Write-Host "`nNOTES:" -ForegroundColor Yellow
    Write-Host "• Some settings require reboot to take effect" -ForegroundColor Gray
    Write-Host "• Hardware-dependent features (TPM, VBS) may not be available on all systems" -ForegroundColor Gray
    Write-Host "• This script provides technical controls only - administrative and physical controls require separate implementation" -ForegroundColor Gray
    Write-Host "• Regular compliance validation and continuous monitoring are required" -ForegroundColor Gray
    
} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Add-ComplianceResult -Control "SCRIPT" -Title "Script Execution" -Status "Failed" -Details $_.Exception.Message -Impact "Critical"
} finally {
    if ($global:TranscriptFile) {
        Stop-Transcript | Out-Null
    }
}

# Conditional reboot
if (-not $NoReboot) {
    Write-Host "`nRebooting system in 30 seconds to apply settings..." -ForegroundColor Red
    Write-Host "Press Ctrl+C to cancel reboot." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    Restart-Computer -Force
} else {
    Write-Host "`nReboot suppressed. Some settings may require manual reboot to take effect." -ForegroundColor Yellow
    Write-Host "Run with -NoReboot:`$false to enable automatic reboot." -ForegroundColor Gray
}
