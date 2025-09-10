# Essential 8 Compliance PowerShell Script
# Australian Cyber Security Centre - Essential Eight Mitigation Strategies
# Version: 1.0
# Author: Automated compliance checker

#Requires -RunAsAdministrator

param(
    [switch]$CheckOnly = $false,
    [switch]$Remediate = $false,
    [string]$LogPath = "$env:USERPROFILE\Desktop\Essential8_Report.txt"
)

# Initialize results array
$Results = @()
$ComplianceScore = 0
$TotalChecks = 8

Write-Host "=== Australian Cyber Security Essential 8 Compliance Check ===" -ForegroundColor Cyan
Write-Host "Start Time: $(Get-Date)" -ForegroundColor Yellow
Write-Host ""

# Function to log results
function Write-Result {
    param($Title, $Status, $Details, $Recommendation = "")
    $Result = @{
        Title = $Title
        Status = $Status
        Details = $Details
        Recommendation = $Recommendation
        Timestamp = Get-Date
    }
    $global:Results += $Result
    
    $Color = switch ($Status) {
        "COMPLIANT" { "Green" }
        "NON-COMPLIANT" { "Red" }
        "PARTIAL" { "Yellow" }
        "WARNING" { "Magenta" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Title" -ForegroundColor $Color
    if ($Details) { Write-Host "  Details: $Details" -ForegroundColor Gray }
    if ($Recommendation) { Write-Host "  Recommendation: $Recommendation" -ForegroundColor Gray }
    Write-Host ""
}

# 1. Application Control
Write-Host "1. Checking Application Control (Mitigation Strategy 1)" -ForegroundColor Blue
try {
    $AppLockerPolicy = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
    $DefenderAppControl = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    
    if ($AppLockerPolicy -or $DefenderAppControl) {
        if ($AppLockerPolicy) {
            $RuleCount = ($AppLockerPolicy.RuleCollections | Measure-Object).Count
            Write-Result "Application Control" "COMPLIANT" "AppLocker policy active with $RuleCount rule collections"
            $global:ComplianceScore++
        } elseif ($DefenderAppControl -and $DefenderAppControl.CodeIntegrityPolicyEnforcementStatus -eq 1) {
            Write-Result "Application Control" "COMPLIANT" "Windows Defender Application Control enabled"
            $global:ComplianceScore++
        } else {
            Write-Result "Application Control" "PARTIAL" "Some application control detected but may not be fully enforced" "Review and strengthen application control policies"
        }
    } else {
        Write-Result "Application Control" "NON-COMPLIANT" "No application control mechanisms detected" "Implement AppLocker or Windows Defender Application Control"
    }
} catch {
    Write-Result "Application Control" "WARNING" "Error checking application control: $($_.Exception.Message)" "Manual verification required"
}

# 2. Patch Applications
Write-Host "2. Checking Application Patching (Mitigation Strategy 2)" -ForegroundColor Blue
try {
    # Check Windows Update settings
    $WUSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    $AutoUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ErrorAction SilentlyContinue
    
    # Check for common applications and their update mechanisms
    $OutdatedApps = @()
    
    # Check if automatic updates are configured
    if ($WUSettings.AUOptions -eq 4 -or $AutoUpdate.AUOptions -eq 4) {
        Write-Result "Application Patching" "COMPLIANT" "Automatic updates configured for Windows"
        $global:ComplianceScore++
    } else {
        Write-Result "Application Patching" "NON-COMPLIANT" "Automatic updates not properly configured" "Enable automatic updates for operating system and applications"
    }
} catch {
    Write-Result "Application Patching" "WARNING" "Error checking patch management: $($_.Exception.Message)" "Manual verification of update policies required"
}

# 3. Configure Microsoft Office macro settings
Write-Host "3. Checking Microsoft Office Macro Settings (Mitigation Strategy 3)" -ForegroundColor Blue
try {
    $OfficeVersions = @("16.0", "15.0", "14.0") # Office 2019/365, 2013, 2010
    $MacroCompliant = $false
    
    foreach ($version in $OfficeVersions) {
        $ExcelMacro = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$version\Excel\Security" -Name VBAWarnings -ErrorAction SilentlyContinue
        $WordMacro = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$version\Word\Security" -Name VBAWarnings -ErrorAction SilentlyContinue
        $PowerPointMacro = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\$version\PowerPoint\Security" -Name VBAWarnings -ErrorAction SilentlyContinue
        
        if ($ExcelMacro.VBAWarnings -eq 2 -or $WordMacro.VBAWarnings -eq 2 -or $PowerPointMacro.VBAWarnings -eq 2) {
            $MacroCompliant = $true
            break
        }
    }
    
    if ($MacroCompliant) {
        Write-Result "Office Macro Settings" "COMPLIANT" "Microsoft Office macros disabled or restricted"
        $global:ComplianceScore++
    } else {
        Write-Result "Office Macro Settings" "NON-COMPLIANT" "Microsoft Office macro security not properly configured" "Disable macros or allow only signed/trusted macros"
    }
} catch {
    Write-Result "Office Macro Settings" "WARNING" "Error checking Office macro settings: $($_.Exception.Message)" "Manually verify Office security settings"
}

# 4. User Application Hardening
Write-Host "4. Checking User Application Hardening (Mitigation Strategy 4)" -ForegroundColor Blue
try {
    # Check web browser settings (simplified check)
    $IEZones = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -ErrorAction SilentlyContinue
    $EdgeSettings = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Edge" -ErrorAction SilentlyContinue
    
    $HardeningScore = 0
    $TotalHardeningChecks = 3
    
    # Check Internet Explorer security zones
    if ($IEZones -and $IEZones.'1200' -eq 3) {
        $HardeningScore++
    }
    
    # Check if Java/Flash are disabled or restricted
    $JavaDisabled = -not (Get-ItemProperty -Path "HKLM:\SOFTWARE\JavaSoft" -ErrorAction SilentlyContinue)
    if ($JavaDisabled) { $HardeningScore++ }
    
    # Check Adobe Flash (should be disabled)
    $FlashDisabled = -not (Test-Path "C:\Windows\System32\Macromed\Flash\*")
    if ($FlashDisabled) { $HardeningScore++ }
    
    if ($HardeningScore -eq $TotalHardeningChecks) {
        Write-Result "User Application Hardening" "COMPLIANT" "Web browsers and applications properly hardened"
        $global:ComplianceScore++
    } elseif ($HardeningScore -gt 0) {
        Write-Result "User Application Hardening" "PARTIAL" "Some hardening measures in place ($HardeningScore/$TotalHardeningChecks)" "Review and implement additional browser/application security settings"
    } else {
        Write-Result "User Application Hardening" "NON-COMPLIANT" "Insufficient application hardening detected" "Harden web browsers, disable unnecessary plugins, configure security zones"
    }
} catch {
    Write-Result "User Application Hardening" "WARNING" "Error checking application hardening: $($_.Exception.Message)" "Manual verification required"
}

# 5. Restrict Administrative Privileges
Write-Host "5. Checking Administrative Privileges (Mitigation Strategy 5)" -ForegroundColor Blue
try {
    $AdminUsers = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.ObjectClass -eq "User" }
    $TotalUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    $AdminRatio = ($AdminUsers.Count / $TotalUsers.Count) * 100
    
    # Check UAC settings
    $UACLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue
    
    if ($AdminRatio -le 20 -and $UACLevel.ConsentPromptBehaviorAdmin -ge 2) {
        Write-Result "Administrative Privileges" "COMPLIANT" "Admin users: $($AdminUsers.Count), Ratio: $([math]::Round($AdminRatio,1))%, UAC enabled"
        $global:ComplianceScore++
    } elseif ($AdminRatio -le 30) {
        Write-Result "Administrative Privileges" "PARTIAL" "Admin users: $($AdminUsers.Count), Ratio: $([math]::Round($AdminRatio,1))%" "Reduce number of administrative users and ensure UAC is properly configured"
    } else {
        Write-Result "Administrative Privileges" "NON-COMPLIANT" "Too many administrative users: $($AdminUsers.Count), Ratio: $([math]::Round($AdminRatio,1))%" "Implement principle of least privilege, reduce admin accounts"
    }
} catch {
    Write-Result "Administrative Privileges" "WARNING" "Error checking administrative privileges: $($_.Exception.Message)" "Manual verification required"
}

# 6. Patch Operating System
Write-Host "6. Checking Operating System Patching (Mitigation Strategy 6)" -ForegroundColor Blue
try {
    $LastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $DaysSinceBoot = (Get-Date) - $LastBoot
    $HotFixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
    $RecentPatches = $HotFixes | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-30) }
    
    if ($RecentPatches.Count -gt 0 -and $DaysSinceBoot.Days -lt 30) {
        Write-Result "Operating System Patching" "COMPLIANT" "Recent patches installed: $($RecentPatches.Count), Last reboot: $([math]::Round($DaysSinceBoot.Days)) days ago"
        $global:ComplianceScore++
    } elseif ($RecentPatches.Count -gt 0) {
        Write-Result "Operating System Patching" "PARTIAL" "Patches installed but system may need restart" "Regular reboots recommended to complete patch installation"
    } else {
        Write-Result "Operating System Patching" "NON-COMPLIANT" "No recent patches detected" "Ensure Windows Update is enabled and patches are being installed regularly"
    }
} catch {
    Write-Result "Operating System Patching" "WARNING" "Error checking OS patches: $($_.Exception.Message)" "Manual verification required"
}

# 7. Multi-factor Authentication
Write-Host "7. Checking Multi-factor Authentication (Mitigation Strategy 7)" -ForegroundColor Blue
try {
    # Check for Windows Hello
    $WindowsHello = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name AllowDomainPINLogon -ErrorAction SilentlyContinue
    $BiometricService = Get-Service -Name "WbioSrvc" -ErrorAction SilentlyContinue
    
    # Check for smart card policies
    $SmartCardPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" -ErrorAction SilentlyContinue
    
    if ($WindowsHello -or ($BiometricService -and $BiometricService.Status -eq "Running") -or $SmartCardPolicy) {
        Write-Result "Multi-factor Authentication" "COMPLIANT" "MFA mechanisms detected (Windows Hello/Biometrics/Smart Cards)"
        $global:ComplianceScore++
    } else {
        Write-Result "Multi-factor Authentication" "NON-COMPLIANT" "No MFA mechanisms detected" "Implement Windows Hello, biometric authentication, or smart card authentication"
    }
} catch {
    Write-Result "Multi-factor Authentication" "WARNING" "Error checking MFA: $($_.Exception.Message)" "Manual verification of authentication methods required"
}

# 8. Regular Backups
Write-Host "8. Checking Regular Backups (Mitigation Strategy 8)" -ForegroundColor Blue
try {
    # Check Windows Backup
    $BackupSchedule = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Backup\" -ErrorAction SilentlyContinue
    $FileHistoryEnabled = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory" -Name Enabled -ErrorAction SilentlyContinue
    $SystemRestore = Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending | Select-Object -First 1
    
    $BackupScore = 0
    $BackupMechanisms = @()
    
    if ($BackupSchedule) { 
        $BackupScore++
        $BackupMechanisms += "Windows Backup"
    }
    if ($FileHistoryEnabled.Enabled -eq 1) { 
        $BackupScore++
        $BackupMechanisms += "File History"
    }
    if ($SystemRestore -and $SystemRestore.CreationTime -gt (Get-Date).AddDays(-7)) { 
        $BackupScore++
        $BackupMechanisms += "System Restore"
    }
    
    if ($BackupScore -ge 2) {
        Write-Result "Regular Backups" "COMPLIANT" "Multiple backup mechanisms: $($BackupMechanisms -join ', ')"
        $global:ComplianceScore++
    } elseif ($BackupScore -eq 1) {
        Write-Result "Regular Backups" "PARTIAL" "Limited backup coverage: $($BackupMechanisms -join ', ')" "Implement additional backup strategies and test recovery procedures"
    } else {
        Write-Result "Regular Backups" "NON-COMPLIANT" "No automated backup mechanisms detected" "Implement regular backup solution with offsite/offline storage"
    }
} catch {
    Write-Result "Regular Backups" "WARNING" "Error checking backup configuration: $($_.Exception.Message)" "Manual verification of backup procedures required"
}

# Generate Summary Report
Write-Host "=== ESSENTIAL 8 COMPLIANCE SUMMARY ===" -ForegroundColor Cyan
$CompliancePercentage = [math]::Round(($ComplianceScore / $TotalChecks) * 100, 1)
Write-Host "Overall Compliance Score: $ComplianceScore/$TotalChecks ($CompliancePercentage%)" -ForegroundColor $(if ($CompliancePercentage -ge 80) { "Green" } elseif ($CompliancePercentage -ge 60) { "Yellow" } else { "Red" })

$MaturityLevel = switch ($ComplianceScore) {
    { $_ -eq 8 } { "Maturity Level 3 (Leading)" }
    { $_ -ge 6 } { "Maturity Level 2 (Advanced)" }
    { $_ -ge 4 } { "Maturity Level 1 (Baseline)" }
    default { "Below Maturity Level 1" }
}
Write-Host "Estimated Maturity Level: $MaturityLevel" -ForegroundColor Cyan

# Export detailed report
Write-Host "`nGenerating detailed report..." -ForegroundColor Yellow
$ReportContent = @"
ESSENTIAL 8 COMPLIANCE REPORT
Generated: $(Get-Date)
System: $env:COMPUTERNAME
User: $env:USERNAME

EXECUTIVE SUMMARY
=================
Overall Compliance Score: $ComplianceScore/$TotalChecks ($CompliancePercentage%)
Estimated Maturity Level: $MaturityLevel

DETAILED FINDINGS
=================
"@

foreach ($result in $Results) {
    $ReportContent += @"

[$($result.Status)] $($result.Title)
Details: $($result.Details)
$(if ($result.Recommendation) { "Recommendation: $($result.Recommendation)" })
Checked: $($result.Timestamp)

"@
}

$ReportContent += @"

NEXT STEPS
==========
1. Address all NON-COMPLIANT items immediately
2. Improve PARTIAL compliance items
3. Implement regular compliance monitoring
4. Schedule periodic reviews and updates
5. Consider professional cybersecurity assessment

For detailed implementation guidance, refer to:
- Australian Cyber Security Centre Essential Eight documentation
- Microsoft security baselines and recommendations
- Industry-specific cybersecurity frameworks

Report saved to: $LogPath
"@

$ReportContent | Out-File -FilePath $LogPath -Encoding UTF8
Write-Host "Detailed report saved to: $LogPath" -ForegroundColor Green

Write-Host "`nCompliance check completed at $(Get-Date)" -ForegroundColor Yellow
Write-Host "For the latest Essential Eight guidance, visit: https://www.cyber.gov.au/essential-eight" -ForegroundColor Cyan
