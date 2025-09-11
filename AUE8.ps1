#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Australia Essential Eight Cybersecurity Compliance Audit Script
.DESCRIPTION
    This script audits and helps implement the Australian Cyber Security Centre's Essential Eight controls
.NOTES
    Version: 1.0
    Author: Essential Eight Compliance Tool
    Requires: Administrator privileges
#>

# Initialize transcript for logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = "$env:USERPROFILE\Desktop\Essential8_Audit_$timestamp"
New-Item -ItemType Directory -Path $logPath -Force | Out-Null
Start-Transcript -Path "$logPath\audit_log.txt"

Write-Host "`n===== AUSTRALIA ESSENTIAL EIGHT COMPLIANCE AUDIT =====" -ForegroundColor Cyan
Write-Host "Audit Started: $(Get-Date)" -ForegroundColor Green
Write-Host "Results will be saved to: $logPath" -ForegroundColor Yellow

# Initialize results
$results = @{
    "Timestamp" = Get-Date
    "ComputerName" = $env:COMPUTERNAME
    "Controls" = @{}
}

# Function to write results
function Write-Result {
    param(
        [string]$Control,
        [string]$Check,
        [string]$Status,
        [string]$Details,
        [string]$Recommendation = ""
    )
    
    $color = switch($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARNING" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "`n[$Control] $Check" -ForegroundColor Cyan
    Write-Host "  Status: $Status" -ForegroundColor $color
    Write-Host "  Details: $Details" -ForegroundColor Gray
    if ($Recommendation) {
        Write-Host "  Recommendation: $Recommendation" -ForegroundColor Yellow
    }
    
    if (-not $results.Controls.ContainsKey($Control)) {
        $results.Controls[$Control] = @()
    }
    $results.Controls[$Control] += @{
        Check = $Check
        Status = $Status
        Details = $Details
        Recommendation = $Recommendation
    }
}

# ====================
# 1. APPLICATION CONTROL
# ====================
Write-Host "`n`n[1/8] CHECKING APPLICATION CONTROL..." -ForegroundColor Magenta

# Check AppLocker status
$appLockerStatus = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($appLockerStatus) {
    if ($appLockerStatus.Status -eq 'Running') {
        Write-Result "Application Control" "AppLocker Service" "PASS" "AppLocker service is running"
    } else {
        Write-Result "Application Control" "AppLocker Service" "FAIL" "AppLocker service is not running" `
            "Start AppLocker: Start-Service AppIDSvc"
    }
} else {
    Write-Result "Application Control" "AppLocker Service" "FAIL" "AppLocker service not found" `
        "Configure AppLocker policies in Group Policy"
}

# Check Windows Defender Application Control
$wdacPolicies = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
if ($wdacPolicies -and $wdacPolicies.CodeIntegrityPolicyEnforcementStatus -eq 2) {
    Write-Result "Application Control" "WDAC" "PASS" "Windows Defender Application Control is enforced"
} else {
    Write-Result "Application Control" "WDAC" "WARNING" "WDAC not fully enforced" `
        "Consider implementing WDAC policies"
}

# ====================
# 2. PATCH APPLICATIONS
# ====================
Write-Host "`n`n[2/8] CHECKING APPLICATION PATCHING..." -ForegroundColor Magenta

# Check installed applications and their versions
$apps = @(
    @{Name="Google Chrome"; Path="HKLM:\SOFTWARE\Google\Chrome\BLBeacon"; VersionKey="version"},
    @{Name="Mozilla Firefox"; Path="HKLM:\SOFTWARE\Mozilla\Mozilla Firefox"; VersionKey="CurrentVersion"},
    @{Name="Adobe Reader"; Path="HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer"; VersionKey="Version"}
)

foreach ($app in $apps) {
    if (Test-Path $app.Path) {
        try {
            $version = (Get-ItemProperty -Path $app.Path -Name $app.VersionKey -ErrorAction Stop).$($app.VersionKey)
            Write-Result "Patch Applications" $app.Name "INFO" "Version: $version" `
                "Ensure latest version is installed"
        } catch {
            Write-Result "Patch Applications" $app.Name "WARNING" "Unable to determine version"
        }
    }
}

# ====================
# 3. CONFIGURE MICROSOFT OFFICE MACRO SETTINGS
# ====================
Write-Host "`n`n[3/8] CHECKING OFFICE MACRO SETTINGS..." -ForegroundColor Magenta

# Check Office macro settings
$officeVersions = @("16.0", "15.0", "14.0")  # Office 2016+, 2013, 2010
$officeApps = @("Word", "Excel", "PowerPoint", "Outlook")

foreach ($version in $officeVersions) {
    foreach ($app in $officeApps) {
        $regPath = "HKCU:\Software\Policies\Microsoft\Office\$version\$app\Security"
        if (Test-Path $regPath) {
            try {
                $vbaWarning = (Get-ItemProperty -Path $regPath -Name "VBAWarnings" -ErrorAction SilentlyContinue).VBAWarnings
                if ($vbaWarning -eq 4) {
                    Write-Result "Office Macros" "$app $version" "PASS" "Macros disabled without notification"
                } elseif ($vbaWarning -eq 3) {
                    Write-Result "Office Macros" "$app $version" "WARNING" "Macros disabled with notification"
                } else {
                    Write-Result "Office Macros" "$app $version" "FAIL" "Macros may be enabled" `
                        "Set VBAWarnings to 3 or 4 via Group Policy"
                }
            } catch {
                continue
            }
        }
    }
}

# ====================
# 4. USER APPLICATION HARDENING
# ====================
Write-Host "`n`n[4/8] CHECKING APPLICATION HARDENING..." -ForegroundColor Magenta

# Check Java settings
$javaPath = "HKLM:\SOFTWARE\JavaSoft\Java Plug-in"
if (Test-Path $javaPath) {
    Write-Result "App Hardening" "Java" "WARNING" "Java browser plugin detected" `
        "Consider removing Java browser plugin if not required"
} else {
    Write-Result "App Hardening" "Java" "PASS" "Java browser plugin not detected"
}

# Check Flash settings
$flashPath = "HKLM:\SOFTWARE\Macromedia\FlashPlayer"
if (Test-Path $flashPath) {
    Write-Result "App Hardening" "Flash" "FAIL" "Flash Player detected - EOL product" `
        "Remove Flash Player immediately"
} else {
    Write-Result "App Hardening" "Flash" "PASS" "Flash Player not detected"
}

# Check browser hardening (Edge)
$edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (Test-Path $edgePath) {
    $smartScreen = (Get-ItemProperty -Path $edgePath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue).SmartScreenEnabled
    if ($smartScreen -eq 1) {
        Write-Result "App Hardening" "Edge SmartScreen" "PASS" "SmartScreen is enabled"
    } else {
        Write-Result "App Hardening" "Edge SmartScreen" "WARNING" "SmartScreen not enforced"
    }
}

# ====================
# 5. RESTRICT ADMINISTRATIVE PRIVILEGES
# ====================
Write-Host "`n`n[5/8] CHECKING ADMINISTRATIVE PRIVILEGES..." -ForegroundColor Magenta

# Get local administrators
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$adminCount = ($admins | Measure-Object).Count

if ($adminCount -gt 3) {
    Write-Result "Admin Privileges" "Local Administrators" "WARNING" "$adminCount administrators found" `
        "Review and minimize administrator accounts"
} else {
    Write-Result "Admin Privileges" "Local Administrators" "PASS" "$adminCount administrators found"
}

# Check UAC settings
$uacReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ($uacReg.EnableLUA -eq 1) {
    Write-Result "Admin Privileges" "UAC" "PASS" "UAC is enabled"
} else {
    Write-Result "Admin Privileges" "UAC" "FAIL" "UAC is disabled" `
        "Enable UAC for better security"
}

# ====================
# 6. PATCH OPERATING SYSTEMS
# ====================
Write-Host "`n`n[6/8] CHECKING OS PATCHING..." -ForegroundColor Magenta

# Check Windows Update settings
$au = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
if ($au -and $au.NoAutoUpdate -eq 0) {
    Write-Result "OS Patching" "Windows Update" "PASS" "Automatic updates enabled"
} else {
    Write-Result "OS Patching" "Windows Update" "WARNING" "Check automatic update settings"
}

# Check last update time
try {
    $lastUpdate = (Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1).InstalledOn
    $daysSinceUpdate = (New-TimeSpan -Start $lastUpdate -End (Get-Date)).Days
    
    if ($daysSinceUpdate -lt 30) {
        Write-Result "OS Patching" "Last Update" "PASS" "Updated $daysSinceUpdate days ago"
    } else {
        Write-Result "OS Patching" "Last Update" "WARNING" "Updated $daysSinceUpdate days ago" `
            "Check for pending updates"
    }
} catch {
    Write-Result "OS Patching" "Last Update" "WARNING" "Unable to determine last update date"
}

# ====================
# 7. MULTI-FACTOR AUTHENTICATION
# ====================
Write-Host "`n`n[7/8] CHECKING MULTI-FACTOR AUTHENTICATION..." -ForegroundColor Magenta

# Check if machine is domain joined
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($domain -ne "WORKGROUP") {
    Write-Result "MFA" "Domain Status" "INFO" "Computer is domain-joined to: $domain" `
        "Ensure MFA is configured at domain level"
} else {
    Write-Result "MFA" "Domain Status" "INFO" "Computer is not domain-joined" `
        "Consider implementing MFA for local accounts"
}

# Check Windows Hello
$helloReg = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
if (Test-Path $helloReg) {
    $helloEnabled = (Get-ItemProperty -Path $helloReg -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    if ($helloEnabled -eq 1) {
        Write-Result "MFA" "Windows Hello" "PASS" "Windows Hello for Business is enabled"
    } else {
        Write-Result "MFA" "Windows Hello" "INFO" "Windows Hello for Business not enforced"
    }
} else {
    Write-Result "MFA" "Windows Hello" "INFO" "Windows Hello policies not configured"
}

# ====================
# 8. REGULAR BACKUPS
# ====================
Write-Host "`n`n[8/8] CHECKING BACKUP CONFIGURATION..." -ForegroundColor Magenta

# Check Windows Backup
$backupFeature = Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction SilentlyContinue
if ($backupFeature -and $backupFeature.InstallState -eq "Installed") {
    Write-Result "Backups" "Windows Backup" "INFO" "Windows Backup feature is installed"
} else {
    # Check File History for Windows 10/11
    $fileHistory = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\fhsvc" -ErrorAction SilentlyContinue
    if ($fileHistory) {
        Write-Result "Backups" "File History" "INFO" "File History service is available" `
            "Ensure File History is configured and running"
    } else {
        Write-Result "Backups" "Backup Solution" "WARNING" "No backup solution detected" `
            "Implement a backup solution"
    }
}

# Check VSS (Volume Shadow Copy)
$vssWriters = vssadmin list writers 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Result "Backups" "VSS" "PASS" "Volume Shadow Copy Service is working"
} else {
    Write-Result "Backups" "VSS" "WARNING" "VSS may have issues"
}

# ====================
# GENERATE REPORT
# ====================
Write-Host "`n`n===== GENERATING COMPLIANCE REPORT =====" -ForegroundColor Cyan

# Create HTML report
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Essential Eight Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #003366; border-bottom: 3px solid #FFD700; padding-bottom: 10px; }
        h2 { color: #003366; margin-top: 30px; }
        .info { background-color: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #003366; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .info-status { color: blue; font-weight: bold; }
        .recommendation { background-color: #fffacd; padding: 5px; border-left: 3px solid orange; margin-top: 5px; }
    </style>
</head>
<body>
    <h1>Australia Essential Eight Compliance Report</h1>
    <div class="info">
        <strong>Computer:</strong> $($results.ComputerName)<br>
        <strong>Date:</strong> $($results.Timestamp)<br>
        <strong>Generated by:</strong> Essential Eight Compliance Audit Script v1.0
    </div>
"@

$controlNames = @{
    "Application Control" = "1. Application Control"
    "Patch Applications" = "2. Patch Applications"
    "Office Macros" = "3. Configure Microsoft Office Macro Settings"
    "App Hardening" = "4. User Application Hardening"
    "Admin Privileges" = "5. Restrict Administrative Privileges"
    "OS Patching" = "6. Patch Operating Systems"
    "MFA" = "7. Multi-Factor Authentication"
    "Backups" = "8. Regular Backups"
}

foreach ($control in $controlNames.Keys) {
    if ($results.Controls.ContainsKey($control)) {
        $html += "<h2>$($controlNames[$control])</h2>"
        $html += "<table>"
        $html += "<tr><th>Check</th><th>Status</th><th>Details</th><th>Recommendation</th></tr>"
        
        foreach ($check in $results.Controls[$control]) {
            $statusClass = switch($check.Status) {
                "PASS" { "pass" }
                "FAIL" { "fail" }
                "WARNING" { "warning" }
                "INFO" { "info-status" }
                default { "" }
            }
            
            $html += "<tr>"
            $html += "<td>$($check.Check)</td>"
            $html += "<td class='$statusClass'>$($check.Status)</td>"
            $html += "<td>$($check.Details)</td>"
            $html += "<td>$($check.Recommendation)</td>"
            $html += "</tr>"
        }
        
        $html += "</table>"
    }
}

$html += @"
    <div class="info" style="margin-top: 40px;">
        <h3>Next Steps:</h3>
        <ol>
            <li>Review all FAIL and WARNING items</li>
            <li>Implement recommendations based on your organization's risk profile</li>
            <li>Consider maturity levels (ML1, ML2, ML3) for each control</li>
            <li>Consult ACSC guidance at <a href="https://www.cyber.gov.au/acsc/view-all-content/essential-eight">cyber.gov.au</a></li>
            <li>Run this audit regularly to track compliance progress</li>
        </ol>
    </div>
</body>
</html>
"@

# Save HTML report
$html | Out-File -FilePath "$logPath\Essential8_Report.html" -Encoding UTF8

# Save JSON report
$results | ConvertTo-Json -Depth 4 | Out-File -FilePath "$logPath\Essential8_Report.json" -Encoding UTF8

# ====================
# SUMMARY
# ====================
Write-Host "`n`n===== AUDIT COMPLETE =====" -ForegroundColor Green
Write-Host "Reports saved to: $logPath" -ForegroundColor Yellow
Write-Host "`nFiles generated:" -ForegroundColor Cyan
Write-Host "  - Essential8_Report.html (Open in browser for formatted view)" -ForegroundColor White
Write-Host "  - Essential8_Report.json (Machine-readable format)" -ForegroundColor White
Write-Host "  - audit_log.txt (Full transcript)" -ForegroundColor White

# Open HTML report
Start-Process "$logPath\Essential8_Report.html"

Stop-Transcript

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
