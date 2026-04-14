<#
.SYNOPSIS
    Windows Security Hardening Script
.DESCRIPTION
    Audits Windows systems against security best practices and applies fixes.
    Checks Windows Updates, Firewall, UAC, Antivirus, Password Policy, and more.
.PARAMETER Apply
    Apply fixes automatically (Audit only by default)
.PARAMETER Output
    Output file for the report (JSON format)
.PARAMETER SkipReboot
    Skip reboot prompt after fixes
.EXAMPLE
    .\windows_hardening.ps1                    # Audit only
    .\windows_hardening.ps1 -Apply             # Audit and apply fixes
    .\windows_hardening.ps1 -Apply -SkipReboot # Apply fixes without reboot prompt
.NOTES
    Author: Joshua Guda
    Requires: PowerShell 5.1 or higher, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Apply,
    
    [Parameter(Mandatory=$false)]
    [string]$Output = "windows_hardening_report.json",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReboot
)

#region Functions

# Color functions for console output
function Write-Success { 
    Write-Host "[✓] $($args[0])" -ForegroundColor Green 
}

function Write-Failure { 
    Write-Host "[✗] $($args[0])" -ForegroundColor Red 
}

function Write-Warning { 
    Write-Host "[!] $($args[0])" -ForegroundColor Yellow 
}

function Write-Info { 
    Write-Host "[*] $($args[0])" -ForegroundColor Cyan 
}

function Write-Header { 
    Write-Host "`n$($args[0])" -ForegroundColor Magenta -BackgroundColor Black
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Generic test function
function Test-SecurityConfig {
    param($Name, $Check, $Fix, $Points, $Category)
    
    Write-Info "Checking $Name..."
    
    $result = & $Check
    
    if ($result -eq $true) {
        Write-Success "$Name - PASSED"
        $global:results["Passed"] += @{Name=$Name; Category=$Category}
    } else {
        Write-Failure "$Name - FAILED"
        $global:score -= $Points
        $global:results["Failed"] += @{Name=$Name; Category=$Category; Points=$Points}
        
        if ($Apply -and $Fix) {
            Write-Warning "Applying fix for $Name..."
            try {
                & $Fix
                $global:results["Remediations"] += @{Name=$Name; Status="Applied"}
                Write-Success "  Fix applied successfully"
            } catch {
                Write-Failure "  Failed to apply fix: $_"
                $global:results["Remediations"] += @{Name=$Name; Status="Failed"; Error=$_.ToString()}
            }
        } else {
            $global:results["Remediations"] += @{Name=$Name; Status="Manual fix required"}
        }
    }
}

#endregion

#region Security Checks

# Check 1: Windows Updates
function Check-WindowsUpdates {
    Write-Info "  Checking Windows Update status..."
    
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
        
        if ($HistoryCount -gt 0) {
            $LastUpdate = $UpdateSearcher.QueryHistory(0, 1) | Select-Object -First 1
            $DaysSince = ((Get-Date) - $LastUpdate.Date).Days
            
            if ($DaysSince -le 30) {
                Write-Info "  Last update: $($DaysSince) days ago (OK)"
                return $true
            } else {
                Write-Warning "  Last update: $($DaysSince) days ago"
                return $false
            }
        }
        return $false
    } catch {
        Write-Warning "  Could not check update status: $_"
        return $false
    }
}

function Fix-WindowsUpdates {
    Write-Info "  Starting Windows Update..."
    Start-Process "ms-settings:windowsupdate"
    Write-Warning "  Please install updates manually when the Settings window opens"
}

# Check 2: Windows Firewall
function Check-Firewall {
    $Profiles = Get-NetFirewallProfile
    $EnabledCount = ($Profiles | Where-Object {$_.Enabled -eq $true}).Count
    $result = $EnabledCount -eq 3
    
    if ($result) {
        Write-Info "  All firewall profiles are enabled"
    } else {
        Write-Warning "  Only $EnabledCount/3 firewall profiles are enabled"
    }
    return $result
}

function Fix-Firewall {
    Set-NetFirewallProfile -All -Enabled True
    Write-Success "  Firewall enabled for all profiles"
}

# Check 3: UAC (User Account Control)
function Check-UAC {
    $UAC = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    $enabled = $UAC.EnableLUA -eq 1
    $level = $UAC.ConsentPromptBehaviorAdmin -eq 2  # 2 = Always notify
    
    if ($enabled -and $level) {
        Write-Info "  UAC is enabled with 'Always notify' level"
        return $true
    } elseif ($enabled) {
        Write-Warning "  UAC is enabled but not at highest level"
        return $false
    } else {
        Write-Warning "  UAC is disabled"
        return $false
    }
}

function Fix-UAC {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    Write-Success "  UAC configured to highest level (Always notify)"
}

# Check 4: Windows Defender
function Check-Antivirus {
    try {
        $AV = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($AV) {
            $enabled = $AV.AntivirusEnabled -eq $true
            $realTime = $AV.RealTimeProtectionEnabled -eq $true
            $definitions = $AV.AntivirusSignatureVersion
            
            if ($enabled -and $realTime) {
                Write-Info "  Windows Defender is active (Signatures: $definitions)"
                return $true
            } else {
                Write-Warning "  Windows Defender issues: Enabled=$enabled, RealTime=$realTime"
                return $false
            }
        }
        return $false
    } catch {
        Write-Warning "  Could not check Windows Defender status"
        return $false
    }
}

function Fix-Antivirus {
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Update-MpSignature -ErrorAction SilentlyContinue
        Write-Success "  Windows Defender real-time protection enabled"
    } catch {
        Write-Warning "  Please enable Windows Defender manually"
    }
}

# Check 5: Password Policy
function Check-PasswordPolicy {
    try {
        $Policy = net accounts 2>$null
        $MinLengthMatch = [regex]::Match($Policy, "Minimum password length\s*=\s*(\d+)")
        $MaxAgeMatch = [regex]::Match($Policy, "Maximum password age\s*=\s*(\d+)")
        
        if ($MinLengthMatch.Success) {
            $MinLength = [int]$MinLengthMatch.Groups[1].Value
            $MinLengthOk = $MinLength -ge 8
            
            if ($MaxAgeMatch.Success) {
                $MaxAge = [int]$MaxAgeMatch.Groups[1].Value
                $MaxAgeOk = ($MaxAge -le 90) -or ($MaxAge -eq 0 -and $MaxAgeMatch.Value -notcontains "unlimited")
                
                Write-Info "  Password policy: MinLength=$MinLength, MaxAge=$MaxAge days"
                return ($MinLengthOk -and $MaxAgeOk)
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Fix-PasswordPolicy {
    net accounts /minpwlen:8 2>$null
    net accounts /maxpwage:90 2>$null
    Write-Success "  Password minimum length set to 8, maximum age to 90 days"
}

# Check 6: Guest Account
function Check-GuestAccount {
    try {
        $Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        $disabled = $Guest.Enabled -eq $false
        if ($disabled) {
            Write-Info "  Guest account is disabled"
        } else {
            Write-Warning "  Guest account is enabled (security risk)"
        }
        return $disabled
    } catch {
        Write-Warning "  Could not check Guest account status"
        return $true  # Assume disabled if can't check
    }
}

function Fix-GuestAccount {
    Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    Write-Success "  Guest account disabled"
}

# Check 7: Built-in Administrator Account
function Check-AdminAccount {
    try {
        $Admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        $disabled = $Admin.Enabled -eq $false
        if ($disabled) {
            Write-Info "  Built-in Administrator account is disabled"
        } else {
            Write-Warning "  Built-in Administrator account is enabled (use named admin accounts instead)"
        }
        return $disabled
    } catch {
        return $true
    }
}

function Fix-AdminAccount {
    Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Write-Success "  Built-in Administrator account disabled"
}

# Check 8: RDP
function Check-RDP {
    try {
        $RDP = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
        $disabled = $RDP.fDenyTSConnections -eq 1
        if ($disabled) {
            Write-Info "  RDP is disabled"
        } else {
            Write-Warning "  RDP is enabled (ensure Network Level Authentication is required)"
        }
        return $disabled
    } catch {
        return $true
    }
}

function Fix-RDP {
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    Write-Success "  RDP disabled"
}

# Check 9: PowerShell Logging
function Check-PSLogging {
    try {
        $Logging = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        $enabled = $Logging.EnableScriptBlockLogging -eq 1
        if ($enabled) {
            Write-Info "  PowerShell script block logging is enabled"
        } else {
            Write-Warning "  PowerShell script block logging is disabled (important for security monitoring)"
        }
        return $enabled
    } catch {
        return $false
    }
}

function Fix-PSLogging {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Name "ScriptBlockLogging" -Force -ErrorAction SilentlyContinue
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
    Write-Success "  PowerShell script block logging enabled"
}

# Check 10: SMB1 Protocol
function Check-SMB1 {
    try {
        $SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        $disabled = $SMB1.State -eq "Disabled"
        if ($disabled) {
            Write-Info "  SMB1 protocol is disabled"
        } else {
            Write-Warning "  SMB1 protocol is enabled (vulnerable to EternalBlue and other exploits)"
        }
        return $disabled
    } catch {
        return $true
    }
}

function Fix-SMB1 {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
    Write-Success "  SMB1 protocol disabled (restart required for complete removal)"
    $global:rebootRequired = $true
}

# Check 11: Audit Policy
function Check-AuditPolicy {
    try {
        $Audit = auditpol /get /category:"Logon/Logoff" 2>$null
        $hasLogon = $Audit -match "Logon\s+Success and Failure"
        $hasLogoff = $Audit -match "Logoff\s+Success"
        
        if ($hasLogon -and $hasLogoff) {
            Write-Info "  Audit policy is configured for Logon/Logoff events"
            return $true
        } else {
            Write-Warning "  Audit policy is not fully configured"
            return $false
        }
    } catch {
        return $false
    }
}

function Fix-AuditPolicy {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
    auditpol /set /subcategory:"Logoff" /success:enable /failure:disable 2>$null
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable 2>$null
    Write-Success "  Audit policy configured for Logon/Logoff events"
}

# Check 12: Network Discovery
function Check-NetworkDiscovery {
    try {
        $ND = Get-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled -ErrorAction SilentlyContinue
        $disabled = ($ND | Measure-Object).Count -eq 0
        if ($disabled) {
            Write-Info "  Network discovery is disabled"
        } else {
            Write-Warning "  Network discovery is enabled (can expose system information)"
        }
        return $disabled
    } catch {
        return $true
    }
}

function Fix-NetworkDiscovery {
    Get-NetFirewallRule -DisplayGroup "Network Discovery" | Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Success "  Network discovery disabled"
}

# Check 13: LM/NTLMv1 Authentication
function Check-LMHash {
    try {
        $LM = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue
        $disabled = $LM.NoLMHash -eq 1
        if ($disabled) {
            Write-Info "  LM hash storage is disabled"
        } else {
            Write-Warning "  LM hash storage is enabled (weak authentication)"
        }
        return $disabled
    } catch {
        return $false
    }
}

function Fix-LMHash {
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
    Write-Success "  LM hash storage disabled"
}

# Check 14: Anonymous Share Access
function Check-AnonymousAccess {
    try {
        $Restrict = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
        $restricted = $Restrict.RestrictAnonymous -ge 1
        if ($restricted) {
            Write-Info "  Anonymous access is restricted"
        } else {
            Write-Warning "  Anonymous access is not restricted"
        }
        return $restricted
    } catch {
        return $false
    }
}

function Fix-AnonymousAccess {
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
    Write-Success  " Anonymous access restricted"
}

# Check 15: AutoPlay/AutoRun
function Check-AutoPlay {
    try {
        $AutoPlay = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
        $disabled = $AutoPlay.NoDriveTypeAutoRun -eq 255
        if ($disabled) {
            Write-Info "  AutoPlay is disabled"
        } else {
            Write-Warning "  AutoPlay is enabled (can spread malware via USB drives)"
        }
        return $disabled
    } catch {
        return $false
    }
}

function Fix-AutoPlay {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
    Write-Success "  AutoPlay disabled"
}

#endregion

#region Main Execution

# Initialize results
$results = @{
    "Passed" = @()
    "Failed" = @()
    "Warnings" = @()
    "Remediations" = @()
}
$score = 100
$rebootRequired = $false

# Check for Administrator privileges
if (-not (Test-Administrator)) {
    Write-Failure "This script requires Administrator privileges!"
    Write-Warning "Please run PowerShell as Administrator and try again."
    exit 1
}

# Header
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  WINDOWS SECURITY HARDENING TOOL" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Mode: $(if ($Apply) {'Audit & Apply'} else {'Audit Only'})" -ForegroundColor Yellow
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "User: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Time: $(Get-Date)" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Run all checks
Write-Header "SYSTEM CONFIGURATION CHECKS"
Test-SecurityConfig -Name "Windows Updates" -Check {Check-WindowsUpdates} -Fix {Fix-WindowsUpdates} -Points 15 -Category "System Maintenance"
Test-SecurityConfig -Name "Windows Firewall" -Check {Check-Firewall} -Fix {Fix-Firewall} -Points 15 -Category "Network Security"
Test-SecurityConfig -Name "UAC Enabled" -Check {Check-UAC} -Fix {Fix-UAC} -Points 10 -Category "User Access Control"

Write-Header "ENDPOINT PROTECTION"
Test-SecurityConfig -Name "Windows Defender" -Check {Check-Antivirus} -Fix {Fix-Antivirus} -Points 15 -Category "Endpoint Protection"

Write-Header "ACCOUNT SECURITY"
Test-SecurityConfig -Name "Password Policy" -Check {Check-PasswordPolicy} -Fix {Fix-PasswordPolicy} -Points 10 -Category "Account Security"
Test-SecurityConfig -Name "Guest Account Disabled" -Check {Check-GuestAccount} -Fix {Fix-GuestAccount} -Points 5 -Category "Account Security"
Test-SecurityConfig -Name "Admin Account Disabled" -Check {Check-AdminAccount} -Fix {Fix-AdminAccount} -Points 5 -Category "Account Security"

Write-Header "NETWORK SECURITY"
Test-SecurityConfig -Name "RDP Disabled" -Check {Check-RDP} -Fix {Fix-RDP} -Points 10 -Category "Network Security"
Test-SecurityConfig -Name "SMB1 Disabled" -Check {Check-SMB1} -Fix {Fix-SMB1} -Points 10 -Category "Network Security"
Test-SecurityConfig -Name "Network Discovery Disabled" -Check {Check-NetworkDiscovery} -Fix {Fix-NetworkDiscovery} -Points 5 -Category "Network Security"

Write-Header "AUDIT & MONITORING"
Test-SecurityConfig -Name "PowerShell Logging" -Check {Check-PSLogging} -Fix {Fix-PSLogging} -Points 5 -Category "Audit & Monitoring"
Test-SecurityConfig -Name "Audit Policy" -Check {Check-AuditPolicy} -Fix {Fix-AuditPolicy} -Points 5 -Category "Audit & Monitoring"

Write-Header "ADDITIONAL HARDENING"
Test-SecurityConfig -Name "LM Hash Storage Disabled" -Check {Check-LMHash} -Fix {Fix-LMHash} -Points 5 -Category "Authentication"
Test-SecurityConfig -Name "Anonymous Access Restricted" -Check {Check-AnonymousAccess} -Fix {Fix-AnonymousAccess} -Points 5 -Category "Network Security"
Test-SecurityConfig -Name "AutoPlay Disabled" -Check {Check-AutoPlay} -Fix {Fix-AutoPlay} -Points 5 -Category "System Security"

# Calculate final score (ensure not negative)
$score = [Math]::Max(0, $score)

# Determine rating
if ($score -ge 90) { $rating = "EXCELLENT" }
elseif ($score -ge 75) { $rating = "GOOD" }
elseif ($score -ge 60) { $rating = "FAIR" }
else { $rating = "POOR" }

# Generate Report
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  HARDENING REPORT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SCORE: $score/100" -ForegroundColor $(if ($score -ge 80) {"Green"} elseif ($score -ge 60) {"Yellow"} else {"Red"})
Write-Host "RATING: $rating" -ForegroundColor $(if ($rating -eq "EXCELLENT") {"Green"} elseif ($rating -eq "GOOD") {"Yellow"} else {"Red"})

Write-Host "`nPASSED CHECKS: $($results["Passed"].Count)" -ForegroundColor Green
$results["Passed"] | ForEach-Object { Write-Host "  ✓ $($_.Name) [$($_.Category)]" -ForegroundColor Gray }

if ($results["Failed"].Count -gt 0) {
    Write-Host "`nFAILED CHECKS: $($results["Failed"].Count)" -ForegroundColor Red
    $results["Failed"] | ForEach-Object { Write-Host "  ✗ $($_.Name) [$($_.Category)] (-$($_.Points) points)" -ForegroundColor Red }
}

if ($results["Remediations"].Count -gt 0) {
    Write-Host "`nREMEDIATIONS:" -ForegroundColor Yellow
    $results["Remediations"] | ForEach-Object { 
        if ($_.Status -eq "Applied") {
            Write-Host "  ✓ $($_.Name): Applied" -ForegroundColor Green
        } else {
            Write-Host "  ! $($_.Name): $($_.Status)" -ForegroundColor Yellow
        }
    }
}

# Save report to JSON
$report = @{
    "Timestamp" = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "ComputerName" = $env:COMPUTERNAME
    "Score" = $score
    "Rating" = $rating
    "Mode" = if ($Apply) {"Audit & Apply"} else {"Audit Only"}
    "Passed" = $results["Passed"]
    "Failed" = $results["Failed"]
    "Remediations" = $results["Remediations"]
    "RebootRequired" = $rebootRequired
}

try {
    $report | ConvertTo-Json -Depth 10 | Out-File $Output -Encoding UTF8
    Write-Host "`nReport saved to $Output" -ForegroundColor Cyan
} catch {
    Write-Warning "Could not save report to $Output : $_"
}

# Reboot prompt if needed
if ($rebootRequired -and -not $SkipReboot) {
    Write-Warning "`nA reboot is required to complete some changes."
    $response = Read-Host "Reboot now? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Restart-Computer -Force
    }
}

if (-not $Apply) {
    Write-Host "`nRun with -Apply to automatically fix issues where possible." -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  HARDENING COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

#endregion
