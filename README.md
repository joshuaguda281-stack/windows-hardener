# Windows Hardener - Security Configuration Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Platform](https://img.shields.io/badge/platform-Windows-blue)](https://microsoft.com/windows)

A comprehensive Windows security hardening script that audits and configures systems against security best practices. Based on CIS benchmarks and Microsoft security recommendations.

## 🚀 Features

### Security Checks (15 total)

| Category | Checks | Points |
|----------|--------|--------|
| **System Maintenance** | Windows Updates | 15 |
| **Network Security** | Firewall, RDP, SMB1, Network Discovery, Anonymous Access | 35 |
| **User Access Control** | UAC Configuration | 10 |
| **Endpoint Protection** | Windows Defender | 15 |
| **Account Security** | Password Policy, Guest Account, Admin Account | 20 |
| **Audit & Monitoring** | PowerShell Logging, Audit Policy | 10 |
| **Authentication** | LM Hash Storage | 5 |
| **System Security** | AutoPlay | 5 |

### What Gets Checked

- ✅ Windows Update status (last 30 days)
- ✅ Firewall profiles (Domain, Private, Public)
- ✅ UAC level (Always notify)
- ✅ Windows Defender (Real-time protection)
- ✅ Password policy (minimum length 8, max age 90 days)
- ✅ Guest account (disabled)
- ✅ Built-in Administrator account (disabled)
- ✅ RDP (disabled)
- ✅ PowerShell script block logging
- ✅ SMB1 protocol (disabled)
- ✅ Audit policy (Logon/Logoff events)
- ✅ Network discovery (disabled)
- ✅ LM hash storage (disabled)
- ✅ Anonymous share access (restricted)
- ✅ AutoPlay (disabled)

## 📋 Requirements

- **Windows 10/11** or **Windows Server 2016+**
- **PowerShell 5.1** or higher
- **Administrator privileges**

## 🔧 Installation

```powershell
# Clone the repository
git clone https://github.com/YOUR_USERNAME/windows-hardener.git
cd windows-hardener

# Or download the script directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/windows-hardener/main/windows_hardening.ps1" -OutFile "windows_hardening.ps1"


💻 Usage
Audit Only (Recommended First)
# Open PowerShell as Administrator
# Navigate to script directory
cd C:\path\to\windows-hardener

# Run audit (no changes made)
.\windows_hardening.ps1

Audit and Apply Fixes

# Run with automatic fixes
.\windows_hardening.ps1 -Apply

# Skip reboot prompt
.\windows_hardening.ps1 -Apply -SkipReboot

# Save report to custom location
.\windows_hardening.ps1 -Apply -Output "C:\Reports\hardening.json"

📊 Sample Output

========================================
  WINDOWS SECURITY HARDENING TOOL
========================================
Mode: Audit Only
Computer: DESKTOP-ABC123
User: Administrator
Time: 01/15/2024 14:30:00
========================================

SYSTEM CONFIGURATION CHECKS
[*] Checking Windows Updates...
  Last update: 5 days ago (OK)
[✓] Windows Updates - PASSED

[*] Checking Windows Firewall...
  All firewall profiles are enabled
[✓] Windows Firewall - PASSED

[*] Checking UAC Enabled...
  UAC is enabled with 'Always notify' level
[✓] UAC Enabled - PASSED

ENDPOINT PROTECTION
[*] Checking Windows Defender...
  Windows Defender is active (Signatures: 1.391.1234.0)
[✓] Windows Defender - PASSED

========================================
  HARDENING REPORT
========================================
SCORE: 95/100
RATING: EXCELLENT

PASSED CHECKS: 12
  ✓ Windows Updates [System Maintenance]
  ✓ Windows Firewall [Network Security]
  ✓ UAC Enabled [User Access Control]
  ✓ Windows Defender [Endpoint Protection]

FAILED CHECKS: 3
  ✗ PowerShell Logging [Audit & Monitoring] (-5 points)
  ✗ Audit Policy [Audit & Monitoring] (-5 points)
  ✗ SMB1 Disabled [Network Security] (-10 points)

Run with -Apply to automatically fix issues where possible.


📁 Report Format
The script generates a JSON report:

{
    "Timestamp": "2024-01-15 14:35:00",
    "ComputerName": "DESKTOP-ABC123",
    "Score": 95,
    "Rating": "EXCELLENT",
    "Mode": "Audit Only",
    "Passed": [
        {"Name": "Windows Updates", "Category": "System Maintenance"},
        {"Name": "Windows Firewall", "Category": "Network Security"}
    ],
    "Failed": [
        {"Name": "SMB1 Disabled", "Category": "Network Security", "Points": 10}
    ],
    "RebootRequired": true
}


🎯 Use Cases
New System Deployment - Harden fresh Windows installations

Compliance Auditing - Verify security configurations

Incident Response - Remediate compromised systems

Regular Maintenance - Monthly security checks

CIS Benchmark Compliance - Meet security standards

📋 CIS Benchmark Mapping
Check	CIS Control
Windows Updates	1.1 - Ensure 'Configure Automatic Updates' is set
Windows Firewall	9.2 - Ensure 'Windows Firewall: Domain' is configured
UAC	2.3 - Ensure 'User Account Control: Admin Approval Mode'
Password Policy	1.1 - Password Policy settings
SMB1	18.5 - Disable SMB v1 protocol
PowerShell Logging	17.7 - Enable PowerShell Script Block Logging
🔧 Troubleshooting
Issue	Solution
"Access Denied"	Run PowerShell as Administrator
Script not running	Set execution policy: Set-ExecutionPolicy RemoteSigned
Windows Defender not found	Script works with any antivirus, but alerts will show
Report not saving	Check write permissions on output directory
📝 License
MIT License - See LICENSE file for details.

👤 Author
Joshua Guda

GitHub: @joshuaguda281-stack

LinkedIn: Joshua Guda

🙏 Acknowledgments
CIS (Center for Internet Security) for benchmarks

Microsoft for security baselines

NIST for cybersecurity framework

⭐ Support
If this script helps you secure Windows systems, please star the repository!



