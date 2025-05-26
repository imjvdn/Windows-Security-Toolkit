<div align="center">
  <h1>🛡️ Windows Security Toolkit</h1>
  <p>A comprehensive PowerShell module for security analysis, auditing, and incident response on Windows systems.</p>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![GitHub stars](https://img.shields.io/github/stars/imjvdn/Windows-Security-Toolkit?style=social)](https://github.com/imjvdn/Windows-Security-Toolkit/stargazers)
</div>

## Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [How to Use This Toolkit](#-how-to-use-this-toolkit)
  - [Ready-to-Use Security Scripts](#1-ready-to-use-security-scripts)
  - [PowerShell Module (Advanced)](#2-powershell-module-advanced)
- [Documentation](#-documentation)
  - [Security Command References](#security-command-references)
  - [Guides & Tutorials](#guides--tutorials)
- [Security Scripts](#-security-scripts)
  - [Audit Tools](#audit-tools)
  - [Reporting Tools](#reporting-tools)
- [PowerShell Module](#-powershell-module)
- [Testing](#-testing)
  - [Running Tests](#running-tests)
  - [Test Structure](#test-structure)
- [Advanced Usage](#-advanced-usage)
- [Security Commands Reference](#-security-commands-reference)
- [Additional Resources](#-additional-resources)
- [License](#-license)

## 🎯 Features

- **Comprehensive Auditing**: Collect system, user, and network security information
- **Security Compliance**: Evaluate systems against CIS and NIST benchmarks
- **Interactive Visualizations**: Dynamic dashboards and reports for security analysis
- **Easy to Use**: Simple, intuitive cmdlets for security professionals
- **Detailed Reporting**: Multiple output formats for analysis and documentation
- **Extensible**: Modular design for adding new security checks

## 🚀 Quick Start

```powershell
# Clone the repository
git clone https://github.com/imjvdn/Windows-Security-Toolkit.git
cd Windows-Security-Toolkit

# Run the example script
.\examples\Run-SecurityAudit.ps1
```

## 📚 Documentation

#### Security Command References
- 🏢 [Active Directory Security](docs/ad-security.md) - Comprehensive AD auditing and security commands
- 📧 [Exchange Online Security](docs/exchange-security.md) - Exchange Online security auditing commands
- 🔐 [Windows Security](docs/windows-security.md) - Local Windows system security commands

#### Guides & Tutorials
- 🔍 [Incident Response Guide](docs/incident-response.md) - Step-by-step incident response procedures

<details>
<summary>🔍 Cmdlets</summary>

### Get-SystemSecurityAudit

```powershell
Get-SystemSecurityAudit [-OutputDirectory <String>]
```

Performs a comprehensive security audit of the system, collecting information about:
- System configuration
- User accounts and permissions
- Network settings and connections
- Running processes and services
- Installed software and updates
- Security settings and policies

#### Output Files

The function creates the following CSV files in the output directory:
- SystemInfo.csv
- UserAccounts.csv
- NetworkConfig.csv
- RunningProcesses.csv
- InstalledSoftware.csv
- SecuritySettings.csv

</details>

## 💼 How to Use This Toolkit

This toolkit provides two ways to perform security audits and generate reports:

### 1. Ready-to-Use Security Scripts

The easiest way to get started is to use our ready-made security scripts in the `scripts/` directory:

```powershell
# Navigate to the scripts directory
cd scripts/audit-tools

# Run a comprehensive system audit
.\Complete-SystemAudit.ps1

# Or run a focused user account audit
.\Audit-UserAccounts.ps1
```

### 2. PowerShell Module (Advanced)

For advanced users or integration into existing tools, you can use the PowerShell module in the `src/` directory:

```powershell
# Import the module
Import-Module .\src\WindowsSecurityToolkit.psd1

# Run the main audit function
Get-SystemSecurityAudit -OutputDirectory "C:\SecurityAudit"
```

## 💼 Security Scripts

### Audit Tools

The `scripts/audit-tools/` directory contains specialized security audit scripts for targeted assessments:

- **Complete-SystemAudit.ps1**: Comprehensive system-wide security audit
- **Audit-UserAccounts.ps1**: Focused audit of user accounts and permissions
- **Audit-NetworkSecurity.ps1**: Network configuration and security assessment
- **Audit-SecurityCompliance.ps1**: Evaluates system against CIS and NIST security benchmarks

### Reporting Tools

The `scripts/reporting-tools/` directory contains tools for generating professional reports from audit data:

- **Convert-AuditToHtmlReport.ps1**: Creates interactive HTML reports with filtering and search
- **Generate-ExecutiveSummary.ps1**: Produces executive summaries with key findings and recommendations
- **Convert-AuditToDashboard.ps1**: Generates an interactive security dashboard with visualizations

## 💻 PowerShell Module

The `src/` directory contains the PowerShell module that powers this toolkit:

- **WindowsSecurityToolkit.psd1**: Module manifest file
- **WindowsSecurityToolkit.psm1**: Module script file
- **Public/Get-SystemSecurityAudit.ps1**: Main security audit function

## 🚨 Testing

The toolkit includes Pester tests to verify functionality and ensure code quality. The tests are located in the `tests/` directory.

### Running Tests

To run the tests, use the included test runner script:

```powershell
# Navigate to the tests directory
cd tests

# Run all tests
.\Run-Tests.ps1
```

### Test Structure

- **WindowsSecurityToolkit.Module.Tests.ps1**: Tests for module structure and exports
- **Get-SystemSecurityAudit.Tests.ps1**: Tests for the main audit function
- **environment/TestSetup.ps1**: Sets up the test environment

### Adding New Tests

When adding new functionality to the toolkit, please also add corresponding tests to maintain code quality.

## 🔧 Advanced Usage

<details>
<summary>Advanced Usage Details</summary>

### Importing the Module
```powershell
# Import the module from the source directory
Import-Module .\src\WindowsSecurityToolkit.psd1 -Force -Verbose

# Check available commands
Get-Command -Module WindowsSecurityToolkit
```

### Running Specific Audits
```powershell
# Audit only user accounts
$outputDir = "C:\SecurityAudit"
$userAccountsFile = Join-Path -Path $outputDir -ChildPath "UserAccounts.csv"

# Get all local users
Get-LocalUser | Export-Csv -Path $userAccountsFile -NoTypeInformation

# View the results
Import-Csv -Path $userAccountsFile | Format-Table -AutoSize
```

### Basic Audit with Default Settings
```powershell
# Run the audit with default settings
Get-SystemSecurityAudit
```

### Custom Output Directory
```powershell
# Specify a custom output directory
Get-SystemSecurityAudit -OutputDirectory "C:\SecurityAudit"
```

### Run as Administrator
For best results, run the toolkit with administrative privileges:
```powershell
# Start a new PowerShell session as Administrator
Start-Process powershell -Verb RunAs -ArgumentList "-Command Import-Module .\src\WindowsSecurityToolkit.psd1; Get-SystemSecurityAudit"
```

</details>

<details>
<summary>🛠️ Development</summary>

### Development Setup
1. Clone the repository
```powershell
git clone https://github.com/imjvdn/Windows-Security-Toolkit.git
cd Windows-Security-Toolkit
```

2. Install required modules
```powershell
# Install Pester for testing
Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser

# Install PSScriptAnalyzer for linting
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
```

</details>

## 🔍 Security Commands Reference

<details>
<summary>Basic System Information Commands</summary>

### View System Information
```powershell
# Get basic system information
systeminfo | Select-String "OS", "System"
```

### Check Uptime
```powershell
# Check system uptime
(Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
```
</details>

<details>
<summary>User Management Commands</summary>

### List All Users
```powershell
# List all user accounts
Get-LocalUser | Format-Table Name, Enabled, LastLogon
```

### View Local Administrators
```powershell
# List members of the Administrators group
Get-LocalGroupMember -Group "Administrators"
```

### Check Logged In Users
```powershell
# See currently logged in users
query user
```
</details>

<details>
<summary>Network Commands</summary>

### View Active Connections
```powershell
# List active network connections
Get-NetTCPConnection -State Established | Format-Table -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```

### Check Firewall Status
```powershell
# Check Windows Firewall status
Get-NetFirewallProfile | Format-Table Name, Enabled
```

### Flush DNS Cache
```powershell
# Clear DNS resolver cache
Clear-DnsClientCache
```
</details>

<details>
<summary>System Inspection Commands</summary>

### List Running Processes
```powershell
# View all running processes
Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20
```

### View Installed Software
```powershell
# List installed applications
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```

### Check Startup Programs
```powershell
# See what programs run at startup
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
```
</details>

<details>
<summary>Security Check Commands</summary>

### View Installed Updates
```powershell
# List installed Windows updates
Get-HotFix | Sort-Object -Property InstalledOn -Descending
```

### Check Scheduled Tasks
```powershell
# View scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State
```

### View Shared Folders
```powershell
# List network shares
Get-SmbShare
```
</details>

## 📦 One-Click Security Audit

Run this in PowerShell for a quick system check:
```powershell
Write-Host "=== SECURITY CHECK ===" -ForegroundColor Cyan; `
Write-Host "`n[+] Users:" -ForegroundColor Green; net user; `
Write-Host "`n[+] Local Admins:" -ForegroundColor Green; net localgroup administrators; `
Write-Host "`n[+] Active Connections:" -ForegroundColor Green; netstat -ano | findstr ESTABLISHED; `
Write-Host "`n[+] Firewall Status:" -ForegroundColor Green; netsh advfirewall show allprofiles; `
Write-Host "`n[+] System Uptime:" -ForegroundColor Green; systeminfo | find "System Boot Time:"
```

## 🔐 Registry Security

<details>
<summary>Registry Security Commands</summary>

### Check AutoRun Entries
```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Check Suspicious Registry Paths
```powershell
# Common persistence locations
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Taskman
```

### Check for Suspicious Services
```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s | findstr /i "ImagePath" | findstr /v /i "system32"
```

### Check for AlwaysInstallElevated (Potential Privilege Escalation)
```powershell
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
```

### Check for Unquoted Service Paths
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

### Check for Weak Registry Permissions
```powershell
# Check permissions on sensitive registry keys
icacls "C:\Windows\System32\config\SAM"
icacls "C:\Windows\System32\config\SECURITY"
```
</details>

## 📝 Notes
- Run as Administrator for best results
- Commands work on Windows 7/10/11 and Server 2008R2+
- For detailed output, remove the `findstr` filters

## 📚 Additional Resources
- [Microsoft Docs](https://docs.microsoft.com)
- [SS64 Command Reference](https://ss64.com/)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
