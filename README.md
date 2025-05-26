<div align="center">
  <h1>🛡️ Windows Security Toolkit</h1>
  <p>A comprehensive PowerShell module for security analysis, auditing, and incident response on Windows systems.</p>
  
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![GitHub stars](https://img.shields.io/github/stars/imjvdn/Windows-Security-Toolkit?style=social)](https://github.com/imjvdn/Windows-Security-Toolkit/stargazers)
</div>

## 🎯 Features

- **Comprehensive Auditing**: Collect system, user, and network security information
- **Easy to Use**: Simple, intuitive cmdlets for security professionals
- **Detailed Reporting**: CSV output for analysis and documentation
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
Performs a comprehensive security audit of a Windows system.

```powershell
# Basic usage
Get-SystemSecurityAudit

# Specify custom output directory
Get-SystemSecurityAudit -OutputDirectory "C:\\MyAudit"
```

#### Output Files
- `SystemInfo.csv`: Basic system information
- `LocalUsers.csv`: User account information
- `NetworkConnections.csv`: Active network connections
- `InstalledSoftware.csv`: Installed applications
- `ScheduledTasks.csv`: Configured scheduled tasks
- `RunningServices.csv`: Non-Microsoft running services
- `FirewallRules.csv`: Enabled firewall rules
- `AuditSummary.csv`: Summary of the audit

</details>

<details>
<summary>🚧 Project Structure</summary>

```
Windows-Security-Toolkit/
├── src/                  # Source code for the PowerShell module
│   ├── WindowsSecurityToolkit.psd1  # Module manifest
│   ├── WindowsSecurityToolkit.psm1  # Module script
│   └── Public/             # Public functions
│       └── Get-SystemSecurityAudit.ps1
├── scripts/              # Security scripts
│   ├── audit-tools/       # Targeted security audit scripts
│   └── reporting-tools/   # Report generation tools
├── examples/            # Example scripts
└── docs/                # Documentation
```

</details>

## 💼 Security Scripts

### Audit Tools

The `scripts/audit-tools/` directory contains specialized security audit scripts for targeted assessments:

- **Complete-SystemAudit.ps1**: Comprehensive system-wide security audit
- **Audit-UserAccounts.ps1**: Focused audit of user accounts and permissions
- **Audit-NetworkSecurity.ps1**: Network configuration and security assessment

### Reporting Tools

The `scripts/reporting-tools/` directory contains tools for generating professional reports from audit data:

- **Convert-AuditToHtmlReport.ps1**: Creates interactive HTML reports with filtering and search
- **Generate-ExecutiveSummary.ps1**: Produces executive summaries with key findings and recommendations

<details>
<summary>🔧 Advanced Usage</summary>

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
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon
$users | Export-Csv -Path "UserAudit.csv" -NoTypeInformation

# Check for suspicious processes
Get-Process | Where-Object { $_.Path -notlike "*Windows*" } | 
    Select-Object ProcessName, Id, Path
```

</details>

<details>
<summary>🧪 Examples</summary>

### Basic Audit with Default Settings
```powershell
.\examples\Run-SecurityAudit.ps1
```

### Custom Output Directory
```powershell
.\examples\Run-SecurityAudit.ps1 -OutputDirectory "C:\SecurityAudit_$(Get-Date -Format 'yyyyMMdd')"
```

### Run as Administrator
```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-NoExit', '-File', '.\examples\Run-SecurityAudit.ps1'
```

</details>

<details>
<summary>🤝 Contributing</summary>

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup

1. Clone the repository
2. Install Pester for testing:
   ```powershell
   Install-Module -Name Pester -Force -SkipPublisherCheck
   ```
3. Run tests:
   ```powershell
   Invoke-Pester -Path .\tests\
   ```

</details>

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with ❤️ for security professionals
- Inspired by real-world security challenges
- [Contributors](https://github.com/imjvdn/Windows-Security-Toolkit/graphs/contributors)

---
<p align="center">
  Made with PowerShell | 2025
</p>



## 🔍 Basic System Info

### View System Information
```powershell
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Boot Time"
```

### Check Uptime
```powershell
net statistics workstation | find "Statistics since"
```

## 👥 User Management

### List All Users
```powershell
net user
```

### View Local Administrators
```powershell
net localgroup administrators
```

### Check Logged In Users
```powershell
query user
```

## 🌐 Network

### View Active Connections
```powershell
netstat -ano | findstr ESTABLISHED
```

### Check Firewall Status
```powershell
netsh advfirewall show allprofiles
```

### Flush DNS Cache
```powershell
ipconfig /flushdns
```

## 🔍 System Inspection

### List Running Processes
```powershell
tasklist /v | findstr /i "running"
```

### View Installed Software
```powershell
wmic product get name,version
```

### Check Startup Programs
```powershell
wmic startup get caption,command
```

## 🛡️ Security Checks

### View Installed Updates
```powershell
wmic qfe list brief
```

### Check Scheduled Tasks
```powershell
schtasks /query /fo TABLE /nh /v
```

### View Shared Folders
```powershell
net share
```

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

## 📝 Notes
- Run as Administrator for best results
- Commands work on Windows 7/10/11 and Server 2008R2+
- For detailed output, remove the `findstr` filters

## 📚 Additional Resources
- [Microsoft Docs](https://docs.microsoft.com)
- [SS64 Command Reference](https://ss64.com/)
