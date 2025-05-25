# 🛡️ Windows Security Toolkit

A comprehensive PowerShell module for security analysis, auditing, and incident response on Windows systems.

## 📦 Features

- **System Security Audit**: Comprehensive collection of system security information
- **Easy to Use**: Simple, intuitive cmdlets for security professionals
- **Extensible**: Modular design for adding new security checks
- **Detailed Reporting**: CSV output for easy analysis and reporting

## 🚀 Quick Start

1. **Clone the repository**
   ```powershell
   git clone https://github.com/yourusername/Windows-Security-Toolkit.git
   cd Windows-Security-Toolkit
   ```

2. **Run an example script**
   ```powershell
   .\examples\Run-SecurityAudit.ps1
   ```

3. **Or import the module directly**
   ```powershell
   # Import the module
   Import-Module .\src\WindowsSecurityToolkit.psd1 -Force
   
   # Run a security audit
   $results = Get-SystemSecurityAudit -OutputDirectory "C:\SecurityAudit"
   ```

## 📚 Documentation

### Cmdlets

#### Get-SystemSecurityAudit
Performs a comprehensive security audit of a Windows system.

```powershell
# Basic usage
Get-SystemSecurityAudit

# Specify custom output directory
Get-SystemSecurityAudit -OutputDirectory "C:\MyAudit"
```

**Output Files:**
- `SystemInfo.csv`: Basic system information
- `LocalUsers.csv`: User account information
- `NetworkConnections.csv`: Active network connections
- `InstalledSoftware.csv`: Installed applications
- `ScheduledTasks.csv`: Configured scheduled tasks
- `RunningServices.csv`: Non-Microsoft running services
- `FirewallRules.csv`: Enabled firewall rules
- `AuditSummary.csv`: Summary of the audit

## 🏗️ Project Structure

```
Windows-Security-Toolkit/
├── src/                # Source code
│   ├── Public/        # Functions users will call directly
│   └── Private/       # Internal helper functions
├── tests/             # Pester tests
│   └── environment/   # Test environment setup
├── examples/          # Example scripts
├── config/            # Configuration files
└── docs/              # Documentation
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with ❤️ for security professionals
- Inspired by real-world security challenges



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
