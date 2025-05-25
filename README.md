# 🔒 Windows Security Commands Cheat Sheet

Quick reference for essential Windows security commands. No setup required - works in PowerShell and Command Prompt.

## 🚀 Quick Start

Run any command directly in **PowerShell** or **Command Prompt** (Admin rights required for some commands).

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

## 📝 Notes
- Run as Administrator for best results
- Commands work on Windows 7/10/11 and Server 2008R2+
- For detailed output, remove the `findstr` filters

## 📚 Additional Resources
- [Microsoft Docs](https://docs.microsoft.com)
- [SS64 Command Reference](https://ss64.com/)
