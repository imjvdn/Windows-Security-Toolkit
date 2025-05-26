# 🛡️ Windows Security PowerShell Cheat Sheet

This cheat sheet provides quick reference commands for common security tasks in Windows environments.

## 🔍 System Reconnaissance

### Basic System Information
```powershell
# Get OS details
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer

# Get hardware info
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory

# List all hotfixes
Get-HotFix | Sort-Object -Property InstalledOn -Descending

# Get BIOS information
Get-CimInstance -ClassName Win32_BIOS | Select-Object Manufacturer, Name, SerialNumber, Version
```

### Network Configuration
```powershell
# Get all network adapters
Get-NetAdapter | Format-Table -Property Name, InterfaceDescription, Status, LinkSpeed

# Get IP configuration
Get-NetIPConfiguration | Format-Table -Property InterfaceAlias, IPv4Address, IPv6Address, DNSServer

# Get routing table
Get-NetRoute -AddressFamily IPv4 | Format-Table -Property DestinationPrefix, NextHop, RouteMetric, ifIndex

# Get network connections
Get-NetTCPConnection -State Established | Format-Table -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

## 👥 User & Account Auditing

### User Account Information
```powershell
# List all local users
Get-LocalUser | Format-Table -Property Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet

# Find accounts with passwords that never expire
Get-LocalUser | Where-Object { $_.PasswordNeverExpires -eq $true } | Format-Table -Property Name, Enabled, SID

# Find accounts with empty passwords (security risk)
Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false } | Format-Table -Property Name, Enabled, SID

# Get detailed information about a specific user
Get-LocalUser -Name "Administrator" | Format-List -Property *
```

### Group Membership
```powershell
# List all local groups
Get-LocalGroup | Format-Table -Property Name, SID, Description

# List members of the Administrators group
Get-LocalGroupMember -Group "Administrators" | Format-Table -Property Name, PrincipalSource, ObjectClass

# Check if a user is a member of a specific group
Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -like "*username*" }

# List all groups a user belongs to
$username = "JohnDoe"
Get-LocalGroup | ForEach-Object { 
    $group = $_.Name
    $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
    if ($members.Name -contains $username) {
        [PSCustomObject]@{
            User = $username
            Group = $group
        }
    }
}
```

## 🔒 Security Configuration

### Windows Firewall
```powershell
# Check firewall status
Get-NetFirewallProfile | Format-Table -Property Name, Enabled

# Enable all firewall profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# List firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true -and $_.Direction -eq "Inbound" } | 
    Format-Table -Property DisplayName, Direction, Action, Profile

# Create a new firewall rule
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -Protocol TCP -LocalPort 23 -Action Block
```

### Security Policies
```powershell
# Get account lockout policy
net accounts

# Set account lockout policy
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# Get password policy
net accounts

# Set password policy (minimum length 14, maximum age 60 days)
net accounts /minpwlen:14 /maxpwage:60
```

## 🔍 Threat Hunting

### Process Analysis
```powershell
# List all running processes with owner
Get-Process | Select-Object -Property Name, Id, Path, Company, CPU, @{Name="Owner"; Expression={(Get-Process -Id $_.Id -IncludeUserName).UserName}} | 
    Sort-Object -Property CPU -Descending

# Find processes with unusual parent-child relationships
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine | 
    Where-Object { $_.Name -eq "powershell.exe" -and $_.ParentProcessId -ne 0 }

# Find processes with unusual execution paths
Get-Process | Where-Object { $_.Path -notlike "C:\Windows\*" -and $_.Path -notlike "C:\Program Files*" } | 
    Select-Object Name, Id, Path, Company

# Get command line arguments for processes
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, CommandLine | 
    Where-Object { $_.CommandLine -like "*-enc*" -or $_.CommandLine -like "*hidden*" }
```

### Service Analysis
```powershell
# List all services
Get-Service | Format-Table -Property Name, DisplayName, Status

# Find non-Microsoft services that are running
Get-CimInstance -ClassName Win32_Service | 
    Where-Object { $_.State -eq "Running" -and $_.PathName -notlike "*Windows*" } | 
    Select-Object Name, DisplayName, PathName, StartMode

# Find services with unusual paths
Get-CimInstance -ClassName Win32_Service | 
    Where-Object { $_.PathName -notlike "C:\Windows\*" -and $_.PathName -notlike "C:\Program Files*" } | 
    Select-Object Name, DisplayName, PathName, StartMode

# Find services running as SYSTEM
Get-CimInstance -ClassName Win32_Service | 
    Where-Object { $_.StartName -eq "LocalSystem" } | 
    Select-Object Name, DisplayName, PathName, StartMode, StartName
```

### Scheduled Tasks
```powershell
# List all scheduled tasks
Get-ScheduledTask | Format-Table -Property TaskName, TaskPath, State

# Find tasks that run with highest privileges
Get-ScheduledTask | Where-Object { $_.Principal.RunLevel -eq "Highest" } | 
    Format-Table -Property TaskName, TaskPath, State

# Find tasks with unusual actions
Get-ScheduledTask | ForEach-Object {
    $actions = $_.Actions
    foreach ($action in $actions) {
        if ($action.Execute -notlike "C:\Windows\*" -and $action.Execute -notlike "C:\Program Files*") {
            [PSCustomObject]@{
                TaskName = $_.TaskName
                TaskPath = $_.TaskPath
                Execute = $action.Execute
                Arguments = $action.Arguments
            }
        }
    }
}
```

## 🔐 Registry Analysis

### AutoRun Locations
```powershell
# Check common autorun locations
$autoRunLocations = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($location in $autoRunLocations) {
    if (Test-Path $location) {
        Get-ItemProperty -Path $location | 
            ForEach-Object { $_.PSObject.Properties } | 
            Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSProvider") } | 
            Select-Object Name, Value
    }
}
```

### Suspicious Registry Keys
```powershell
# Check for suspicious Winlogon entries
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | 
    Select-Object Userinit, Shell, Taskman

# Check for AlwaysInstallElevated (privilege escalation)
$hklmInstallElevated = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcuInstallElevated = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated

if ($hklmInstallElevated -eq 1 -and $hkcuInstallElevated -eq 1) {
    Write-Warning "AlwaysInstallElevated is enabled - this is a security risk!"
}
```

## 📂 File System Analysis

### Find Suspicious Files
```powershell
# Find recently modified executable files
Get-ChildItem -Path C:\ -Include *.exe, *.dll, *.ps1, *.bat, *.vbs -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | 
    Select-Object FullName, LastWriteTime, Length

# Find files with unusual extensions in system directories
Get-ChildItem -Path C:\Windows\System32 -Exclude *.exe, *.dll, *.sys, *.ini, *.log -File -Recurse -ErrorAction SilentlyContinue | 
    Select-Object FullName, Extension, Length, LastWriteTime

# Find files with no extension but executable content
Get-ChildItem -Path C:\ -File -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.Extension -eq "" -and $_.Length -gt 0 } | 
    Select-Object FullName, Length, LastWriteTime
```

### Check File Permissions
```powershell
# Find files with unusual permissions
$systemFiles = "C:\Windows\System32\config"
Get-ChildItem -Path $systemFiles -File -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $acl = Get-Acl -Path $_.FullName -ErrorAction SilentlyContinue
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -notlike "*SYSTEM*" -and 
                $access.IdentityReference -notlike "*Administrators*" -and 
                $access.IdentityReference -notlike "*TrustedInstaller*") {
                [PSCustomObject]@{
                    File = $_.FullName
                    Identity = $access.IdentityReference
                    AccessType = $access.AccessControlType
                    Rights = $access.FileSystemRights
                }
            }
        }
    }
```

## 🌐 Network Analysis

### Network Connections
```powershell
# Get all active TCP connections with process information
Get-NetTCPConnection -State Established | 
    ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
            ProcessId = $_.OwningProcess
            ProcessName = $process.Name
            ProcessPath = $process.Path
        }
    } | Format-Table

# Find processes with unusual network connections
Get-NetTCPConnection | 
    Where-Object { $_.RemotePort -eq 4444 -or $_.RemotePort -eq 443 -or $_.RemotePort -eq 8080 } | 
    ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
            ProcessId = $_.OwningProcess
            ProcessName = $process.Name
            ProcessPath = $process.Path
        }
    }
```

### DNS Cache
```powershell
# View DNS cache
Get-DnsClientCache | Format-Table -Property Name, Data, TimeToLive

# Find suspicious DNS entries
Get-DnsClientCache | 
    Where-Object { $_.Name -like "*.ru" -or $_.Name -like "*.cn" -or $_.Data -like "10.*" } | 
    Format-Table -Property Name, Data, TimeToLive
```

## 📊 Event Log Analysis

### Security Events
```powershell
# Get failed login attempts
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 | 
    Format-Table -Property TimeCreated, Id, Message -Wrap

# Get account lockouts
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 20 | 
    Format-Table -Property TimeCreated, Id, Message -Wrap

# Get successful logins
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 | 
    Format-Table -Property TimeCreated, Id, Message -Wrap

# Get security log clearing events (potential evidence tampering)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 10 | 
    Format-Table -Property TimeCreated, Id, Message -Wrap
```

### PowerShell Events
```powershell
# Get PowerShell script block logging events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 20 | 
    Format-Table -Property TimeCreated, Id, Message -Wrap

# Get PowerShell execution events
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; Id=400} -MaxEvents 20 | 
    Format-Table -Property TimeCreated, Id, Message -Wrap
```

## 🛡️ Incident Response

### Memory Analysis
```powershell
# Capture memory dump (requires administrator privileges)
# Note: This creates a large file
$outputFile = "C:\memory.dmp"
Write-Output "Capturing memory dump to $outputFile"
wmic.exe /OUTPUT:$outputFile process call create "C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $pid $outputFile full"
```

### Evidence Collection
```powershell
# Create a directory for evidence collection
$evidenceDir = "C:\Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $evidenceDir | Out-Null

# Collect system information
Get-ComputerInfo | Out-File "$evidenceDir\SystemInfo.txt"

# Collect running processes
Get-Process | Out-File "$evidenceDir\RunningProcesses.txt"

# Collect network connections
Get-NetTCPConnection | Out-File "$evidenceDir\NetworkConnections.txt"

# Collect services
Get-Service | Out-File "$evidenceDir\Services.txt"

# Collect scheduled tasks
Get-ScheduledTask | Out-File "$evidenceDir\ScheduledTasks.txt"

# Collect event logs (security)
Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 1000 | 
    Export-Csv "$evidenceDir\SecurityEvents.csv" -NoTypeInformation

# Compress the evidence directory
Compress-Archive -Path $evidenceDir -DestinationPath "$evidenceDir.zip"
```

## 🔧 Hardening Commands

### Disable Unnecessary Services
```powershell
# Disable Remote Registry service
Set-Service -Name RemoteRegistry -StartupType Disabled -Status Stopped

# Disable Print Spooler service (if not needed)
Set-Service -Name Spooler -StartupType Disabled -Status Stopped

# Disable LLMNR (Link-Local Multicast Name Resolution)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWORD
```

### Enable Security Features
```powershell
# Enable Windows Defender real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable Windows Defender cloud-based protection
Set-MpPreference -MAPSReporting Advanced

# Enable Windows Defender Controlled Folder Access (ransomware protection)
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable Windows Defender Attack Surface Reduction rules
Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
```

### SMB Hardening
```powershell
# Disable SMBv1 (vulnerable protocol)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Enable SMB encryption
Set-SmbServerConfiguration -EncryptData $true -Force

# Disable guest access to SMB shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWORD
```

## 🔄 Regular Maintenance

### Update Management
```powershell
# Check for Windows updates
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate

# Install all available updates
Install-WindowsUpdate -AcceptAll -AutoReboot
```

### Backup Critical Data
```powershell
# Backup important files
$source = "C:\ImportantData"
$destination = "D:\Backups\ImportantData_$(Get-Date -Format 'yyyyMMdd')"
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item -Path "$source\*" -Destination $destination -Recurse -Force
```

### Clean Temporary Files
```powershell
# Clean temp files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
```

## 📝 Notes

- Always run these commands with appropriate permissions (usually Administrator)
- Test commands in a non-production environment first
- Some commands may require specific Windows versions or features
- Always follow your organization's security policies and procedures
