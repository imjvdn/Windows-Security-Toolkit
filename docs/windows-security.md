# 🔐 Windows Security Commands

## 📋 Table of Contents
1. [System Information](#system-information)
2. [User & Group Management](#user--group-management)
3. [Security Configuration](#security-configuration)
4. [Network Security](#network-security)
5. [Security Products](#security-products)
6. [Event Logs](#event-logs)
7. [Scheduled Tasks](#scheduled-tasks)
8. [Processes & Services](#processes--services)
9. [File System Security](#file-system-security)
10. [Reporting](#reporting)

## System Information

### Basic System Details
```powershell
# Get comprehensive system information
systeminfo /FO CSV | ConvertFrom-Csv | Select-Object 'Host Name', 'OS Name', 'OS Version', 
    'System Manufacturer', 'System Model', 'System Type', 'Total Physical Memory', 
    'Domain', 'Logon Server', 'Hotfix(s)'

# Get installed updates
Get-HotFix | Sort-Object InstalledOn -Descending | 
    Select-Object HotFixID, Description, InstalledBy, InstalledOn
```

### System Uptime
```powershell
# Get system uptime
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$uptime = (Get-Date) - $os.LastBootUpTime
[PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    LastBootTime = $os.LastBootUpTime
    Uptime = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
}
```

## User & Group Management

### Local User Accounts
```powershell
# Get all local users with security details
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, 
    PasswordRequired, PasswordExpires, UserMayChangePassword, 
    PasswordNeverExpires, AccountExpires, Description | 
    Format-Table -AutoSize

# Find users with security issues
Get-LocalUser | Where-Object { $_.Enabled -and 
    ($_.PasswordNeverExpires -or -not $_.PasswordRequired) } | 
    Select-Object Name, Enabled, PasswordNeverExpires, PasswordRequired
```

### Local Group Membership
```powershell
# Get members of sensitive groups
$sensitiveGroups = @("Administrators", "Remote Desktop Users", "Backup Operators")
foreach ($group in $sensitiveGroups) {
    Write-Host "\n$group members:" -ForegroundColor Cyan
    Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | 
        Select-Object Name, PrincipalSource, ObjectClass
}
```

## Security Configuration

### Windows Firewall
```powershell
# Get firewall profiles
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, 
    DefaultOutboundAction, LogAllowed, LogBlocked, LogIgnored

# Get enabled inbound rules
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | 
    Select-Object DisplayName, Direction, Action, Profile | 
    Sort-Object Profile, DisplayName
```

### Security Settings
```powershell
# Get UAC configuration
$uacSettings = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
[PSCustomObject]@{
    UACEnabled = $uacSettings.EnableLUA -eq 1
    AdminConsentPrompt = switch ($uacSettings.ConsentPromptBehaviorAdmin) {
        0 {"Elevate without prompting"}
        1 {"Prompt for credentials on secure desktop"}
        2 {"Prompt for consent on secure desktop"}
        3 {"Prompt for credentials"}
        4 {"Prompt for consent"}
        5 {"Prompt for consent for non-Windows binaries"}
        default {"Unknown"}
    }
    SecureDesktop = $uacSettings.PromptOnSecureDesktop -eq 1
}

# Check BitLocker status
if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, 
        ProtectionStatus, EncryptionPercentage, VolumeType, EncryptionMethod
}
```

## Network Security

### Active Connections
```powershell
# Get active network connections with process details
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
    @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}, 
    @{Name="PID"; Expression={$_.OwningProcess}} | 
    Sort-Object Process | Format-Table -AutoSize
```

### Network Configuration
```powershell
# Get network adapter configuration
Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceDescription, 
    IPv4Address, IPv6Address, DNSServer | Format-Table -AutoSize

# Get network shares
Get-SmbShare | Where-Object {$_.Special -eq $false} | 
    Select-Object Name, Path, Description, CurrentUserCount
```

## Security Products

### Antivirus Status
```powershell
# Get installed security products
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct | 
    Select-Object displayName, productState, timestamp

# Get Windows Defender status
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, 
    RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, 
    AntispywareEnabled, NISEnabled
```

## Event Logs

### Security Events
```powershell
# Get recent security events
$startTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} -MaxEvents 50 | 
    Select-Object TimeCreated, Id, LevelDisplayName, Message
```

### Authentication Events
```powershell
# Get failed login attempts (last 7 days)
$startTime = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$startTime} -MaxEvents 100 | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser = $_.Properties[5].Value
            SourceIP = $_.Properties[19].Value
            LogonType = $_.Properties[10].Value
            FailureReason = $_.Properties[8].Value
        }
    }
```

## Scheduled Tasks

### Task Auditing
```powershell
# Get non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | 
    Select-Object TaskName, TaskPath, State, Author

# Get tasks with highest privileges
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "Highest"} | 
    Select-Object TaskName, TaskPath, State, Author
```

## Processes & Services

### Running Processes
```powershell
# Get non-Microsoft processes
Get-Process | Where-Object {$_.Company -notlike "*Microsoft*" -and $_.Path -notlike "$env:WINDIR\*"} | 
    Select-Object Name, Id, Path, Company | Format-Table -AutoSize

# Find processes with unusual paths
Get-Process | Where-Object {
    $_.Path -and 
    $_.Path -notlike "$env:WINDIR\*" -and 
    $_.Path -notlike "$env:ProgramFiles\*" -and 
    $_.Path -notlike "$env:ProgramFiles(x86)\*"
} | Select-Object Name, Id, Path
```

### Services
```powershell
# Get non-Microsoft services
Get-Service | Where-Object {$_.DisplayName -notlike "*Microsoft*" -and $_.Status -eq "Running"} | 
    Select-Object DisplayName, Name, Status, StartType

# Find services with unusual binary paths
Get-WmiObject -Class Win32_Service | Where-Object {
    $_.PathName -notlike "*system32*" -and 
    $_.PathName -notlike "*Program Files*" -and 
    $_.State -eq "Running"
} | Select-Object DisplayName, Name, State, PathName
```

## File System Security

### File Integrity
```powershell
# Find recently modified system files
$startTime = (Get-Date).AddDays(-7)
Get-ChildItem -Path "$env:WINDIR\System32" -File -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -gt $startTime } | 
    Select-Object FullName, LastWriteTime, Length

# Check for unsigned executables
Get-ChildItem -Path "$env:WINDIR\System32\*.exe" -File | 
    Get-AuthenticodeSignature | 
    Where-Object {$_.Status -ne "Valid"} | 
    Select-Object Path, Status, StatusMessage
```

## Reporting

### Security Audit Report
```powershell
# Create a timestamp for the output files
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$env:USERPROFILE\SecurityAudit_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Export system information
systeminfo /FO CSV | Out-File -FilePath "$outputDir\SystemInfo.csv"

# Export local users
Get-LocalUser | 
    Select-Object Name, Enabled, LastLogon, PasswordLastSet, 
    PasswordRequired, PasswordNeverExpires | 
    Export-Csv -Path "$outputDir\LocalUsers.csv" -NoTypeInformation

# Export network connections
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
    @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | 
    Export-Csv -Path "$outputDir\NetworkConnections.csv" -NoTypeInformation

Write-Host "Security audit results saved to: $outputDir" -ForegroundColor Green
```
