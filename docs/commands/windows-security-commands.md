# 🔐 Windows Security Commands

This document contains essential PowerShell commands for Windows security auditing and analysis.

## 🔍 System Information

```powershell
# Get system information
systeminfo /FO CSV | ConvertFrom-Csv | Select-Object 'Host Name', 'OS Name', 'OS Version', 'OS Manufacturer', 'OS Configuration', 'OS Build Type', 'Registered Owner', 'Registered Organization', 'Product ID', 'Original Install Date', 'System Boot Time', 'System Manufacturer', 'System Model', 'System Type', 'Processor(s)', 'BIOS Version', 'Windows Directory', 'System Directory', 'Boot Device', 'System Locale', 'Input Locale', 'Time Zone', 'Total Physical Memory', 'Available Physical Memory', 'Virtual Memory: Max Size', 'Virtual Memory: Available', 'Virtual Memory: In Use', 'Page File Location(s)', 'Domain', 'Logon Server', 'Hotfix(s)', 'Network Card(s)', 'Hyper-V Requirements'

# Get installed hotfixes
Get-HotFix | Select-Object -Property PSComputerName, Description, HotFixID, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending
```

## 👥 User and Group Management

```powershell
# Get local users
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordRequired,UserMayChangePassword | Format-Table -AutoSize

# Get local administrators
Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource,ObjectClass

# Get domain users (if domain-joined)
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
    Get-ADUser -Filter * -Properties * | Select-Object Name,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,PasswordExpired | Sort-Object Name
}
```

## 🔒 Security Configuration

```powershell
# Get Windows Firewall status
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction

# Get UAC settings
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop

# Get BitLocker status (if available)
if (Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,VolumeType,EncryptionMethod,KeyProtector
}
```

## 🌐 Network Information

```powershell
# Get network connections
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Sort-Object -Property Process | Format-Table -AutoSize

# Get network shares
Get-SmbShare | Where-Object {$_.Special -eq $false} | Select-Object Name,Path,Description,CurrentUserCount | Format-Table -AutoSize

# Get DNS cache
Get-DnsClientCache | Select-Object Entry,RecordData,DataLength,Status,Section,TimeToLive | Format-Table -AutoSize
```

## 🛡️ Security Products

```powershell
# Get installed security products
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState, timestamp

# Get Windows Defender status
Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsVirtualMachine,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled
```

## 🔍 Log Analysis

```powershell
# Get security events (last 24 hours)
$startTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startTime} -MaxEvents 50 | Select-Object TimeCreated,Id,LevelDisplayName,Message | Format-Table -Wrap -AutoSize

# Get failed login attempts (last 7 days)
$startTime = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$startTime} -MaxEvents 100 | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        TargetUser = $_.Properties[5].Value
        SourceIP = $_.Properties[19].Value
        LogonType = $_.Properties[10].Value
        FailureReason = $_.Properties[8].Value
    }
} | Format-Table -AutoSize
```

## 🔄 Scheduled Tasks

```powershell
# Get non-Microsoft scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | Select-Object TaskName,TaskPath,State,Author,Description | Format-Table -AutoSize

# Get tasks that run with highest privileges
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "Highest"} | Select-Object TaskName,TaskPath,State,Author,Description | Format-Table -AutoSize
```

## 🔍 Running Processes and Services

```powershell
# Get non-Microsoft running processes
Get-Process | Where-Object {$_.Company -notlike "*Microsoft*" -and $_.Path -notlike "$env:WINDIR\*"} | Select-Object Name,Id,Path,Company,Description | Format-Table -AutoSize

# Get non-Microsoft services
Get-Service | Where-Object {$_.DisplayName -notlike "*Microsoft*" -and $_.Status -eq "Running"} | Select-Object DisplayName,Name,Status,StartType | Format-Table -AutoSize
```

## 📊 Exporting Results

```powershell
# Create a timestamp for the output files
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$env:USERPROFILE\SecurityAudit_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Export system information
systeminfo /FO CSV | Out-File -FilePath "$outputDir\SystemInfo.csv"

# Export local users
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordRequired,UserMayChangePassword | Export-Csv -Path "$outputDir\LocalUsers.csv" -NoTypeInformation

# Export network connections
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} | Export-Csv -Path "$outputDir\NetworkConnections.csv" -NoTypeInformation

Write-Host "Audit results saved to: $outputDir" -ForegroundColor Green
```

## 🔄 One-Liners for Quick Checks

```powershell
# Check for users with password never expires
Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true} | Select-Object Name,Enabled,PasswordNeverExpires

# Find files modified in the last 7 days (excluding Windows and Program Files)
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7) -and $_.FullName -notlike "$env:WINDIR\*" -and $_.FullName -notlike "${env:ProgramFiles}*" -and $_.FullName -notlike "${env:ProgramFiles(x86)}*"} | Select-Object FullName,LastWriteTime,Length | Sort-Object LastWriteTime -Descending

# Check for unsigned executables in System32
Get-ChildItem -Path "$env:WINDIR\System32\*.exe" | Get-AuthenticodeSignature | Where-Object {$_.Status -ne "Valid"} | Select-Object Path,Status,StatusMessage
```

## 📝 Notes

- Run PowerShell as Administrator for full functionality
- Some commands may require specific modules or features
- Be cautious with commands that modify system settings
- Always review and understand commands before execution

## 📚 Additional Resources

- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
- [Microsoft Security Baselines](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/Microsoft-Security-Baselines)
- [NIST Security Configuration Checklists](https://www.nist.gov/cyberframework/online-learning/components-framework/protect)
