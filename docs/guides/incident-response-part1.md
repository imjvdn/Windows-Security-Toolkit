# 🚨 Incident Response Guide - Part 1: Initial Triage

## 📋 Table of Contents
1. [Initial Setup](#-initial-setup)
2. [System Information](#-system-information)
3. [User and Authentication](#-user-and-authentication)
4. [Process Analysis](#-process-analysis)
5. [Network Connections](#-network-connections)

## 🛠️ Initial Setup

### Create Incident Directory
```powershell
# Create timestamped incident directory
$incidentID = (Get-Date -Format "yyyyMMdd_HHmmss") + "_Incident"
$incidentDir = "C:\IR_$incidentID"
New-Item -ItemType Directory -Path $incidentDir -Force | Out-Null
Write-Host "Incident directory created: $incidentDir" -ForegroundColor Green

# Create subdirectories
$subDirs = @("SystemInfo", "Processes", "Network", "Logs", "Files", "Memory")
foreach ($dir in $subDirs) {
    New-Item -ItemType Directory -Path "$incidentDir\$dir" -Force | Out-Null
}
```

## 💻 System Information

### Basic System Info
```powershell
# System information
systeminfo > "$incidentDir\SystemInfo\systeminfo.txt"

# OS version and build
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer | 
    Format-List | Out-File "$incidentDir\SystemInfo\os_info.txt"

# Installed updates
Get-HotFix | Sort-Object InstalledOn -Descending | 
    Select-Object HotFixID, Description, InstalledOn, InstalledBy | 
    Export-Csv -Path "$incidentDir\SystemInfo\installed_updates.csv" -NoTypeInformation
```

### System Time and Uptime
```powershell
# Record system time and uptime
$systemInfo = @{
    CurrentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TimeZone = (Get-TimeZone).DisplayName
    Uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    LastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
}
$systemInfo | ConvertTo-Json | Out-File "$incidentDir\SystemInfo\system_time_info.json"
```

## 👤 User and Authentication

### Current User Sessions
```powershell
# Get currently logged on users
query user /server:$env:COMPUTERNAME 2>&1 | Out-File "$incidentDir\SystemInfo\logged_on_users.txt"

# Get recent successful logons (last 7 days)
$startTime = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$startTime} -MaxEvents 1000 | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[5].Value
            Domain = $_.Properties[6].Value
            LogonType = $_.Properties[8].Value
            SourceIP = $_.Properties[18].Value
            Process = $_.Properties[9].Value
        }
    } | Export-Csv -Path "$incidentDir\SystemInfo\recent_logons.csv" -NoTypeInformation
```

### User Account Information
```powershell
# Get local users
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordNeverExpires,UserMayChangePassword | 
    Export-Csv -Path "$incidentDir\SystemInfo\local_users.csv" -NoTypeInformation

# Get local groups and members
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    Get-LocalGroupMember -Group $group | 
        Select-Object @{Name="Group";Expression={$group}}, Name, SID, ObjectClass
} | Export-Csv -Path "$incidentDir\SystemInfo\local_groups.csv" -NoTypeInformation
```

## 🔍 Process Analysis

### Running Processes
```powershell
# Get all running processes with details
Get-Process | Select-Object Id, ProcessName, Path, Company, Description, CPU, WorkingSet, 
    @{Name="CommandLine";Expression={(Get-WmiObject Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine}} |
    Export-Csv -Path "$incidentDir\Processes\running_processes.csv" -NoTypeInformation

# Check for unsigned executables
Get-Process | Where-Object { $_.Path } | ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        ProcessName = $_.ProcessName
        ProcessId = $_.Id
        Path = $_.Path
        Status = $sig.Status
        Signer = $sig.SignerCertificate.Subject
        TimeStamp = $sig.TimeStamperCertificate.Subject
    }
} | Where-Object { $_.Status -ne "Valid" } | 
    Export-Csv -Path "$incidentDir\Processes\unsigned_processes.csv" -NoTypeInformation
```

### Process Dependencies
```powershell
# Get loaded DLLs for suspicious processes
function Get-ProcessDLLs {
    param([int]$ProcessId)
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $modules = $process.Modules | 
            Select-Object ModuleName, FileName, FileVersion, FileDescription, Company
        
        [PSCustomObject]@{
            ProcessId = $ProcessId
            ProcessName = $process.ProcessName
            Modules = $modules
        }
    } catch {
        Write-Warning "Could not get modules for process ID $ProcessId : $_"
    }
}

# Example: Get DLLs for top 10 processes by CPU usage
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | 
    ForEach-Object { Get-ProcessDLLs -ProcessId $_.Id } |
    ConvertTo-Json -Depth 5 | 
    Out-File "$incidentDir\Processes\process_dependencies.json"
```

## 🌐 Network Connections

### Active Connections
```powershell
# Get all active network connections
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object Process | 
    Export-Csv -Path "$incidentDir\Network\active_connections.csv" -NoTypeInformation

# Get listening ports
Get-NetTCPConnection -State Listen | 
    Select-Object LocalAddress,LocalPort,OwningProcess,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object LocalPort |
    Export-Csv -Path "$incidentDir\Network\listening_ports.csv" -NoTypeInformation
```

### DNS Cache and ARP Table
```powershell
# Get DNS cache
Get-DnsClientCache | 
    Select-Object Entry,RecordData,DataLength,Status,Section,TimeToLive |
    Export-Csv -Path "$incidentDir\Network\dns_cache.csv" -NoTypeInformation

# Get ARP table
Get-NetNeighbor | Where-Object { $_.State -eq "Reachable" -or $_.State -eq "Stale" } | 
    Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias |
    Export-Csv -Path "$incidentDir\Network\arp_table.csv" -NoTypeInformation
```

### Network Configuration
```powershell
# Get network adapter configuration
Get-NetIPConfiguration -Detailed | 
    Select-Object InterfaceAlias,InterfaceDescription,IPv4Address,IPv6Address,DNSServer | 
    ConvertTo-Json -Depth 3 | 
    Out-File "$incidentDir\Network\network_config.json"

# Get firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | 
    Select-Object DisplayName,Enabled,Profile,Direction,Action |
    Export-Csv -Path "$incidentDir\Network\firewall_rules.csv" -NoTypeInformation
```

---
*Continue to [Part 2: Persistence and Log Analysis](incident-response-part2.md) for more commands.*
