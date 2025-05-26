<#
.SYNOPSIS
    Captures volatile system data including memory dumps and runtime system state.
.DESCRIPTION
    This script captures volatile system data that would be lost after a system
    reboot, including memory dumps, running processes, network connections,
    and other ephemeral system state information. This data is critical for
    incident response and forensic analysis.
.PARAMETER OutputPath
    Path where the captured volatile data will be stored.
.PARAMETER CaptureMemoryDump
    If specified, captures a full memory dump of the system.
    Note: This requires significant disk space and may take a long time.
.PARAMETER CaptureProcessMemory
    If specified, captures memory dumps of specific processes of interest.
.PARAMETER ProcessNames
    Array of process names to capture memory from. Only used when CaptureProcessMemory is specified.
.PARAMETER CaptureTcpConnections
    If specified, captures detailed TCP connection information.
.PARAMETER CaptureUdpConnections
    If specified, captures detailed UDP connection information.
.PARAMETER CaptureArpCache
    If specified, captures the ARP cache.
.PARAMETER CaptureRoutingTable
    If specified, captures the routing table.
.PARAMETER CaptureAll
    If specified, captures all volatile data types.
.EXAMPLE
    .\Export-VolatileData.ps1 -OutputPath "D:\VolatileData" -CaptureAll
    
    Captures all volatile data types and stores them in D:\VolatileData.
.EXAMPLE
    .\Export-VolatileData.ps1 -OutputPath "D:\VolatileData" -CaptureProcessMemory -ProcessNames "explorer", "chrome", "svchost"
    
    Captures memory dumps of the specified processes and stores them in D:\VolatileData.
.NOTES
    File Name      : Export-VolatileData.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges
    Legal Note     : This tool should only be used with proper authorization on systems you own or have permission to examine.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$CaptureMemoryDump,
    
    [Parameter(Mandatory = $false)]
    [switch]$CaptureProcessMemory,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ProcessNames = @("explorer", "lsass", "svchost"),
    
    [Parameter(Mandatory = $false)]
    [switch]$CaptureTcpConnections,
    
    [Parameter(Mandatory = $false)]
    [switch]$CaptureUdpConnections,
    
    [Parameter(Mandatory = $false)]
    [switch]$CaptureArpCache,
    
    [Parameter(Mandatory = $false)]
    [switch]$CaptureRoutingTable,
    
    [Parameter(Mandatory = $false)]
    [switch]$CaptureAll
)

#Requires -RunAsAdministrator

# Initialize script
$ErrorActionPreference = "Stop"
$startTime = Get-Date
$hostname = $env:COMPUTERNAME
$volatileDataDir = Join-Path -Path $OutputPath -ChildPath "$hostname-volatile-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$logFile = Join-Path -Path $volatileDataDir -ChildPath "Capture.log"

# If CaptureAll is specified, enable all capture types
if ($CaptureAll) {
    $CaptureMemoryDump = $true
    $CaptureProcessMemory = $true
    $CaptureTcpConnections = $true
    $CaptureUdpConnections = $true
    $CaptureArpCache = $true
    $CaptureRoutingTable = $true
}

# Create output directory
function Initialize-VolatileDataCapture {
    if (-not (Test-Path -Path $volatileDataDir)) {
        New-Item -Path $volatileDataDir -ItemType Directory -Force | Out-Null
    }
    
    # Initialize log file
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Starting volatile data capture on $hostname" | Out-File -FilePath $logFile -Encoding utf8
}

# Function to log actions
function Write-CaptureLog {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - [$Level] $Message" | Out-File -FilePath $logFile -Encoding utf8 -Append
    
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARNING" { Write-Host $Message -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message }
    }
}

# Function to compute file hash
function Get-CaptureHash {
    param (
        [string]$FilePath
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash
    } catch {
        Write-CaptureLog "Failed to compute hash for $FilePath: $_" -Level "ERROR"
        return "HASH_COMPUTATION_FAILED"
    }
}

# Function to capture basic runtime system state
function Capture-RuntimeState {
    $runtimeDir = Join-Path -Path $volatileDataDir -ChildPath "RuntimeState"
    New-Item -Path $runtimeDir -ItemType Directory -Force | Out-Null
    
    Write-CaptureLog "Capturing runtime system state..."
    
    # Capture running processes with detailed information
    $processesFile = Join-Path -Path $runtimeDir -ChildPath "RunningProcesses.csv"
    Write-CaptureLog "Capturing running processes..."
    
    try {
        Get-Process | Select-Object Id, ProcessName, Path, Company, Description, Product, FileVersion, 
            StartTime, CPU, WorkingSet, PrivateMemorySize, VirtualMemorySize, Threads, Handles, 
            @{Name="ParentProcessId"; Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($_.Id)'").ParentProcessId}},
            @{Name="CommandLine"; Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($_.Id)'").CommandLine}} |
            Export-Csv -Path $processesFile -NoTypeInformation
        
        $hash = Get-CaptureHash -FilePath $processesFile
        Write-CaptureLog "Captured running processes: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture running processes: $_" -Level "ERROR"
    }
    
    # Capture loaded modules for each process
    $modulesDir = Join-Path -Path $runtimeDir -ChildPath "LoadedModules"
    New-Item -Path $modulesDir -ItemType Directory -Force | Out-Null
    
    Write-CaptureLog "Capturing loaded modules for each process..."
    
    try {
        $processes = Get-Process
        foreach ($process in $processes) {
            try {
                $modulesFile = Join-Path -Path $modulesDir -ChildPath "Modules_$($process.Id)_$($process.ProcessName).csv"
                $process.Modules | Select-Object ModuleName, FileName, FileVersion, Size, Company, Description |
                    Export-Csv -Path $modulesFile -NoTypeInformation
                Write-CaptureLog "Captured modules for process $($process.ProcessName) (PID: $($process.Id))"
            } catch {
                Write-CaptureLog "Failed to capture modules for process $($process.ProcessName) (PID: $($process.Id)): $_" -Level "WARNING"
            }
        }
        Write-CaptureLog "Loaded modules capture complete" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture loaded modules: $_" -Level "ERROR"
    }
    
    # Capture services state
    $servicesFile = Join-Path -Path $runtimeDir -ChildPath "Services.csv"
    Write-CaptureLog "Capturing services state..."
    
    try {
        Get-Service | Select-Object Name, DisplayName, Status, StartType, 
            @{Name="PathName"; Expression={(Get-WmiObject -Class Win32_Service -Filter "Name = '$($_.Name)'").PathName}},
            @{Name="StartName"; Expression={(Get-WmiObject -Class Win32_Service -Filter "Name = '$($_.Name)'").StartName}} |
            Export-Csv -Path $servicesFile -NoTypeInformation
        
        $hash = Get-CaptureHash -FilePath $servicesFile
        Write-CaptureLog "Captured services state: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture services state: $_" -Level "ERROR"
    }
    
    # Capture environment variables
    $envVarsFile = Join-Path -Path $runtimeDir -ChildPath "EnvironmentVariables.csv"
    Write-CaptureLog "Capturing environment variables..."
    
    try {
        Get-ChildItem Env: | Select-Object Name, Value |
            Export-Csv -Path $envVarsFile -NoTypeInformation
        
        $hash = Get-CaptureHash -FilePath $envVarsFile
        Write-CaptureLog "Captured environment variables: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture environment variables: $_" -Level "ERROR"
    }
    
    # Capture logged-on users
    $loggedOnUsersFile = Join-Path -Path $runtimeDir -ChildPath "LoggedOnUsers.csv"
    Write-CaptureLog "Capturing logged-on users..."
    
    try {
        quser | Out-File -FilePath (Join-Path -Path $runtimeDir -ChildPath "LoggedOnUsers_quser.txt") -Encoding utf8
        
        Get-WmiObject -Class Win32_LoggedOnUser | Select-Object Antecedent, Dependent |
            Export-Csv -Path $loggedOnUsersFile -NoTypeInformation
        
        $hash = Get-CaptureHash -FilePath $loggedOnUsersFile
        Write-CaptureLog "Captured logged-on users: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture logged-on users: $_" -Level "ERROR"
    }
    
    # Capture scheduled tasks
    $scheduledTasksFile = Join-Path -Path $runtimeDir -ChildPath "ScheduledTasks.csv"
    Write-CaptureLog "Capturing scheduled tasks..."
    
    try {
        Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author, Description |
            Export-Csv -Path $scheduledTasksFile -NoTypeInformation
        
        $hash = Get-CaptureHash -FilePath $scheduledTasksFile
        Write-CaptureLog "Captured scheduled tasks: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture scheduled tasks: $_" -Level "ERROR"
    }
    
    Write-CaptureLog "Runtime system state capture complete" -Level "SUCCESS"
}

# Function to capture network connections
function Capture-NetworkConnections {
    $networkDir = Join-Path -Path $volatileDataDir -ChildPath "NetworkState"
    New-Item -Path $networkDir -ItemType Directory -Force | Out-Null
    
    Write-CaptureLog "Capturing network state..."
    
    # Capture basic network configuration
    $networkConfigFile = Join-Path -Path $networkDir -ChildPath "NetworkConfiguration.txt"
    Write-CaptureLog "Capturing network configuration..."
    
    try {
        ipconfig /all | Out-File -FilePath $networkConfigFile -Encoding utf8
        $hash = Get-CaptureHash -FilePath $networkConfigFile
        Write-CaptureLog "Captured network configuration: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture network configuration: $_" -Level "ERROR"
    }
    
    # Capture TCP connections
    if ($CaptureTcpConnections -or $CaptureAll) {
        $tcpConnectionsFile = Join-Path -Path $networkDir -ChildPath "TcpConnections.csv"
        Write-CaptureLog "Capturing TCP connections..."
        
        try {
            # First, capture raw netstat output
            $netstatTcpFile = Join-Path -Path $networkDir -ChildPath "netstat_tcp.txt"
            netstat -ano -p TCP | Out-File -FilePath $netstatTcpFile -Encoding utf8
            
            # Then, parse and structure the data
            $tcpConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
                @{Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                @{Name="CreationTime"; Expression={$_.CreationTime}},
                @{Name="CommandLine"; Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($_.OwningProcess)'").CommandLine}}
            
            $tcpConnections | Export-Csv -Path $tcpConnectionsFile -NoTypeInformation
            
            $hash = Get-CaptureHash -FilePath $tcpConnectionsFile
            Write-CaptureLog "Captured TCP connections: $hash" -Level "SUCCESS"
        } catch {
            Write-CaptureLog "Failed to capture TCP connections: $_" -Level "ERROR"
        }
    }
    
    # Capture UDP connections
    if ($CaptureUdpConnections -or $CaptureAll) {
        $udpConnectionsFile = Join-Path -Path $networkDir -ChildPath "UdpConnections.csv"
        Write-CaptureLog "Capturing UDP connections..."
        
        try {
            # First, capture raw netstat output
            $netstatUdpFile = Join-Path -Path $networkDir -ChildPath "netstat_udp.txt"
            netstat -ano -p UDP | Out-File -FilePath $netstatUdpFile -Encoding utf8
            
            # Then, parse and structure the data
            $udpConnections = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess,
                @{Name="ProcessName"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
                @{Name="CreationTime"; Expression={$_.CreationTime}},
                @{Name="CommandLine"; Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId = '$($_.OwningProcess)'").CommandLine}}
            
            $udpConnections | Export-Csv -Path $udpConnectionsFile -NoTypeInformation
            
            $hash = Get-CaptureHash -FilePath $udpConnectionsFile
            Write-CaptureLog "Captured UDP connections: $hash" -Level "SUCCESS"
        } catch {
            Write-CaptureLog "Failed to capture UDP connections: $_" -Level "ERROR"
        }
    }
    
    # Capture ARP cache
    if ($CaptureArpCache -or $CaptureAll) {
        $arpCacheFile = Join-Path -Path $networkDir -ChildPath "ArpCache.txt"
        Write-CaptureLog "Capturing ARP cache..."
        
        try {
            arp -a | Out-File -FilePath $arpCacheFile -Encoding utf8
            $hash = Get-CaptureHash -FilePath $arpCacheFile
            Write-CaptureLog "Captured ARP cache: $hash" -Level "SUCCESS"
        } catch {
            Write-CaptureLog "Failed to capture ARP cache: $_" -Level "ERROR"
        }
    }
    
    # Capture routing table
    if ($CaptureRoutingTable -or $CaptureAll) {
        $routingTableFile = Join-Path -Path $networkDir -ChildPath "RoutingTable.txt"
        Write-CaptureLog "Capturing routing table..."
        
        try {
            route print | Out-File -FilePath $routingTableFile -Encoding utf8
            $hash = Get-CaptureHash -FilePath $routingTableFile
            Write-CaptureLog "Captured routing table: $hash" -Level "SUCCESS"
        } catch {
            Write-CaptureLog "Failed to capture routing table: $_" -Level "ERROR"
        }
    }
    
    # Capture DNS cache
    $dnsCacheFile = Join-Path -Path $networkDir -ChildPath "DnsCache.txt"
    Write-CaptureLog "Capturing DNS cache..."
    
    try {
        ipconfig /displaydns | Out-File -FilePath $dnsCacheFile -Encoding utf8
        $hash = Get-CaptureHash -FilePath $dnsCacheFile
        Write-CaptureLog "Captured DNS cache: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture DNS cache: $_" -Level "ERROR"
    }
    
    # Capture network shares
    $sharesFile = Join-Path -Path $networkDir -ChildPath "NetworkShares.csv"
    Write-CaptureLog "Capturing network shares..."
    
    try {
        Get-WmiObject -Class Win32_Share | Select-Object Name, Path, Description, Type |
            Export-Csv -Path $sharesFile -NoTypeInformation
        
        $hash = Get-CaptureHash -FilePath $sharesFile
        Write-CaptureLog "Captured network shares: $hash" -Level "SUCCESS"
    } catch {
        Write-CaptureLog "Failed to capture network shares: $_" -Level "ERROR"
    }
    
    Write-CaptureLog "Network state capture complete" -Level "SUCCESS"
}

# Function to capture process memory
function Capture-ProcessMemory {
    if (-not $CaptureProcessMemory -and -not $CaptureAll) {
        Write-CaptureLog "Skipping process memory capture as requested"
        return
    }
    
    $processMemoryDir = Join-Path -Path $volatileDataDir -ChildPath "ProcessMemory"
    New-Item -Path $processMemoryDir -ItemType Directory -Force | Out-Null
    
    Write-CaptureLog "Capturing process memory dumps..."
    
    # Check if procdump is available
    $procdumpPath = Join-Path -Path $PSScriptRoot -ChildPath "tools\procdump.exe"
    $procdumpAvailable = Test-Path -Path $procdumpPath
    
    if (-not $procdumpAvailable) {
        Write-CaptureLog "ProcDump not found at $procdumpPath. Attempting to use PowerShell methods." -Level "WARNING"
    }
    
    foreach ($processName in $ProcessNames) {
        Write-CaptureLog "Attempting to capture memory for process: $processName"
        
        try {
            $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
            
            if (-not $processes) {
                Write-CaptureLog "Process $processName not found" -Level "WARNING"
                continue
            }
            
            foreach ($process in $processes) {
                $dumpFile = Join-Path -Path $processMemoryDir -ChildPath "$($process.ProcessName)_$($process.Id).dmp"
                
                if ($procdumpAvailable) {
                    # Use procdump if available
                    Write-CaptureLog "Using ProcDump to capture memory for $($process.ProcessName) (PID: $($process.Id))"
                    & $procdumpPath -ma $process.Id $dumpFile
                } else {
                    # Fallback to PowerShell method using WER
                    Write-CaptureLog "Using PowerShell method to capture memory for $($process.ProcessName) (PID: $($process.Id))"
                    
                    try {
                        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
                        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
                        $Flags = [Reflection.BindingFlags] 'NonPublic, Static'
                        $MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags)
                        $MiniDumpWithFullMemory = [UInt32] 2
                        
                        $ProcessHandle = $process.Handle
                        $ProcessId = $process.Id
                        $DumpFile = New-Object System.IO.FileStream($dumpFile, [System.IO.FileMode]::Create)
                        $Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle, $ProcessId, $DumpFile.SafeFileHandle, $MiniDumpWithFullMemory, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero))
                        
                        $DumpFile.Close()
                        
                        if (-not $Result) {
                            throw "Failed to create memory dump"
                        }
                    } catch {
                        Write-CaptureLog "PowerShell method failed: $_" -Level "ERROR"
                        Write-CaptureLog "Memory dump for $($process.ProcessName) (PID: $($process.Id)) could not be captured" -Level "ERROR"
                        continue
                    }
                }
                
                if (Test-Path -Path $dumpFile) {
                    $hash = Get-CaptureHash -FilePath $dumpFile
                    Write-CaptureLog "Captured memory dump for $($process.ProcessName) (PID: $($process.Id)): $hash" -Level "SUCCESS"
                } else {
                    Write-CaptureLog "Failed to capture memory dump for $($process.ProcessName) (PID: $($process.Id))" -Level "ERROR"
                }
            }
        } catch {
            Write-CaptureLog "Error capturing memory for process $processName: $_" -Level "ERROR"
        }
    }
    
    Write-CaptureLog "Process memory capture complete" -Level "SUCCESS"
}

# Function to capture full system memory dump
function Capture-SystemMemory {
    if (-not $CaptureMemoryDump -and -not $CaptureAll) {
        Write-CaptureLog "Skipping system memory dump as requested"
        return
    }
    
    $memoryDumpDir = Join-Path -Path $volatileDataDir -ChildPath "SystemMemory"
    New-Item -Path $memoryDumpDir -ItemType Directory -Force | Out-Null
    
    Write-CaptureLog "Capturing system memory dump..."
    
    # Check available disk space
    $drive = Split-Path -Path $memoryDumpDir -Qualifier
    $driveInfo = Get-PSDrive -Name $drive.TrimEnd(':')
    $availableSpace = $driveInfo.Free
    
    # Get total physical memory
    $totalMemory = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory
    
    if ($availableSpace -lt ($totalMemory * 1.5)) {
        Write-CaptureLog "Insufficient disk space for full memory dump. Required: $([math]::Round($totalMemory / 1GB, 2)) GB, Available: $([math]::Round($availableSpace / 1GB, 2)) GB" -Level "ERROR"
        return
    }
    
    # Check if WinPmem is available
    $winpmemPath = Join-Path -Path $PSScriptRoot -ChildPath "tools\winpmem.exe"
    $winpmemAvailable = Test-Path -Path $winpmemPath
    
    if (-not $winpmemAvailable) {
        Write-CaptureLog "WinPmem not found at $winpmemPath. Full system memory dump cannot be captured." -Level "ERROR"
        Write-CaptureLog "Please download WinPmem from https://github.com/Velocidex/WinPmem and place it in the tools directory." -Level "ERROR"
        return
    }
    
    # Capture memory dump using WinPmem
    $dumpFile = Join-Path -Path $memoryDumpDir -ChildPath "FullMemory_$hostname.raw"
    
    try {
        Write-CaptureLog "Starting memory acquisition with WinPmem. This may take several minutes..."
        & $winpmemPath $dumpFile
        
        if (Test-Path -Path $dumpFile) {
            $hash = Get-CaptureHash -FilePath $dumpFile
            Write-CaptureLog "Captured full system memory dump: $hash" -Level "SUCCESS"
        } else {
            Write-CaptureLog "Failed to capture full system memory dump" -Level "ERROR"
        }
    } catch {
        Write-CaptureLog "Error capturing system memory: $_" -Level "ERROR"
    }
    
    Write-CaptureLog "System memory capture complete" -Level "SUCCESS"
}

# Function to create final package
function Complete-VolatileDataCapture {
    # Create ZIP archive
    $volatileDataZip = "$volatileDataDir.zip"
    Write-CaptureLog "Creating volatile data package: $volatileDataZip"
    
    try {
        Compress-Archive -Path $volatileDataDir -DestinationPath $volatileDataZip -Force
        $packageHash = Get-CaptureHash -FilePath $volatileDataZip
        
        Write-CaptureLog "Volatile data capture complete. Package saved to: $volatileDataZip" -Level "SUCCESS"
        Write-CaptureLog "Package SHA256: $packageHash" -Level "SUCCESS"
        
        return $volatileDataZip
    } catch {
        Write-CaptureLog "Failed to create volatile data package: $_" -Level "ERROR"
        return $null
    }
}

# Main execution
try {
    # Initialize volatile data capture
    Initialize-VolatileDataCapture
    
    # Capture runtime system state (always captured)
    Capture-RuntimeState
    
    # Capture network connections
    Capture-NetworkConnections
    
    # Capture process memory if requested
    Capture-ProcessMemory
    
    # Capture full system memory if requested
    Capture-SystemMemory
    
    # Create final package
    $volatileDataPackage = Complete-VolatileDataCapture
    
    if ($volatileDataPackage) {
        Write-Host "`nVolatile data capture complete!" -ForegroundColor Green
        Write-Host "Data package: $volatileDataPackage" -ForegroundColor Cyan
    } else {
        Write-Host "`nVolatile data capture completed with errors. Check the log file for details." -ForegroundColor Yellow
    }
    
    return $volatileDataPackage
} catch {
    Write-CaptureLog "Critical error in volatile data capture: $_" -Level "ERROR"
    Write-Host "Critical error in volatile data capture: $_" -ForegroundColor Red
    return $null
}
