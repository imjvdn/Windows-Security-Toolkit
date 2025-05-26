<#
.SYNOPSIS
    Scans network ports on local or remote Windows systems.
.DESCRIPTION
    This script performs a comprehensive port scan on specified targets using pure PowerShell.
    It identifies open ports, running services, and potential security vulnerabilities
    without requiring external tools like nmap.
.PARAMETER Target
    The target to scan. Can be a hostname, IP address, or CIDR notation.
.PARAMETER Ports
    Specific ports to scan. If not specified, common ports will be scanned.
.PARAMETER ScanType
    Type of scan to perform: Quick, Common, or Full.
    Quick: Scans only the most common ports (about 20)
    Common: Scans common ports (about 100)
    Full: Scans all ports from 1-1024 plus common higher ports
.PARAMETER Timeout
    Timeout in milliseconds for each port connection attempt.
.PARAMETER Threads
    Number of concurrent threads to use for scanning.
.PARAMETER OutputPath
    Path where the scan results will be saved.
.EXAMPLE
    .\Scan-NetworkPorts.ps1 -Target 192.168.1.1 -ScanType Quick
    
    Performs a quick scan of the most common ports on 192.168.1.1.
.EXAMPLE
    .\Scan-NetworkPorts.ps1 -Target 192.168.1.0/24 -Ports 80,443,3389 -OutputPath "C:\Reports"
    
    Scans ports 80, 443, and 3389 on all hosts in the 192.168.1.0/24 subnet.
.NOTES
    File Name      : Scan-NetworkPorts.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,
    
    [Parameter(Mandatory = $false)]
    [int[]]$Ports,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Quick", "Common", "Full")]
    [string]$ScanType = "Common",
    
    [Parameter(Mandatory = $false)]
    [int]$Timeout = 1000,
    
    [Parameter(Mandatory = $false)]
    [int]$Threads = 10,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\PortScan_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
)

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Define common ports and their services
$commonPortsMap = @{
    20 = "FTP Data"
    21 = "FTP Control"
    22 = "SSH"
    23 = "Telnet"
    25 = "SMTP"
    53 = "DNS"
    67 = "DHCP Server"
    68 = "DHCP Client"
    69 = "TFTP"
    80 = "HTTP"
    88 = "Kerberos"
    110 = "POP3"
    111 = "RPC"
    123 = "NTP"
    135 = "RPC/DCOM"
    137 = "NetBIOS Name"
    138 = "NetBIOS Datagram"
    139 = "NetBIOS Session"
    143 = "IMAP"
    161 = "SNMP"
    162 = "SNMP Trap"
    389 = "LDAP"
    443 = "HTTPS"
    445 = "SMB"
    464 = "Kerberos Change/Set"
    465 = "SMTPS"
    500 = "ISAKMP/IKE"
    514 = "Syslog"
    515 = "LPD/LPR"
    587 = "SMTP Submission"
    636 = "LDAPS"
    993 = "IMAPS"
    995 = "POP3S"
    1433 = "MSSQL"
    1434 = "MSSQL Browser"
    1521 = "Oracle DB"
    1723 = "PPTP"
    3306 = "MySQL"
    3389 = "RDP"
    5060 = "SIP"
    5061 = "SIP TLS"
    5432 = "PostgreSQL"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
    8080 = "HTTP Alternate"
    8443 = "HTTPS Alternate"
}

# Define port lists based on scan type
function Get-PortList {
    param (
        [string]$ScanType,
        [int[]]$CustomPorts
    )
    
    # If custom ports are specified, use those
    if ($CustomPorts -and $CustomPorts.Count -gt 0) {
        return $CustomPorts
    }
    
    # Otherwise, use predefined lists based on scan type
    switch ($ScanType) {
        "Quick" {
            return @(21, 22, 23, 25, 80, 139, 443, 445, 3389, 5985, 5986, 8080)
        }
        "Common" {
            return @(20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 464, 465, 500, 514, 515, 587, 636, 993, 995, 1433, 1434, 1521, 1723, 3306, 3389, 5060, 5061, 5432, 5985, 5986, 8080, 8443)
        }
        "Full" {
            $fullList = 1..1024
            $highPorts = @(1433, 1434, 1521, 1723, 3306, 3389, 5060, 5061, 5432, 5985, 5986, 8080, 8443)
            return $fullList + $highPorts | Select-Object -Unique | Sort-Object
        }
    }
}

# Function to parse CIDR notation
function Get-IPRange {
    param (
        [string]$CIDR
    )
    
    # Check if input is CIDR notation
    if ($CIDR -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
        $IPAddress = ($CIDR -split '/')[0]
        $SubnetBits = [int]($CIDR -split '/')[1]
        
        # Convert IP address to integer
        $IPAddressBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
        if ([BitConverter]::IsLittleEndian) {
            [Array]::Reverse($IPAddressBytes)
        }
        $IPAddressInt = [BitConverter]::ToUInt32($IPAddressBytes, 0)
        
        # Calculate subnet mask
        $SubnetMaskInt = ([UInt32]0xFFFFFFFF) -shl (32 - $SubnetBits)
        
        # Calculate first and last IP in range
        $NetworkAddressInt = $IPAddressInt -band $SubnetMaskInt
        $BroadcastAddressInt = $NetworkAddressInt -bor ((-bnot $SubnetMaskInt) -band [UInt32]::MaxValue)
        
        # Generate all IP addresses in range (excluding network and broadcast)
        $FirstUsableAddressInt = $NetworkAddressInt + 1
        $LastUsableAddressInt = $BroadcastAddressInt - 1
        
        $IPRange = @()
        for ($i = $FirstUsableAddressInt; $i -le $LastUsableAddressInt; $i++) {
            $IPBytes = [BitConverter]::GetBytes($i)
            if ([BitConverter]::IsLittleEndian) {
                [Array]::Reverse($IPBytes)
            }
            $IPRange += [System.Net.IPAddress]::new($IPBytes).ToString()
        }
        
        return $IPRange
    } else {
        # If not CIDR, return the input as a single IP
        return @($CIDR)
    }
}

# Function to scan a single port on a host
function Test-Port {
    param (
        [string]$ComputerName,
        [int]$Port,
        [int]$Timeout
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connection = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
        $success = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
        
        if ($success) {
            $tcpClient.EndConnect($connection)
            $serviceName = $commonPortsMap[$Port]
            if (-not $serviceName) {
                $serviceName = "Unknown"
            }
            
            # Try to get banner if it's a common service that might send one
            $banner = ""
            if ($Port -in @(21, 22, 25, 80, 110, 143)) {
                try {
                    $stream = $tcpClient.GetStream()
                    $stream.ReadTimeout = 2000
                    $buffer = New-Object System.Byte[] 1024
                    $encoding = New-Object System.Text.ASCIIEncoding
                    
                    # Wait a moment for the server to send a banner
                    Start-Sleep -Milliseconds 500
                    
                    if ($stream.DataAvailable) {
                        $bytesRead = $stream.Read($buffer, 0, 1024)
                        if ($bytesRead -gt 0) {
                            $banner = $encoding.GetString($buffer, 0, $bytesRead).Trim()
                        }
                    }
                    
                    # For HTTP, send a simple request
                    if ($Port -eq 80 -or $Port -eq 443) {
                        $writer = New-Object System.IO.StreamWriter $stream
                        $writer.WriteLine("HEAD / HTTP/1.1")
                        $writer.WriteLine("Host: $ComputerName")
                        $writer.WriteLine("Connection: close")
                        $writer.WriteLine("")
                        $writer.Flush()
                        
                        Start-Sleep -Milliseconds 500
                        
                        if ($stream.DataAvailable) {
                            $bytesRead = $stream.Read($buffer, 0, 1024)
                            if ($bytesRead -gt 0) {
                                $banner = $encoding.GetString($buffer, 0, $bytesRead).Trim()
                                # Extract server header if present
                                if ($banner -match "Server: ([^\r\n]+)") {
                                    $banner = "Server: " + $matches[1]
                                }
                            }
                        }
                    }
                } catch {
                    # Ignore banner reading errors
                }
            }
            
            $result = [PSCustomObject]@{
                Target = $ComputerName
                Port = $Port
                Status = "Open"
                Service = $serviceName
                Banner = $banner
                ScanTime = Get-Date
            }
            
            return $result
        } else {
            # Port is closed or filtered
            return $null
        }
    } catch {
        # Error occurred
        return $null
    } finally {
        if ($tcpClient -ne $null) {
            $tcpClient.Close()
        }
    }
}

# Function to scan a host for open ports
function Scan-Host {
    param (
        [string]$ComputerName,
        [int[]]$Ports,
        [int]$Timeout,
        [int]$Threads
    )
    
    Write-Verbose "Scanning $ComputerName for ${Ports.Count} ports with $Threads threads..."
    
    # Create a thread-safe queue for ports
    $portQueue = [System.Collections.Concurrent.ConcurrentQueue[int]]::new()
    foreach ($port in $Ports) {
        $portQueue.Enqueue($port)
    }
    
    # Create a thread-safe collection for results
    $results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
    
    # Create and start runspace pool
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads, $sessionState, $Host)
    $runspacePool.Open()
    
    # Create a collection to hold the runspaces
    $runspaces = New-Object System.Collections.ArrayList
    
    # Create and start runspaces for each thread
    for ($i = 0; $i -lt $Threads; $i++) {
        $powershell = [powershell]::Create().AddScript({
            param ($ComputerName, $PortQueue, $Results, $Timeout, $CommonPortsMap)
            
            # Process ports from the queue until it's empty
            $port = $null
            while ($PortQueue.TryDequeue([ref]$port)) {
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connection = $tcpClient.BeginConnect($ComputerName, $port, $null, $null)
                    $success = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
                    
                    if ($success) {
                        $tcpClient.EndConnect($connection)
                        $serviceName = $CommonPortsMap[$port]
                        if (-not $serviceName) {
                            $serviceName = "Unknown"
                        }
                        
                        # Try to get banner if it's a common service that might send one
                        $banner = ""
                        if ($port -in @(21, 22, 25, 80, 110, 143)) {
                            try {
                                $stream = $tcpClient.GetStream()
                                $stream.ReadTimeout = 2000
                                $buffer = New-Object System.Byte[] 1024
                                $encoding = New-Object System.Text.ASCIIEncoding
                                
                                # Wait a moment for the server to send a banner
                                Start-Sleep -Milliseconds 500
                                
                                if ($stream.DataAvailable) {
                                    $bytesRead = $stream.Read($buffer, 0, 1024)
                                    if ($bytesRead -gt 0) {
                                        $banner = $encoding.GetString($buffer, 0, $bytesRead).Trim()
                                    }
                                }
                                
                                # For HTTP, send a simple request
                                if ($port -eq 80 -or $port -eq 443) {
                                    $writer = New-Object System.IO.StreamWriter $stream
                                    $writer.WriteLine("HEAD / HTTP/1.1")
                                    $writer.WriteLine("Host: $ComputerName")
                                    $writer.WriteLine("Connection: close")
                                    $writer.WriteLine("")
                                    $writer.Flush()
                                    
                                    Start-Sleep -Milliseconds 500
                                    
                                    if ($stream.DataAvailable) {
                                        $bytesRead = $stream.Read($buffer, 0, 1024)
                                        if ($bytesRead -gt 0) {
                                            $banner = $encoding.GetString($buffer, 0, $bytesRead).Trim()
                                            # Extract server header if present
                                            if ($banner -match "Server: ([^\r\n]+)") {
                                                $banner = "Server: " + $matches[1]
                                            }
                                        }
                                    }
                                }
                            } catch {
                                # Ignore banner reading errors
                            }
                        }
                        
                        $result = [PSCustomObject]@{
                            Target = $ComputerName
                            Port = $port
                            Status = "Open"
                            Service = $serviceName
                            Banner = $banner
                            ScanTime = Get-Date
                        }
                        
                        $Results.Add($result)
                    }
                } catch {
                    # Ignore errors
                } finally {
                    if ($tcpClient -ne $null) {
                        $tcpClient.Close()
                    }
                }
            }
        }).AddParameter("ComputerName", $ComputerName).AddParameter("PortQueue", $portQueue).AddParameter("Results", $results).AddParameter("Timeout", $Timeout).AddParameter("CommonPortsMap", $commonPortsMap)
        
        $powershell.RunspacePool = $runspacePool
        
        # Start the runspace and save it
        $handle = $powershell.BeginInvoke()
        $runspace = [PSCustomObject]@{
            PowerShell = $powershell
            Handle = $handle
        }
        [void]$runspaces.Add($runspace)
    }
    
    # Wait for all runspaces to complete
    foreach ($runspace in $runspaces) {
        $runspace.PowerShell.EndInvoke($runspace.Handle)
        $runspace.PowerShell.Dispose()
    }
    
    # Close the runspace pool
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    # Return results
    return $results
}

# Main execution
try {
    $startTime = Get-Date
    Write-Host "Starting port scan on $Target..." -ForegroundColor Cyan
    
    # Get the list of ports to scan
    $portsToScan = Get-PortList -ScanType $ScanType -CustomPorts $Ports
    Write-Host "Scanning $($portsToScan.Count) ports per target..." -ForegroundColor Cyan
    
    # Get the list of targets
    $targets = Get-IPRange -CIDR $Target
    Write-Host "Scanning $($targets.Count) targets..." -ForegroundColor Cyan
    
    # Initialize results array
    $allResults = @()
    
    # Scan each target
    $targetCounter = 0
    foreach ($targetHost in $targets) {
        $targetCounter++
        Write-Progress -Activity "Scanning targets" -Status "Target $targetCounter of $($targets.Count): $targetHost" -PercentComplete (($targetCounter / $targets.Count) * 100)
        
        $hostResults = Scan-Host -ComputerName $targetHost -Ports $portsToScan -Timeout $Timeout -Threads $Threads
        $allResults += $hostResults
        
        # Display open ports for this host
        $openPorts = $hostResults | Sort-Object -Property Port
        if ($openPorts.Count -gt 0) {
            Write-Host "`nOpen ports on $targetHost:" -ForegroundColor Green
            $openPorts | Format-Table -Property Port, Service, Banner -AutoSize
        } else {
            Write-Host "`nNo open ports found on $targetHost" -ForegroundColor Yellow
        }
    }
    
    # Calculate statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $totalTargets = $targets.Count
    $totalPorts = $portsToScan.Count
    $totalPortsScanned = $totalTargets * $totalPorts
    $openPortsCount = $allResults.Count
    
    # Generate summary
    $summary = [PSCustomObject]@{
        ScanStartTime = $startTime
        ScanEndTime = $endTime
        ScanDuration = "$($duration.Minutes) minutes, $($duration.Seconds) seconds"
        TotalTargets = $totalTargets
        TotalPortsPerTarget = $totalPorts
        TotalPortsScanned = $totalPortsScanned
        OpenPortsFound = $openPortsCount
        ScanType = $ScanType
    }
    
    # Export results to CSV
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "PortScanResults.csv") -NoTypeInformation
    }
    
    # Export summary to CSV
    $summary | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "PortScanSummary.csv") -NoTypeInformation
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Port Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .summary-item {
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .results {
            margin-top: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Port Scan Report</h1>
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-item"><strong>Scan Start:</strong> $($summary.ScanStartTime)</div>
            <div class="summary-item"><strong>Scan End:</strong> $($summary.ScanEndTime)</div>
            <div class="summary-item"><strong>Duration:</strong> $($summary.ScanDuration)</div>
            <div class="summary-item"><strong>Targets Scanned:</strong> $($summary.TotalTargets)</div>
            <div class="summary-item"><strong>Ports Per Target:</strong> $($summary.TotalPortsPerTarget)</div>
            <div class="summary-item"><strong>Total Ports Scanned:</strong> $($summary.TotalPortsScanned)</div>
            <div class="summary-item"><strong>Open Ports Found:</strong> $($summary.OpenPortsFound)</div>
            <div class="summary-item"><strong>Scan Type:</strong> $($summary.ScanType)</div>
        </div>

        <div class="results">
            <h2>Open Ports</h2>
"@

    if ($allResults.Count -gt 0) {
        # Group results by target
        $groupedResults = $allResults | Group-Object -Property Target
        
        foreach ($group in $groupedResults) {
            $htmlReport += @"
            <h3>Target: $($group.Name)</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Banner</th>
                    <th>Scan Time</th>
                </tr>
"@
            
            foreach ($result in ($group.Group | Sort-Object -Property Port)) {
                $htmlReport += @"
                <tr>
                    <td>$($result.Port)</td>
                    <td>$($result.Service)</td>
                    <td>$($result.Banner)</td>
                    <td>$($result.ScanTime)</td>
                </tr>
"@
            }
            
            $htmlReport += @"
            </table>
"@
        }
    } else {
        $htmlReport += @"
            <p>No open ports were found during this scan.</p>
"@
    }
    
    $htmlReport += @"
        </div>
        
        <div class="footer">
            <p>Generated by Windows Security Toolkit - $(Get-Date)</p>
        </div>
    </div>
</body>
</html>
"@

    # Save HTML report
    $htmlReport | Out-File -FilePath (Join-Path -Path $OutputPath -ChildPath "PortScanReport.html") -Encoding utf8
    
    # Display summary
    Write-Host "`nPort Scan Summary:" -ForegroundColor Green
    Write-Host "=================" -ForegroundColor Green
    Write-Host "Scan Duration: $($summary.ScanDuration)" -ForegroundColor White
    Write-Host "Targets Scanned: $($summary.TotalTargets)" -ForegroundColor White
    Write-Host "Ports Per Target: $($summary.TotalPortsPerTarget)" -ForegroundColor White
    Write-Host "Total Ports Scanned: $($summary.TotalPortsScanned)" -ForegroundColor White
    Write-Host "Open Ports Found: $($summary.OpenPortsFound)" -ForegroundColor $(if ($summary.OpenPortsFound -gt 0) { "Yellow" } else { "Green" })
    Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
    
    # Open HTML report if on Windows
    if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.Platform -ne 'Unix') {
        $htmlReportPath = Join-Path -Path $OutputPath -ChildPath "PortScanReport.html"
        Start-Process $htmlReportPath
    }
    
    return $OutputPath
} catch {
    Write-Error "An error occurred during port scanning: $_"
    throw $_
} finally {
    Write-Host "Port scan completed." -ForegroundColor Cyan
}
