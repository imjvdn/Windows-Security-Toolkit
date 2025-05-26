<#
.SYNOPSIS
    Detects common indicators of compromise on Windows systems.
.DESCRIPTION
    This script scans a Windows system for common indicators of compromise (IOCs)
    including suspicious processes, network connections, registry entries, and more.
    It produces a report of potential security threats that require investigation.
.PARAMETER OutputPath
    The path where the threat detection report will be saved.
.PARAMETER Thorough
    Performs a more thorough scan, which takes longer but detects more subtle indicators.
.EXAMPLE
    .\Detect-ThreatIndicators.ps1 -OutputPath "C:\Reports"
    
    Performs a standard threat detection scan and saves the report to C:\Reports.
.EXAMPLE
    .\Detect-ThreatIndicators.ps1 -OutputPath "C:\Reports" -Thorough
    
    Performs a thorough threat detection scan and saves the report to C:\Reports.
.NOTES
    File Name      : Detect-ThreatIndicators.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\ThreatScan_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    
    [Parameter(Mandatory = $false)]
    [switch]$Thorough
)

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Initialize results array
$threatIndicators = @()

# Function to add a finding to the results
function Add-Finding {
    param (
        [string]$Category,
        [string]$Description,
        [string]$Details,
        [string]$Severity,
        [string]$Recommendation
    )
    
    $threatIndicators += [PSCustomObject]@{
        Category = $Category
        Description = $Description
        Details = $Details
        Severity = $Severity
        Recommendation = $Recommendation
        DetectionTime = Get-Date
    }
}

# Function to check for suspicious processes
function Find-SuspiciousProcesses {
    Write-Verbose "Checking for suspicious processes..."
    
    # Check for processes running from unusual locations
    $suspiciousPaths = @(
        "C:\Windows\Temp\",
        "C:\Temp\",
        "$env:TEMP\",
        "C:\ProgramData\",
        "C:\Users\Public\"
    )
    
    Get-Process | ForEach-Object {
        try {
            $processPath = $_.Path
            if ($processPath) {
                foreach ($path in $suspiciousPaths) {
                    if ($processPath -like "$path*") {
                        Add-Finding -Category "Suspicious Process" `
                            -Description "Process running from suspicious location" `
                            -Details "Process: $($_.Name) (PID: $($_.Id)), Path: $processPath" `
                            -Severity "High" `
                            -Recommendation "Investigate this process and terminate if malicious"
                    }
                }
            }
        } catch {
            # Some processes may not allow access to their path
        }
    }
    
    # Check for processes with suspicious names (common malware names or typosquatting)
    $suspiciousNames = @(
        "svch0st",
        "scvhost",
        "csrss1",
        "lsasss",
        "powershell_ise",
        "cmd1",
        "explorer1",
        "iexplorer",
        "svchost1"
    )
    
    Get-Process | ForEach-Object {
        foreach ($name in $suspiciousNames) {
            if ($_.Name -like $name) {
                Add-Finding -Category "Suspicious Process" `
                    -Description "Process with suspicious name (possible typosquatting)" `
                    -Details "Process: $($_.Name) (PID: $($_.Id)), Path: $($_.Path)" `
                    -Severity "High" `
                    -Recommendation "Terminate this process and investigate further"
            }
        }
    }
    
    # Check for processes with unusual parent-child relationships
    if ($Thorough) {
        $processes = Get-CimInstance -ClassName Win32_Process
        foreach ($process in $processes) {
            $parentProcess = $processes | Where-Object { $_.ProcessId -eq $process.ParentProcessId }
            
            # Check for unusual parent-child relationships
            if ($parentProcess) {
                # PowerShell spawned by unusual parent
                if ($process.Name -eq "powershell.exe" -and 
                    $parentProcess.Name -notin @("explorer.exe", "cmd.exe", "powershell.exe", "powershell_ise.exe", "svchost.exe")) {
                    Add-Finding -Category "Suspicious Process" `
                        -Description "PowerShell spawned by unusual parent process" `
                        -Details "PowerShell (PID: $($process.ProcessId)) spawned by $($parentProcess.Name) (PID: $($parentProcess.ProcessId))" `
                        -Severity "Medium" `
                        -Recommendation "Investigate the parent process and PowerShell command line arguments"
                }
                
                # cmd.exe spawned by unusual parent
                if ($process.Name -eq "cmd.exe" -and 
                    $parentProcess.Name -notin @("explorer.exe", "powershell.exe", "powershell_ise.exe", "svchost.exe")) {
                    Add-Finding -Category "Suspicious Process" `
                        -Description "Command prompt spawned by unusual parent process" `
                        -Details "cmd.exe (PID: $($process.ProcessId)) spawned by $($parentProcess.Name) (PID: $($parentProcess.ProcessId))" `
                        -Severity "Medium" `
                        -Recommendation "Investigate the parent process and command prompt usage"
                }
            }
        }
    }
}

# Function to check for suspicious network connections
function Find-SuspiciousNetworkConnections {
    Write-Verbose "Checking for suspicious network connections..."
    
    # Get all active TCP connections with process information
    $connections = Get-NetTCPConnection -State Established
    
    # Check for connections to unusual ports
    $suspiciousPorts = @(4444, 666, 1337, 31337, 8080, 8888, 9999)
    
    foreach ($connection in $connections) {
        # Check for connections to suspicious remote ports
        if ($connection.RemotePort -in $suspiciousPorts) {
            $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
            Add-Finding -Category "Suspicious Network" `
                -Description "Connection to suspicious remote port" `
                -Details "Process: $($process.Name) (PID: $($process.Id)), Remote: $($connection.RemoteAddress):$($connection.RemotePort)" `
                -Severity "High" `
                -Recommendation "Investigate this connection and terminate if unauthorized"
        }
        
        # Check for non-browser processes connecting to HTTP/HTTPS ports
        if ($connection.RemotePort -in @(80, 443)) {
            $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
            if ($process -and $process.Name -notin @("chrome", "firefox", "iexplore", "msedge", "opera", "brave", "vivaldi", "safari")) {
                Add-Finding -Category "Suspicious Network" `
                    -Description "Non-browser process connecting to web port" `
                    -Details "Process: $($process.Name) (PID: $($process.Id)), Remote: $($connection.RemoteAddress):$($connection.RemotePort)" `
                    -Severity "Medium" `
                    -Recommendation "Verify if this process should be making web connections"
            }
        }
    }
    
    # Check for suspicious listening ports
    $listeningConnections = Get-NetTCPConnection -State Listen
    
    foreach ($connection in $listeningConnections) {
        # Check for unusual listening ports
        if ($connection.LocalPort -in $suspiciousPorts) {
            $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
            Add-Finding -Category "Suspicious Network" `
                -Description "Process listening on suspicious port" `
                -Details "Process: $($process.Name) (PID: $($process.Id)), Local Port: $($connection.LocalPort)" `
                -Severity "High" `
                -Recommendation "Investigate this listening port and terminate if unauthorized"
        }
    }
}

# Function to check for suspicious registry entries
function Find-SuspiciousRegistryEntries {
    Write-Verbose "Checking for suspicious registry entries..."
    
    # Check for persistence mechanisms in Run keys
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $values = Get-ItemProperty -Path $key
            $properties = $values.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSProvider") }
            
            foreach ($prop in $properties) {
                $value = $prop.Value
                
                # Check for suspicious paths or commands
                if ($value -like "*powershell*-e*" -or 
                    $value -like "*cmd*-c*" -or 
                    $value -like "*wscript*" -or 
                    $value -like "*cscript*" -or
                    $value -like "*.vbs*" -or
                    $value -like "*\Temp\*" -or
                    $value -like "*\Windows\Temp\*" -or
                    $value -like "*%TEMP%*" -or
                    $value -like "*\Users\Public\*") {
                    
                    Add-Finding -Category "Persistence" `
                        -Description "Suspicious autorun entry" `
                        -Details "Registry: $key, Name: $($prop.Name), Value: $value" `
                        -Severity "High" `
                        -Recommendation "Remove this registry entry if unauthorized"
                }
            }
        }
    }
    
    # Check for WMI persistence
    if ($Thorough) {
        try {
            $wmiSubscriptions = Get-WmiObject -Namespace root\Subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
            if ($wmiSubscriptions) {
                foreach ($subscription in $wmiSubscriptions) {
                    Add-Finding -Category "Persistence" `
                        -Description "WMI event subscription (potential persistence mechanism)" `
                        -Details "Filter: $($subscription.Filter), Consumer: $($subscription.Consumer)" `
                        -Severity "Medium" `
                        -Recommendation "Investigate this WMI subscription and remove if unauthorized"
                }
            }
        } catch {
            # WMI query may fail on some systems
        }
    }
    
    # Check for AlwaysInstallElevated (privilege escalation)
    $hklmInstallElevated = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcuInstallElevated = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    
    if ($hklmInstallElevated -eq 1 -and $hkcuInstallElevated -eq 1) {
        Add-Finding -Category "Privilege Escalation" `
            -Description "AlwaysInstallElevated is enabled" `
            -Details "Both HKLM and HKCU registry keys are set to 1" `
            -Severity "High" `
            -Recommendation "Disable AlwaysInstallElevated to prevent privilege escalation"
    }
}

# Function to check for suspicious scheduled tasks
function Find-SuspiciousScheduledTasks {
    Write-Verbose "Checking for suspicious scheduled tasks..."
    
    $tasks = Get-ScheduledTask
    
    foreach ($task in $tasks) {
        $actions = $task.Actions
        
        foreach ($action in $actions) {
            # Check for suspicious executables or arguments
            if ($action.Execute) {
                if ($action.Execute -like "*powershell*" -or 
                    $action.Execute -like "*cmd*" -or 
                    $action.Execute -like "*wscript*" -or 
                    $action.Execute -like "*cscript*") {
                    
                    # Check for encoded commands
                    if ($action.Arguments -like "*-e*" -or 
                        $action.Arguments -like "*-enc*" -or 
                        $action.Arguments -like "*-encodedcommand*" -or
                        $action.Arguments -like "*hidden*" -or
                        $action.Arguments -like "*bypass*" -or
                        $action.Arguments -like "*downloadstring*" -or
                        $action.Arguments -like "*downloadfile*" -or
                        $action.Arguments -like "*webclient*") {
                        
                        Add-Finding -Category "Persistence" `
                            -Description "Suspicious scheduled task with encoded/obfuscated command" `
                            -Details "Task: $($task.TaskName), Path: $($task.TaskPath), Command: $($action.Execute) $($action.Arguments)" `
                            -Severity "High" `
                            -Recommendation "Investigate this scheduled task and remove if unauthorized"
                    }
                }
                
                # Check for tasks running from suspicious locations
                if ($action.Execute -like "*\Temp\*" -or 
                    $action.Execute -like "*\Windows\Temp\*" -or 
                    $action.Execute -like "*%TEMP%*" -or
                    $action.Execute -like "*\Users\Public\*" -or
                    $action.Execute -like "*\ProgramData\*") {
                    
                    Add-Finding -Category "Persistence" `
                        -Description "Scheduled task running from suspicious location" `
                        -Details "Task: $($task.TaskName), Path: $($task.TaskPath), Command: $($action.Execute) $($action.Arguments)" `
                        -Severity "High" `
                        -Recommendation "Investigate this scheduled task and remove if unauthorized"
                }
            }
        }
    }
}

# Function to check for suspicious files
function Find-SuspiciousFiles {
    Write-Verbose "Checking for suspicious files..."
    
    # Check for suspicious files in common locations
    $suspiciousLocations = @(
        "C:\Windows\Temp",
        "C:\Temp",
        "$env:TEMP",
        "C:\Users\Public",
        "C:\ProgramData"
    )
    
    $suspiciousExtensions = @("*.ps1", "*.vbs", "*.bat", "*.exe", "*.dll", "*.hta")
    
    foreach ($location in $suspiciousLocations) {
        if (Test-Path $location) {
            foreach ($ext in $suspiciousExtensions) {
                $files = Get-ChildItem -Path $location -Filter $ext -Recurse -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }
                
                foreach ($file in $files) {
                    Add-Finding -Category "Suspicious File" `
                        -Description "Potentially malicious file in suspicious location" `
                        -Details "File: $($file.FullName), Size: $($file.Length) bytes, Created: $($file.CreationTime), Modified: $($file.LastWriteTime)" `
                        -Severity "Medium" `
                        -Recommendation "Investigate this file and remove if malicious"
                }
            }
        }
    }
    
    # Check for alternate data streams (if thorough scan)
    if ($Thorough) {
        $locations = @("C:\Users", "C:\ProgramData")
        
        foreach ($location in $locations) {
            if (Test-Path $location) {
                $files = Get-ChildItem -Path $location -File -Recurse -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }
                
                foreach ($file in $files) {
                    $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue
                    $suspiciousStreams = $streams | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                    
                    if ($suspiciousStreams) {
                        foreach ($stream in $suspiciousStreams) {
                            Add-Finding -Category "Suspicious File" `
                                -Description "File with alternate data stream" `
                                -Details "File: $($file.FullName), Stream: $($stream.Stream), Size: $($stream.Length) bytes" `
                                -Severity "Medium" `
                                -Recommendation "Investigate this alternate data stream and remove if malicious"
                        }
                    }
                }
            }
        }
    }
}

# Function to check for suspicious event log entries
function Find-SuspiciousEventLogs {
    Write-Verbose "Checking for suspicious event log entries..."
    
    # Check for PowerShell script block logging (4104)
    try {
        $scriptBlockEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-PowerShell/Operational'
            Id = 4104
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $scriptBlockEvents) {
            $message = $event.Message
            
            # Check for suspicious PowerShell commands
            if ($message -match "DownloadString|DownloadFile|WebClient|Invoke-Expression|IEX|New-Object Net.WebClient|EncodedCommand|Hidden|Bypass|Shellcode|Mimikatz|Invoke-Mimikatz|PsExec|BloodHound|Empire|Covenant|Invoke-Command|Invoke-WMIMethod|WmiObject|Get-WmiObject") {
                Add-Finding -Category "Suspicious Activity" `
                    -Description "Suspicious PowerShell command detected" `
                    -Details "Time: $($event.TimeCreated), EventID: 4104, Command contains suspicious elements" `
                    -Severity "High" `
                    -Recommendation "Investigate this PowerShell activity"
            }
        }
    } catch {
        # Event log query may fail
    }
    
    # Check for account lockouts (4740)
    try {
        $lockoutEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4740
        } -MaxEvents 10 -ErrorAction SilentlyContinue
        
        if ($lockoutEvents.Count -gt 3) {
            Add-Finding -Category "Suspicious Activity" `
                -Description "Multiple account lockouts detected" `
                -Details "Count: $($lockoutEvents.Count) in recent events" `
                -Severity "Medium" `
                -Recommendation "Investigate potential brute force attempts"
        }
    } catch {
        # Event log query may fail
    }
    
    # Check for event log clearing (1102)
    try {
        $clearLogEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 1102
        } -MaxEvents 5 -ErrorAction SilentlyContinue
        
        if ($clearLogEvents) {
            foreach ($event in $clearLogEvents) {
                Add-Finding -Category "Suspicious Activity" `
                    -Description "Security event log was cleared" `
                    -Details "Time: $($event.TimeCreated), EventID: 1102" `
                    -Severity "High" `
                    -Recommendation "Investigate who cleared the security event log and why"
            }
        }
    } catch {
        # Event log query may fail
    }
}

# Main execution
try {
    $startTime = Get-Date
    Write-Host "Starting threat indicator detection..." -ForegroundColor Cyan
    
    # Run all detection functions
    Find-SuspiciousProcesses
    Find-SuspiciousNetworkConnections
    Find-SuspiciousRegistryEntries
    Find-SuspiciousScheduledTasks
    Find-SuspiciousFiles
    Find-SuspiciousEventLogs
    
    # Calculate statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $totalFindings = $threatIndicators.Count
    $highSeverity = ($threatIndicators | Where-Object { $_.Severity -eq "High" }).Count
    $mediumSeverity = ($threatIndicators | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowSeverity = ($threatIndicators | Where-Object { $_.Severity -eq "Low" }).Count
    
    # Generate summary
    $summary = [PSCustomObject]@{
        ScanDate = Get-Date
        ScanDuration = "$($duration.Minutes) minutes, $($duration.Seconds) seconds"
        TotalFindings = $totalFindings
        HighSeverityFindings = $highSeverity
        MediumSeverityFindings = $mediumSeverity
        LowSeverityFindings = $lowSeverity
        ComputerName = $env:COMPUTERNAME
        ScanType = if ($Thorough) { "Thorough" } else { "Standard" }
    }
    
    # Export results to CSV
    $threatIndicators | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "ThreatIndicators.csv") -NoTypeInformation
    
    # Export summary to CSV
    $summary | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "ScanSummary.csv") -NoTypeInformation
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Indicator Report</title>
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
        .findings {
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
        .high {
            background-color: #ffebee;
            color: #c62828;
        }
        .medium {
            background-color: #fff8e1;
            color: #ff8f00;
        }
        .low {
            background-color: #e8f5e9;
            color: #2e7d32;
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
        <h1>Threat Indicator Report</h1>
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-item"><strong>Computer:</strong> $($summary.ComputerName)</div>
            <div class="summary-item"><strong>Scan Date:</strong> $($summary.ScanDate)</div>
            <div class="summary-item"><strong>Scan Type:</strong> $($summary.ScanType)</div>
            <div class="summary-item"><strong>Duration:</strong> $($summary.ScanDuration)</div>
            <div class="summary-item"><strong>Total Findings:</strong> $($summary.TotalFindings)</div>
            <div class="summary-item"><strong>High Severity:</strong> $($summary.HighSeverityFindings)</div>
            <div class="summary-item"><strong>Medium Severity:</strong> $($summary.MediumSeverityFindings)</div>
            <div class="summary-item"><strong>Low Severity:</strong> $($summary.LowSeverityFindings)</div>
        </div>

        <div class="findings">
            <h2>Detected Threat Indicators</h2>
"@

    if ($threatIndicators.Count -gt 0) {
        $htmlReport += @"
            <table>
                <tr>
                    <th>Category</th>
                    <th>Description</th>
                    <th>Details</th>
                    <th>Severity</th>
                    <th>Recommendation</th>
                </tr>
"@

        foreach ($finding in $threatIndicators) {
            $severityClass = switch ($finding.Severity) {
                "High" { "high" }
                "Medium" { "medium" }
                "Low" { "low" }
                default { "" }
            }
            
            $htmlReport += @"
                <tr class="$severityClass">
                    <td>$($finding.Category)</td>
                    <td>$($finding.Description)</td>
                    <td>$($finding.Details)</td>
                    <td>$($finding.Severity)</td>
                    <td>$($finding.Recommendation)</td>
                </tr>
"@
        }
        
        $htmlReport += @"
            </table>
"@
    } else {
        $htmlReport += @"
            <p>No threat indicators were detected during this scan.</p>
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
    $htmlReport | Out-File -FilePath (Join-Path -Path $OutputPath -ChildPath "ThreatReport.html") -Encoding utf8
    
    # Display summary
    Write-Host "`nThreat Indicator Scan Summary:" -ForegroundColor Green
    Write-Host "===============================" -ForegroundColor Green
    Write-Host "Computer: $($summary.ComputerName)" -ForegroundColor White
    Write-Host "Scan Type: $($summary.ScanType)" -ForegroundColor White
    Write-Host "Scan Duration: $($summary.ScanDuration)" -ForegroundColor White
    Write-Host "Total Findings: $totalFindings" -ForegroundColor White
    Write-Host "High Severity Findings: $highSeverity" -ForegroundColor $(if ($highSeverity -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Severity Findings: $mediumSeverity" -ForegroundColor $(if ($mediumSeverity -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Low Severity Findings: $lowSeverity" -ForegroundColor $(if ($lowSeverity -gt 0) { "Cyan" } else { "Green" })
    Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
    
    # Open HTML report if on Windows
    if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.Platform -ne 'Unix') {
        $htmlReportPath = Join-Path -Path $OutputPath -ChildPath "ThreatReport.html"
        Start-Process $htmlReportPath
    }
    
    return $OutputPath
} catch {
    Write-Error "An error occurred during threat detection: $_"
    throw $_
} finally {
    Write-Host "Threat indicator detection completed." -ForegroundColor Cyan
}
