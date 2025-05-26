<#
.SYNOPSIS
    Collects forensic evidence from a Windows system with proper hashing and chain of custody documentation.
.DESCRIPTION
    This script gathers key system artifacts that may be relevant for forensic investigation,
    including event logs, registry hives, system files, and user data. All collected data is
    hashed to maintain integrity and chain of custody documentation is generated.
.PARAMETER OutputPath
    Path where the collected evidence will be stored.
.PARAMETER IncludeUserProfiles
    If specified, collects user profile data which may contain personal information.
.PARAMETER CollectRegistry
    If specified, collects registry hives.
.PARAMETER CollectEventLogs
    If specified, collects Windows event logs.
.PARAMETER CollectBrowserData
    If specified, collects browser history and cache data.
.PARAMETER CollectAll
    If specified, collects all available evidence types.
.EXAMPLE
    .\Collect-ForensicEvidence.ps1 -OutputPath "D:\Evidence" -CollectAll
    
    Collects all available evidence types and stores them in D:\Evidence.
.EXAMPLE
    .\Collect-ForensicEvidence.ps1 -OutputPath "D:\Evidence" -CollectEventLogs -CollectRegistry
    
    Collects only event logs and registry hives and stores them in D:\Evidence.
.NOTES
    File Name      : Collect-ForensicEvidence.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges
    Legal Note     : This tool should only be used with proper authorization on systems you own or have permission to examine.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeUserProfiles,
    
    [Parameter(Mandatory = $false)]
    [switch]$CollectRegistry,
    
    [Parameter(Mandatory = $false)]
    [switch]$CollectEventLogs,
    
    [Parameter(Mandatory = $false)]
    [switch]$CollectBrowserData,
    
    [Parameter(Mandatory = $false)]
    [switch]$CollectAll
)

#Requires -RunAsAdministrator

# Initialize script
$ErrorActionPreference = "Stop"
$startTime = Get-Date
$hostname = $env:COMPUTERNAME
$evidenceDir = Join-Path -Path $OutputPath -ChildPath "$hostname-evidence-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$chainOfCustodyFile = Join-Path -Path $evidenceDir -ChildPath "ChainOfCustody.txt"
$logFile = Join-Path -Path $evidenceDir -ChildPath "Collection.log"

# If CollectAll is specified, enable all collection types
if ($CollectAll) {
    $IncludeUserProfiles = $true
    $CollectRegistry = $true
    $CollectEventLogs = $true
    $CollectBrowserData = $true
}

# Create evidence directory
function Initialize-EvidenceCollection {
    if (-not (Test-Path -Path $evidenceDir)) {
        New-Item -Path $evidenceDir -ItemType Directory -Force | Out-Null
    }
    
    # Initialize chain of custody document
    @"
CHAIN OF CUSTODY DOCUMENT
=========================
Evidence Collection ID: $hostname-$(Get-Date -Format 'yyyyMMdd-HHmmss')
System: $hostname
Collection Start: $startTime
Collected by: $env:USERNAME
Collection Tool: Windows Security Toolkit - Collect-ForensicEvidence.ps1

EVIDENCE ITEMS
=========================

"@ | Out-File -FilePath $chainOfCustodyFile -Encoding utf8
    
    # Initialize log file
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Starting forensic evidence collection on $hostname" | Out-File -FilePath $logFile -Encoding utf8
}

# Function to log actions
function Write-ForensicLog {
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
function Get-EvidenceHash {
    param (
        [string]$FilePath
    )
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash
    } catch {
        Write-ForensicLog "Failed to compute hash for $FilePath: $_" -Level "ERROR"
        return "HASH_COMPUTATION_FAILED"
    }
}

# Function to document evidence item
function Add-EvidenceItem {
    param (
        [string]$Description,
        [string]$Path,
        [string]$Hash
    )
    
    @"
Item: $Description
Path: $Path
Acquired: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
SHA256: $Hash
-------------------------------------------------

"@ | Out-File -FilePath $chainOfCustodyFile -Encoding utf8 -Append
}

# Function to collect system information
function Get-ForensicSystemInfo {
    $systemInfoDir = Join-Path -Path $evidenceDir -ChildPath "SystemInfo"
    New-Item -Path $systemInfoDir -ItemType Directory -Force | Out-Null
    
    Write-ForensicLog "Collecting system information..."
    
    # Basic system info
    $systemInfoFile = Join-Path -Path $systemInfoDir -ChildPath "SystemInfo.txt"
    systeminfo | Out-File -FilePath $systemInfoFile -Encoding utf8
    $hash = Get-EvidenceHash -FilePath $systemInfoFile
    Add-EvidenceItem -Description "System Information" -Path $systemInfoFile -Hash $hash
    
    # Running processes
    $processesFile = Join-Path -Path $systemInfoDir -ChildPath "RunningProcesses.csv"
    Get-Process | Select-Object Id, ProcessName, Path, Company, CPU, WorkingSet, StartTime | Export-Csv -Path $processesFile -NoTypeInformation
    $hash = Get-EvidenceHash -FilePath $processesFile
    Add-EvidenceItem -Description "Running Processes" -Path $processesFile -Hash $hash
    
    # Services
    $servicesFile = Join-Path -Path $systemInfoDir -ChildPath "Services.csv"
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv -Path $servicesFile -NoTypeInformation
    $hash = Get-EvidenceHash -FilePath $servicesFile
    Add-EvidenceItem -Description "Services" -Path $servicesFile -Hash $hash
    
    # Network configuration
    $networkConfigFile = Join-Path -Path $systemInfoDir -ChildPath "NetworkConfiguration.txt"
    ipconfig /all | Out-File -FilePath $networkConfigFile -Encoding utf8
    $hash = Get-EvidenceHash -FilePath $networkConfigFile
    Add-EvidenceItem -Description "Network Configuration" -Path $networkConfigFile -Hash $hash
    
    # Network connections
    $networkConnectionsFile = Join-Path -Path $systemInfoDir -ChildPath "NetworkConnections.txt"
    netstat -ano | Out-File -FilePath $networkConnectionsFile -Encoding utf8
    $hash = Get-EvidenceHash -FilePath $networkConnectionsFile
    Add-EvidenceItem -Description "Network Connections" -Path $networkConnectionsFile -Hash $hash
    
    # Scheduled tasks
    $scheduledTasksFile = Join-Path -Path $systemInfoDir -ChildPath "ScheduledTasks.csv"
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author | Export-Csv -Path $scheduledTasksFile -NoTypeInformation
    $hash = Get-EvidenceHash -FilePath $scheduledTasksFile
    Add-EvidenceItem -Description "Scheduled Tasks" -Path $scheduledTasksFile -Hash $hash
    
    # Installed software
    $installedSoftwareFile = Join-Path -Path $systemInfoDir -ChildPath "InstalledSoftware.csv"
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Where-Object { $_.DisplayName -ne $null } |
        Export-Csv -Path $installedSoftwareFile -NoTypeInformation
    $hash = Get-EvidenceHash -FilePath $installedSoftwareFile
    Add-EvidenceItem -Description "Installed Software (32-bit)" -Path $installedSoftwareFile -Hash $hash
    
    $installedSoftware64File = Join-Path -Path $systemInfoDir -ChildPath "InstalledSoftware64.csv"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Where-Object { $_.DisplayName -ne $null } |
        Export-Csv -Path $installedSoftware64File -NoTypeInformation
    $hash = Get-EvidenceHash -FilePath $installedSoftware64File
    Add-EvidenceItem -Description "Installed Software (64-bit)" -Path $installedSoftware64File -Hash $hash
    
    Write-ForensicLog "System information collection complete" -Level "SUCCESS"
}

# Function to collect event logs
function Get-ForensicEventLogs {
    if (-not $CollectEventLogs -and -not $CollectAll) {
        Write-ForensicLog "Skipping event log collection as requested"
        return
    }
    
    $eventLogsDir = Join-Path -Path $evidenceDir -ChildPath "EventLogs"
    New-Item -Path $eventLogsDir -ItemType Directory -Force | Out-Null
    
    Write-ForensicLog "Collecting Windows event logs..."
    
    $logNames = @(
        "Application",
        "System",
        "Security",
        "Setup",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Sysmon/Operational"
    )
    
    foreach ($logName in $logNames) {
        $sanitizedName = $logName -replace "/", "-"
        $outputFile = Join-Path -Path $eventLogsDir -ChildPath "$sanitizedName.evtx"
        
        try {
            if (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue) {
                wevtutil epl $logName $outputFile
                $hash = Get-EvidenceHash -FilePath $outputFile
                Add-EvidenceItem -Description "Event Log: $logName" -Path $outputFile -Hash $hash
                Write-ForensicLog "Collected event log: $logName"
            } else {
                Write-ForensicLog "Event log $logName not found on this system" -Level "WARNING"
            }
        } catch {
            Write-ForensicLog "Failed to collect event log $logName: $_" -Level "ERROR"
        }
    }
    
    Write-ForensicLog "Event log collection complete" -Level "SUCCESS"
}

# Function to collect registry hives
function Get-ForensicRegistry {
    if (-not $CollectRegistry -and -not $CollectAll) {
        Write-ForensicLog "Skipping registry collection as requested"
        return
    }
    
    $registryDir = Join-Path -Path $evidenceDir -ChildPath "Registry"
    New-Item -Path $registryDir -ItemType Directory -Force | Out-Null
    
    Write-ForensicLog "Collecting registry hives..."
    
    # Define registry hives to collect
    $hives = @(
        @{Name = "SYSTEM"; Path = "HKLM:\SYSTEM"},
        @{Name = "SOFTWARE"; Path = "HKLM:\SOFTWARE"},
        @{Name = "SECURITY"; Path = "HKLM:\SECURITY"},
        @{Name = "SAM"; Path = "HKLM:\SAM"}
    )
    
    foreach ($hive in $hives) {
        $outputFile = Join-Path -Path $registryDir -ChildPath "$($hive.Name).reg"
        
        try {
            # Export registry hive
            reg export "$($hive.Path -replace ':', '')" $outputFile /y | Out-Null
            
            if (Test-Path -Path $outputFile) {
                $hash = Get-EvidenceHash -FilePath $outputFile
                Add-EvidenceItem -Description "Registry Hive: $($hive.Name)" -Path $outputFile -Hash $hash
                Write-ForensicLog "Collected registry hive: $($hive.Name)"
            } else {
                Write-ForensicLog "Failed to export registry hive: $($hive.Name)" -Level "ERROR"
            }
        } catch {
            Write-ForensicLog "Error exporting registry hive $($hive.Name): $_" -Level "ERROR"
        }
    }
    
    # Export specific registry keys of interest
    $keysOfInterest = @(
        @{Name = "Run_Keys"; Path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
        @{Name = "RunOnce_Keys"; Path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"},
        @{Name = "Services"; Path = "HKLM\SYSTEM\CurrentControlSet\Services"},
        @{Name = "USBStor"; Path = "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"}
    )
    
    foreach ($key in $keysOfInterest) {
        $outputFile = Join-Path -Path $registryDir -ChildPath "$($key.Name).reg"
        
        try {
            reg export $key.Path $outputFile /y | Out-Null
            
            if (Test-Path -Path $outputFile) {
                $hash = Get-EvidenceHash -FilePath $outputFile
                Add-EvidenceItem -Description "Registry Key: $($key.Name)" -Path $outputFile -Hash $hash
                Write-ForensicLog "Collected registry key: $($key.Name)"
            } else {
                Write-ForensicLog "Failed to export registry key: $($key.Name)" -Level "WARNING"
            }
        } catch {
            Write-ForensicLog "Error exporting registry key $($key.Name): $_" -Level "ERROR"
        }
    }
    
    Write-ForensicLog "Registry collection complete" -Level "SUCCESS"
}

# Function to collect user profile data
function Get-ForensicUserProfiles {
    if (-not $IncludeUserProfiles -and -not $CollectAll) {
        Write-ForensicLog "Skipping user profile collection as requested"
        return
    }
    
    $userProfilesDir = Join-Path -Path $evidenceDir -ChildPath "UserProfiles"
    New-Item -Path $userProfilesDir -ItemType Directory -Force | Out-Null
    
    Write-ForensicLog "Collecting user profile data..."
    
    # Get list of user profiles
    $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { -not $_.Special }
    
    foreach ($profile in $userProfiles) {
        try {
            $profilePath = $profile.LocalPath
            $userName = Split-Path -Path $profilePath -Leaf
            $userDir = Join-Path -Path $userProfilesDir -ChildPath $userName
            New-Item -Path $userDir -ItemType Directory -Force | Out-Null
            
            Write-ForensicLog "Processing user profile: $userName"
            
            # Collect interesting files and folders
            $itemsToCollect = @(
                @{Path = "NTUSER.DAT"; Description = "User Registry Hive"},
                @{Path = "AppData\Roaming\Microsoft\Windows\Recent"; Description = "Recent Items"},
                @{Path = "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"; Description = "PowerShell History"},
                @{Path = "AppData\Local\Microsoft\Windows\WebCache"; Description = "Web Cache"},
                @{Path = "AppData\Local\Microsoft\Terminal Server Client\Cache"; Description = "RDP Cache"},
                @{Path = "Downloads"; Description = "Downloads Folder"}
            )
            
            foreach ($item in $itemsToCollect) {
                $sourcePath = Join-Path -Path $profilePath -ChildPath $item.Path
                $destPath = Join-Path -Path $userDir -ChildPath ($item.Path -replace "\\", "-")
                
                if (Test-Path -Path $sourcePath) {
                    try {
                        if ((Get-Item -Path $sourcePath) -is [System.IO.DirectoryInfo]) {
                            # It's a directory, create a ZIP archive
                            $zipPath = "$destPath.zip"
                            Compress-Archive -Path $sourcePath -DestinationPath $zipPath -Force
                            $hash = Get-EvidenceHash -FilePath $zipPath
                            Add-EvidenceItem -Description "User $userName - $($item.Description)" -Path $zipPath -Hash $hash
                        } else {
                            # It's a file, copy it directly
                            Copy-Item -Path $sourcePath -Destination $destPath -Force
                            $hash = Get-EvidenceHash -FilePath $destPath
                            Add-EvidenceItem -Description "User $userName - $($item.Description)" -Path $destPath -Hash $hash
                        }
                        Write-ForensicLog "Collected $($item.Description) for user $userName"
                    } catch {
                        Write-ForensicLog "Failed to collect $($item.Description) for user $userName: $_" -Level "ERROR"
                    }
                } else {
                    Write-ForensicLog "$($item.Description) not found for user $userName" -Level "WARNING"
                }
            }
        } catch {
            Write-ForensicLog "Error processing user profile $userName: $_" -Level "ERROR"
        }
    }
    
    Write-ForensicLog "User profile collection complete" -Level "SUCCESS"
}

# Function to collect browser data
function Get-ForensicBrowserData {
    if (-not $CollectBrowserData -and -not $CollectAll) {
        Write-ForensicLog "Skipping browser data collection as requested"
        return
    }
    
    $browserDataDir = Join-Path -Path $evidenceDir -ChildPath "BrowserData"
    New-Item -Path $browserDataDir -ItemType Directory -Force | Out-Null
    
    Write-ForensicLog "Collecting browser data..."
    
    # Get list of user profiles
    $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { -not $_.Special }
    
    foreach ($profile in $userProfiles) {
        try {
            $profilePath = $profile.LocalPath
            $userName = Split-Path -Path $profilePath -Leaf
            $userBrowserDir = Join-Path -Path $browserDataDir -ChildPath $userName
            New-Item -Path $userBrowserDir -ItemType Directory -Force | Out-Null
            
            Write-ForensicLog "Processing browser data for user: $userName"
            
            # Chrome
            $chromePath = Join-Path -Path $profilePath -ChildPath "AppData\Local\Google\Chrome\User Data\Default"
            if (Test-Path -Path $chromePath) {
                $chromeDataDir = Join-Path -Path $userBrowserDir -ChildPath "Chrome"
                New-Item -Path $chromeDataDir -ItemType Directory -Force | Out-Null
                
                $chromeItems = @(
                    @{Path = "History"; Description = "Chrome History"},
                    @{Path = "Bookmarks"; Description = "Chrome Bookmarks"},
                    @{Path = "Cookies"; Description = "Chrome Cookies"},
                    @{Path = "Login Data"; Description = "Chrome Login Data"},
                    @{Path = "Web Data"; Description = "Chrome Web Data"}
                )
                
                foreach ($item in $chromeItems) {
                    $sourcePath = Join-Path -Path $chromePath -ChildPath $item.Path
                    $destPath = Join-Path -Path $chromeDataDir -ChildPath $item.Path
                    
                    if (Test-Path -Path $sourcePath) {
                        try {
                            Copy-Item -Path $sourcePath -Destination $destPath -Force
                            $hash = Get-EvidenceHash -FilePath $destPath
                            Add-EvidenceItem -Description "User $userName - $($item.Description)" -Path $destPath -Hash $hash
                            Write-ForensicLog "Collected $($item.Description) for user $userName"
                        } catch {
                            Write-ForensicLog "Failed to collect $($item.Description) for user $userName: $_" -Level "ERROR"
                        }
                    } else {
                        Write-ForensicLog "$($item.Description) not found for user $userName" -Level "WARNING"
                    }
                }
            }
            
            # Firefox
            $firefoxPath = Join-Path -Path $profilePath -ChildPath "AppData\Roaming\Mozilla\Firefox\Profiles"
            if (Test-Path -Path $firefoxPath) {
                $firefoxDataDir = Join-Path -Path $userBrowserDir -ChildPath "Firefox"
                New-Item -Path $firefoxDataDir -ItemType Directory -Force | Out-Null
                
                # Get Firefox profile directories
                $firefoxProfiles = Get-ChildItem -Path $firefoxPath -Directory
                
                foreach ($ffProfile in $firefoxProfiles) {
                    $ffProfileDir = Join-Path -Path $firefoxDataDir -ChildPath $ffProfile.Name
                    New-Item -Path $ffProfileDir -ItemType Directory -Force | Out-Null
                    
                    $firefoxItems = @(
                        @{Path = "places.sqlite"; Description = "Firefox History and Bookmarks"},
                        @{Path = "cookies.sqlite"; Description = "Firefox Cookies"},
                        @{Path = "formhistory.sqlite"; Description = "Firefox Form History"},
                        @{Path = "logins.json"; Description = "Firefox Logins"}
                    )
                    
                    foreach ($item in $firefoxItems) {
                        $sourcePath = Join-Path -Path $ffProfile.FullName -ChildPath $item.Path
                        $destPath = Join-Path -Path $ffProfileDir -ChildPath $item.Path
                        
                        if (Test-Path -Path $sourcePath) {
                            try {
                                Copy-Item -Path $sourcePath -Destination $destPath -Force
                                $hash = Get-EvidenceHash -FilePath $destPath
                                Add-EvidenceItem -Description "User $userName - $($item.Description) (Profile: $($ffProfile.Name))" -Path $destPath -Hash $hash
                                Write-ForensicLog "Collected $($item.Description) for user $userName (Firefox Profile: $($ffProfile.Name))"
                            } catch {
                                Write-ForensicLog "Failed to collect $($item.Description) for user $userName (Firefox Profile: $($ffProfile.Name)): $_" -Level "ERROR"
                            }
                        } else {
                            Write-ForensicLog "$($item.Description) not found for user $userName (Firefox Profile: $($ffProfile.Name))" -Level "WARNING"
                        }
                    }
                }
            }
            
            # Edge
            $edgePath = Join-Path -Path $profilePath -ChildPath "AppData\Local\Microsoft\Edge\User Data\Default"
            if (Test-Path -Path $edgePath) {
                $edgeDataDir = Join-Path -Path $userBrowserDir -ChildPath "Edge"
                New-Item -Path $edgeDataDir -ItemType Directory -Force | Out-Null
                
                $edgeItems = @(
                    @{Path = "History"; Description = "Edge History"},
                    @{Path = "Bookmarks"; Description = "Edge Bookmarks"},
                    @{Path = "Cookies"; Description = "Edge Cookies"},
                    @{Path = "Login Data"; Description = "Edge Login Data"},
                    @{Path = "Web Data"; Description = "Edge Web Data"}
                )
                
                foreach ($item in $edgeItems) {
                    $sourcePath = Join-Path -Path $edgePath -ChildPath $item.Path
                    $destPath = Join-Path -Path $edgeDataDir -ChildPath $item.Path
                    
                    if (Test-Path -Path $sourcePath) {
                        try {
                            Copy-Item -Path $sourcePath -Destination $destPath -Force
                            $hash = Get-EvidenceHash -FilePath $destPath
                            Add-EvidenceItem -Description "User $userName - $($item.Description)" -Path $destPath -Hash $hash
                            Write-ForensicLog "Collected $($item.Description) for user $userName"
                        } catch {
                            Write-ForensicLog "Failed to collect $($item.Description) for user $userName: $_" -Level "ERROR"
                        }
                    } else {
                        Write-ForensicLog "$($item.Description) not found for user $userName" -Level "WARNING"
                    }
                }
            }
        } catch {
            Write-ForensicLog "Error processing browser data for user $userName: $_" -Level "ERROR"
        }
    }
    
    Write-ForensicLog "Browser data collection complete" -Level "SUCCESS"
}

# Function to create final evidence package
function Complete-EvidenceCollection {
    # Finalize chain of custody document
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    @"

COLLECTION SUMMARY
=========================
Collection End: $endTime
Total Duration: $($duration.Hours) hours, $($duration.Minutes) minutes, $($duration.Seconds) seconds
Evidence Package Hash: 

"@ | Out-File -FilePath $chainOfCustodyFile -Encoding utf8 -Append
    
    # Create evidence ZIP archive
    $evidenceZip = "$evidenceDir.zip"
    Write-ForensicLog "Creating evidence package: $evidenceZip"
    
    try {
        Compress-Archive -Path $evidenceDir -DestinationPath $evidenceZip -Force
        $packageHash = Get-EvidenceHash -FilePath $evidenceZip
        
        # Update chain of custody with package hash
        (Get-Content -Path $chainOfCustodyFile) -replace "Evidence Package Hash: ", "Evidence Package Hash: $packageHash" | 
            Set-Content -Path $chainOfCustodyFile
        
        # Update the archive with the updated chain of custody file
        Compress-Archive -Path $chainOfCustodyFile -Update -DestinationPath $evidenceZip
        
        Write-ForensicLog "Evidence collection complete. Package saved to: $evidenceZip" -Level "SUCCESS"
        Write-ForensicLog "Evidence package SHA256: $packageHash" -Level "SUCCESS"
        
        return $evidenceZip
    } catch {
        Write-ForensicLog "Failed to create evidence package: $_" -Level "ERROR"
        return $null
    }
}

# Main execution
try {
    # Initialize evidence collection
    Initialize-EvidenceCollection
    
    # Collect system information (always collected)
    Get-ForensicSystemInfo
    
    # Collect event logs if requested
    Get-ForensicEventLogs
    
    # Collect registry if requested
    Get-ForensicRegistry
    
    # Collect user profiles if requested
    Get-ForensicUserProfiles
    
    # Collect browser data if requested
    Get-ForensicBrowserData
    
    # Create final evidence package
    $evidencePackage = Complete-EvidenceCollection
    
    if ($evidencePackage) {
        Write-Host "`nForensic evidence collection complete!" -ForegroundColor Green
        Write-Host "Evidence package: $evidencePackage" -ForegroundColor Cyan
    } else {
        Write-Host "`nForensic evidence collection completed with errors. Check the log file for details." -ForegroundColor Yellow
    }
    
    return $evidencePackage
} catch {
    Write-ForensicLog "Critical error in evidence collection: $_" -Level "ERROR"
    Write-Host "Critical error in evidence collection: $_" -ForegroundColor Red
    return $null
}
