<#
.SYNOPSIS
    Performs a comprehensive security audit of a Windows system.
.DESCRIPTION
    This function collects security-related information including user accounts, 
    network configurations, running processes, and more.
.PARAMETER OutputDirectory
    Specifies the directory where the audit reports will be saved.
    Default is a timestamped directory in the user's Documents folder.
.EXAMPLE
    Get-SystemSecurityAudit -OutputDirectory "C:\AuditReports"
    
    Performs a security audit and saves the reports to C:\AuditReports.
.OUTPUTS
    System.String
    Returns the path to the directory containing the audit reports.
.NOTES
    File Name      : Get-SystemSecurityAudit.ps1
    Author         : Your Name
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges recommended
#>

function Get-SystemSecurityAudit {
    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDirectory = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
    )

    begin {
        # Create output directory if it doesn't exist
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }

        # Initialize results array
        $results = @()
    }

    process {
        try {
            # 1. System Information
            Write-Progress -Activity "Collecting system information..." -Status "System Info"
            $systemInfo = [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                OS = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
                Architecture = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).OSArchitecture
                LastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
                Uptime = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
                TimeCollected = Get-Date
            }
            $systemInfo | Export-Csv -Path "$OutputDirectory\SystemInfo.csv" -NoTypeInformation -Encoding UTF8
            $results += [PSCustomObject]@{
                Category = 'System Info'
                Status = 'Completed'
                File = 'SystemInfo.csv'
            }

            # 2. User Accounts
            Write-Progress -Activity "Collecting user information..." -Status "User Accounts"
            try {
                Get-LocalUser | 
                    Select-Object Name, Enabled, Description, LastLogon, PasswordLastSet, UserMayChangePassword, PasswordNeverExpires |
                    Export-Csv -Path "$OutputDirectory\LocalUsers.csv" -NoTypeInformation -Encoding UTF8
                $results += [PSCustomObject]@{
                    Category = 'User Accounts'
                    Status = 'Completed'
                    File = 'LocalUsers.csv'
                }
            } catch {
                Write-Warning "Failed to collect user accounts: $_"
                $results += [PSCustomObject]@{
                    Category = 'User Accounts'
                    Status = 'Failed'
                    File = 'N/A'
                    Error = $_.Exception.Message
                }
            }

            # 3. Network Information
            Write-Progress -Activity "Collecting network information..." -Status "Network Info"
            try {
                Get-NetTCPConnection -State Established -ErrorAction Stop |
                    Where-Object { $_.LocalAddress -notmatch '^::|^127\.' } |
                    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, 
                                @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
                    Export-Csv -Path "$OutputDirectory\NetworkConnections.csv" -NoTypeInformation -Encoding UTF8
                $results += [PSCustomObject]@{
                    Category = 'Network Connections'
                    Status = 'Completed'
                    File = 'NetworkConnections.csv'
                }
            } catch {
                Write-Warning "Failed to collect network information: $_"
                $results += [PSCustomObject]@{
                    Category = 'Network Connections'
                    Status = 'Failed'
                    File = 'N/A'
                    Error = $_.Exception.Message
                }
            }

            # 4. Installed Software
            Write-Progress -Activity "Collecting installed software..." -Status "Software Info"
            try {
                $software = @()
                $paths = @(
                    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
                    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                )
                
                foreach ($path in $paths) {
                    if (Test-Path -Path $path) {
                        $software += Get-ItemProperty -Path $path | 
                            Where-Object { $_.DisplayName } |
                            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString
                    }
                }
                
                $software | Sort-Object DisplayName |
                    Export-Csv -Path "$OutputDirectory\InstalledSoftware.csv" -NoTypeInformation -Encoding UTF8
                
                $results += [PSCustomObject]@{
                    Category = 'Installed Software'
                    Status = 'Completed'
                    File = 'InstalledSoftware.csv'
                }
            } catch {
                Write-Warning "Failed to collect installed software: $_"
                $results += [PSCustomObject]@{
                    Category = 'Installed Software'
                    Status = 'Failed'
                    File = 'N/A'
                    Error = $_.Exception.Message
                }
            }

            # 5. Scheduled Tasks
            Write-Progress -Activity "Collecting scheduled tasks..." -Status "Scheduled Tasks"
            try {
                if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
                    Get-ScheduledTask | 
                        Where-Object { $_.State -ne "Disabled" } |
                        Select-Object TaskName, TaskPath, State, 
                                    @{Name="Command";Expression={$_.Actions.Execute + " " + $_.Actions.Arguments}} |
                        Export-Csv -Path "$OutputDirectory\ScheduledTasks.csv" -NoTypeInformation -Encoding UTF8
                    
                    $results += [PSCustomObject]@{
                        Category = 'Scheduled Tasks'
                        Status = 'Completed'
                        File = 'ScheduledTasks.csv'
                    }
                } else {
                    throw "Get-ScheduledTask cmdlet not available"
                }
            } catch {
                Write-Warning "Failed to collect scheduled tasks: $_"
                $results += [PSCustomObject]@{
                    Category = 'Scheduled Tasks'
                    Status = 'Failed'
                    File = 'N/A'
                    Error = $_.Exception.Message
                }
            }

            # 6. Services
            Write-Progress -Activity "Collecting service information..." -Status "Services"
            try {
                Get-Service | 
                    Where-Object { $_.Status -eq "Running" -and $_.DisplayName -notmatch "Microsoft|Windows" } |
                    Select-Object DisplayName, Name, Status, StartType |
                    Export-Csv -Path "$OutputDirectory\RunningServices.csv" -NoTypeInformation -Encoding UTF8
                
                $results += [PSCustomObject]@{
                    Category = 'Running Services'
                    Status = 'Completed'
                    File = 'RunningServices.csv'
                }
            } catch {
                Write-Warning "Failed to collect service information: $_"
                $results += [PSCustomObject]@{
                    Category = 'Running Services'
                    Status = 'Failed'
                    File = 'N/A'
                    Error = $_.Exception.Message
                }
            }

            # 7. Firewall Rules
            Write-Progress -Activity "Collecting firewall rules..." -Status "Firewall"
            try {
                if (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue) {
                    Get-NetFirewallRule | 
                        Where-Object { $_.Enabled -eq "True" } |
                        Select-Object DisplayName, DisplayGroup, Enabled, Direction, Action, Profile |
                        Export-Csv -Path "$OutputDirectory\FirewallRules.csv" -NoTypeInformation -Encoding UTF8
                    
                    $results += [PSCustomObject]@{
                        Category = 'Firewall Rules'
                        Status = 'Completed'
                        File = 'FirewallRules.csv'
                    }
                } else {
                    throw "Get-NetFirewallRule cmdlet not available"
                }
            } catch {
                Write-Warning "Failed to collect firewall rules: $_"
                $results += [PSCustomObject]@{
                    Category = 'Firewall Rules'
                    Status = 'Failed'
                    File = 'N/A'
                    Error = $_.Exception.Message
                }
            }

            # Generate summary report
            $results | Export-Csv -Path "$OutputDirectory\AuditSummary.csv" -NoTypeInformation -Encoding UTF8
            
            # Display summary
            Write-Output "`n=== AUDIT SUMMARY ==="
            $results | Format-Table -AutoSize
            
            Write-Output "`nAudit reports have been saved to: $OutputDirectory"

        } catch {
            Write-Error "An error occurred during the audit: $_"
            throw $_
        } finally {
            Write-Progress -Activity "Audit" -Completed
        }
    }

    end {
        return $OutputDirectory
    }
}

# Export the function
Export-ModuleMember -Function Get-SystemSecurityAudit
