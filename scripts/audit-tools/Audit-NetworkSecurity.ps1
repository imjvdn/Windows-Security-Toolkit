<#
.SYNOPSIS
    Performs a targeted audit of network security settings and connections.
.DESCRIPTION
    This script audits network configurations, active connections, firewall rules,
    and other network-related security settings.
.EXAMPLE
    .\Audit-NetworkSecurity.ps1 -OutputDirectory "C:\SecurityAudit\NetworkSecurity"
.NOTES
    File Name      : Audit-NetworkSecurity.ps1
    Author         : Windows Security Toolkit
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges recommended
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\NetworkAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
)

# Ensure the script stops on errors
$ErrorActionPreference = 'Stop'

try {
    # Import the module
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\src\WindowsSecurityToolkit.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    Write-Host "=== Windows Security Toolkit - Network Security Audit ===" -ForegroundColor Cyan
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $OutputDirectory" -ForegroundColor Green
    }
    
    Write-Host "Starting network security audit..." -ForegroundColor Yellow
    
    # Get network adapter configuration
    Write-Host "Collecting network adapter information..." -ForegroundColor Yellow
    $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | 
                       Select-Object Name, InterfaceDescription, Status, MacAddress, 
                                     LinkSpeed, MediaType, PhysicalMediaType, DriverVersion
    $networkAdapters | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "NetworkAdapters.csv") -NoTypeInformation
    
    # Get IP configuration
    Write-Host "Collecting IP configuration..." -ForegroundColor Yellow
    $ipConfig = Get-NetIPConfiguration | 
                Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv4DefaultGateway, 
                              DNSServer, NetProfile.Name
    $ipConfig | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "IPConfiguration.csv") -NoTypeInformation
    
    # Get active TCP connections
    Write-Host "Collecting active network connections..." -ForegroundColor Yellow
    $connections = Get-NetTCPConnection -State Established | 
                   Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
                                 @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, 
                                 @{Name="PID"; Expression={$_.OwningProcess}}
    $connections | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "ActiveConnections.csv") -NoTypeInformation
    
    # Get listening ports
    Write-Host "Collecting listening ports..." -ForegroundColor Yellow
    $listeningPorts = Get-NetTCPConnection -State Listen | 
                      Select-Object LocalAddress, LocalPort, State, 
                                    @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, 
                                    @{Name="PID"; Expression={$_.OwningProcess}}
    $listeningPorts | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "ListeningPorts.csv") -NoTypeInformation
    
    # Get firewall profiles
    Write-Host "Collecting firewall profiles..." -ForegroundColor Yellow
    $firewallProfiles = Get-NetFirewallProfile | 
                        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, 
                                      LogAllowed, LogBlocked, LogFileName
    $firewallProfiles | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "FirewallProfiles.csv") -NoTypeInformation
    
    # Get enabled inbound firewall rules
    Write-Host "Collecting enabled inbound firewall rules..." -ForegroundColor Yellow
    $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True | 
                    Select-Object Name, DisplayName, Description, Direction, Action, 
                                  @{Name="Protocol"; Expression={($_ | Get-NetFirewallPortFilter).Protocol}}, 
                                  @{Name="LocalPort"; Expression={($_ | Get-NetFirewallPortFilter).LocalPort}}, 
                                  @{Name="RemotePort"; Expression={($_ | Get-NetFirewallPortFilter).RemotePort}}, 
                                  @{Name="Program"; Expression={($_ | Get-NetFirewallApplicationFilter).Program}}, 
                                  Enabled, Profile
    $inboundRules | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "InboundFirewallRules.csv") -NoTypeInformation
    
    # Get network shares
    Write-Host "Collecting network shares..." -ForegroundColor Yellow
    $shares = Get-SmbShare | Where-Object { $_.Special -eq $false } | 
              Select-Object Name, Path, Description, CurrentUsers, ShareState, 
                            FolderEnumerationMode, CachingMode, SecurityDescriptor
    $shares | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "NetworkShares.csv") -NoTypeInformation
    
    # Get DNS cache
    Write-Host "Collecting DNS cache..." -ForegroundColor Yellow
    $dnsCache = Get-DnsClientCache | 
                Select-Object Entry, RecordName, RecordType, Status, Section, TimeToLive, DataLength, Data
    $dnsCache | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "DNSCache.csv") -NoTypeInformation
    
    # Check for SMB1 protocol (security risk)
    Write-Host "Checking SMB protocol versions..." -ForegroundColor Yellow
    $smbProtocols = Get-SmbServerConfiguration | 
                    Select-Object EnableSMB1Protocol, EnableSMB2Protocol
    $smbProtocols | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "SMBProtocols.csv") -NoTypeInformation
    
    Write-Host "`nNetwork security audit completed successfully!" -ForegroundColor Green
    Write-Host "Reports saved to: $OutputDirectory" -ForegroundColor Cyan
    
    # Offer to open the output directory
    $openFolder = Read-Host "`nWould you like to open the output directory? (Y/N)"
    if ($openFolder -match '^[Yy]') {
        Invoke-Item -Path $OutputDirectory
    }
    
} catch {
    Write-Error "An error occurred: $_"
    Write-Error $_.ScriptStackTrace
    exit 1
} finally {
    # Clean up if needed
    if (Get-Module -Name WindowsSecurityToolkit) {
        Remove-Module -Name WindowsSecurityToolkit -ErrorAction SilentlyContinue
    }
}
