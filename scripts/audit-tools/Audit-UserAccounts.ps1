<#
.SYNOPSIS
    Performs a targeted audit of user accounts and permissions.
.DESCRIPTION
    This script audits user accounts, group memberships, and permissions.
    It focuses specifically on security-related aspects of user management.
.EXAMPLE
    .\Audit-UserAccounts.ps1 -OutputDirectory "C:\SecurityAudit\UserAccounts"
.NOTES
    File Name      : Audit-UserAccounts.ps1
    Author         : Windows Security Toolkit
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges recommended
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\UserAccountAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
)

# Ensure the script stops on errors
$ErrorActionPreference = 'Stop'

try {
    # Import the module
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\src\WindowsSecurityToolkit.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    Write-Host "=== Windows Security Toolkit - User Account Audit ===" -ForegroundColor Cyan
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Created output directory: $OutputDirectory" -ForegroundColor Green
    }
    
    Write-Host "Starting user account audit..." -ForegroundColor Yellow
    
    # Get local users
    Write-Host "Collecting local user information..." -ForegroundColor Yellow
    $localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, 
                                          PasswordRequired, PasswordNeverExpires, 
                                          UserMayChangePassword, Description
    $localUsers | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "LocalUsers.csv") -NoTypeInformation
    
    # Get local groups and memberships
    Write-Host "Collecting local group memberships..." -ForegroundColor Yellow
    $groups = Get-LocalGroup
    $groupMembers = @()
    
    foreach ($group in $groups) {
        try {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
            foreach ($member in $members) {
                $groupMembers += [PSCustomObject]@{
                    GroupName = $group.Name
                    MemberName = $member.Name
                    MemberType = $member.ObjectClass
                    PrincipalSource = $member.PrincipalSource
                }
            }
        } catch {
            Write-Warning "Could not get members for group $($group.Name): $_"
        }
    }
    
    $groupMembers | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "LocalGroupMembers.csv") -NoTypeInformation
    
    # Check for admin accounts
    Write-Host "Identifying administrative accounts..." -ForegroundColor Yellow
    $adminAccounts = $groupMembers | Where-Object { $_.GroupName -eq "Administrators" }
    $adminAccounts | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "AdminAccounts.csv") -NoTypeInformation
    
    # Check for accounts with password issues
    Write-Host "Identifying password security issues..." -ForegroundColor Yellow
    $passwordIssues = $localUsers | Where-Object { $_.Enabled -and ($_.PasswordNeverExpires -or -not $_.PasswordRequired) }
    $passwordIssues | Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "PasswordIssues.csv") -NoTypeInformation
    
    # Check for domain accounts if domain-joined
    if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
        Write-Host "Computer is domain-joined. Checking domain user information..." -ForegroundColor Yellow
        try {
            # Check if ActiveDirectory module is available
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction Stop
                
                # Get domain users
                $domainUsers = Get-ADUser -Filter * -Properties Name, Enabled, LastLogonDate, 
                                                    PasswordLastSet, PasswordNeverExpires, 
                                                    PasswordExpired, LockedOut
                $domainUsers | Select-Object Name, Enabled, LastLogonDate, 
                                       PasswordLastSet, PasswordNeverExpires, 
                                       PasswordExpired, LockedOut |
                              Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "DomainUsers.csv") -NoTypeInformation
                
                # Get domain admins
                $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | 
                                Get-ADUser -Properties Name, Enabled, LastLogonDate, PasswordLastSet
                $domainAdmins | Select-Object Name, Enabled, LastLogonDate, PasswordLastSet |
                               Export-Csv -Path (Join-Path -Path $OutputDirectory -ChildPath "DomainAdmins.csv") -NoTypeInformation
            } else {
                Write-Warning "ActiveDirectory module not available. Skipping domain user checks."
            }
        } catch {
            Write-Warning "Error accessing domain information: $_"
        }
    }
    
    Write-Host "`nUser account audit completed successfully!" -ForegroundColor Green
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
