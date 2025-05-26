# 🏢 Active Directory Security Commands

This document provides essential PowerShell commands for auditing and securing Active Directory environments.

## 📋 Table of Contents
1. [Prerequisites](#prerequisites)
2. [User Auditing](#user-auditing)
3. [Group Auditing](#group-auditing)
4. [Password Policies](#password-policies)
5. [Group Policy Objects](#group-policy-objects)
6. [Replication](#replication)
7. [Privileged Access](#privileged-access)
8. [Security Logs](#security-logs)
9. [Reporting](#reporting)

## Prerequisites

```powershell
# Install required modules
Install-Module -Name ActiveDirectory -Force -AllowClobber -Scope CurrentUser
Install-Module -Name DSInternals -Force -AllowClobber -Scope CurrentUser

# Import modules
Import-Module ActiveDirectory
Import-Module DSInternals
```

## User Auditing

### List All Users
```powershell
# Get all domain users with key properties
Get-ADUser -Filter * -Properties * | 
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, 
                 PasswordLastSet, PasswordNeverExpires, PasswordExpired |
    Sort-Object Name | 
    Format-Table -AutoSize
```

### Find Inactive Users
```powershell
# Find users who haven't logged in for 90+ days
$90days = (Get-Date).AddDays(-90)
Get-ADUser -Filter {LastLogonDate -lt $90days -and Enabled -eq $true} -Properties LastLogonDate | 
    Select-Object Name, SamAccountName, LastLogonDate | 
    Sort-Object LastLogonDate | 
    Format-Table -AutoSize
```

### Password Policy Violations
```powershell
# Find users with password never expires
Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} -Properties * | 
    Select-Object Name, SamAccountName, PasswordLastSet, PasswordNeverExpires, LastLogonDate |
    Sort-Object Name | 
    Format-Table -AutoSize
```

## Group Auditing

### List Security Groups
```powershell
# Get all security groups
Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties * | 
    Select-Object Name, GroupCategory, GroupScope, Description |
    Sort-Object Name | 
    Format-Table -AutoSize
```

### Audit Admin Groups
```powershell
# Get members of Domain Admins group
Get-ADGroupMember -Identity "Domain Admins" -Recursive | 
    Get-ADUser -Properties * | 
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet |
    Format-Table -AutoSize

# Find users with admin rights across the domain
$adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$adminGroups | ForEach-Object {
    Write-Host "Members of $_ group:" -ForegroundColor Cyan
    Get-ADGroupMember -Identity $_ -Recursive | 
        Get-ADUser -Properties * | 
        Select-Object Name, SamAccountName, Enabled, LastLogonDate |
        Format-Table -AutoSize
}
```

## 🔒 Group Management

```powershell
# Get all security groups
Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties * | 
    Select-Object Name,GroupCategory,GroupScope,Description |
    Sort-Object Name | Format-Table -AutoSize

# Get members of Domain Admins group
Get-ADGroupMember -Identity "Domain Admins" -Recursive | 
    Get-ADUser -Properties * | 
    Select-Object Name,SamAccountName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires |
    Format-Table -AutoSize

# Find users with admin rights across the domain
$adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$adminGroups | ForEach-Object {
    Write-Host "Members of $_ group:" -ForegroundColor Cyan
    Get-ADGroupMember -Identity $_ -Recursive | 
        Get-ADUser -Properties * | 
        Select-Object Name,SamAccountName,Enabled,LastLogonDate |
        Format-Table -AutoSize
    Write-Host "`n"
}
```

## 🔐 Critical AD Security Groups

```powershell
# Define critical security groups to audit
$criticalGroups = @(
    "Domain Admins",        # Full administrative control over the domain
    "Enterprise Admins",    # Full administrative control over all domains in the forest
    "Schema Admins",       # Can modify the Active Directory schema
    "Server Operators",    # Can administer domain controllers
    "Backup Operators",    # Can bypass file permissions for backup purposes
    "Account Operators",   # Can create and modify user accounts
    "Domain Controllers",  # All domain controllers in the domain
    "Print Operators",     # Can manage printers and print queues
    "Administrators"       # Built-in administrators group
)

# Get membership information for each critical group
foreach ($group in $criticalGroups) {
    try {
        Write-Host "\n===== $group =====" -ForegroundColor Yellow
        
        # Get group details
        $groupInfo = Get-ADGroup -Identity $group -Properties Description,MemberOf,whenCreated,whenChanged -ErrorAction Stop
        Write-Host "Description: $($groupInfo.Description)" -ForegroundColor Cyan
        Write-Host "Created: $($groupInfo.whenCreated)" -ForegroundColor Cyan
        Write-Host "Last Modified: $($groupInfo.whenChanged)" -ForegroundColor Cyan
        
        # Get group members
        $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
        Write-Host "\nMembers ($($members.Count)):" -ForegroundColor Green
        
        # Process each member
        foreach ($member in $members) {
            if ($member.objectClass -eq "user") {
                $user = Get-ADUser -Identity $member.SID -Properties Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires
                Write-Host "  [User] $($user.Name) ($($user.SamAccountName))" -ForegroundColor White
                Write-Host "    Enabled: $($user.Enabled), Last Logon: $($user.LastLogonDate), Password Last Set: $($user.PasswordLastSet)" -ForegroundColor Gray
            }
            elseif ($member.objectClass -eq "group") {
                $nestedGroup = Get-ADGroup -Identity $member.SID -Properties Description
                Write-Host "  [Group] $($nestedGroup.Name) - $($nestedGroup.Description)" -ForegroundColor Magenta
                
                # Get nested group members count
                $nestedMembers = Get-ADGroupMember -Identity $nestedGroup.SID -ErrorAction SilentlyContinue
                Write-Host "    Contains $($nestedMembers.Count) members" -ForegroundColor Gray
            }
            elseif ($member.objectClass -eq "computer") {
                $computer = Get-ADComputer -Identity $member.SID -Properties OperatingSystem,LastLogonDate
                Write-Host "  [Computer] $($computer.Name) - $($computer.OperatingSystem)" -ForegroundColor Cyan
                Write-Host "    Last Logon: $($computer.LastLogonDate)" -ForegroundColor Gray
            }
            else {
                Write-Host "  [$($member.objectClass)] $($member.Name)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Warning "Could not process group '$group': $_"
    }
}

# Export all critical group members to CSV
$reportPath = "$env:USERPROFILE\Desktop\AD_Critical_Groups_$(Get-Date -Format 'yyyyMMdd').csv"
$allMembers = @()

foreach ($group in $criticalGroups) {
    try {
        Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | ForEach-Object {
            $member = $_
            $memberObject = $null
            
            if ($member.objectClass -eq "user") {
                $user = Get-ADUser -Identity $member.SID -Properties Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires -ErrorAction SilentlyContinue
                $memberObject = [PSCustomObject]@{
                    Group = $group
                    MemberType = "User"
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    Enabled = $user.Enabled
                    LastLogon = $user.LastLogonDate
                    PasswordLastSet = $user.PasswordLastSet
                    PasswordNeverExpires = $user.PasswordNeverExpires
                }
            }
            elseif ($member.objectClass -eq "group") {
                $nestedGroup = Get-ADGroup -Identity $member.SID -Properties Description -ErrorAction SilentlyContinue
                $memberObject = [PSCustomObject]@{
                    Group = $group
                    MemberType = "Group"
                    Name = $nestedGroup.Name
                    SamAccountName = $nestedGroup.SamAccountName
                    Enabled = "N/A"
                    LastLogon = "N/A"
                    PasswordLastSet = "N/A"
                    PasswordNeverExpires = "N/A"
                }
            }
            elseif ($member.objectClass -eq "computer") {
                $computer = Get-ADComputer -Identity $member.SID -Properties LastLogonDate,OperatingSystem -ErrorAction SilentlyContinue
                $memberObject = [PSCustomObject]@{
                    Group = $group
                    MemberType = "Computer"
                    Name = $computer.Name
                    SamAccountName = $computer.SamAccountName
                    Enabled = $computer.Enabled
                    LastLogon = $computer.LastLogonDate
                    PasswordLastSet = "N/A"
                    PasswordNeverExpires = "N/A"
                    OperatingSystem = $computer.OperatingSystem
                }
            }
            
            if ($memberObject) {
                $allMembers += $memberObject
            }
        }
    }
    catch {
        Write-Warning "Could not export members for group '$group': $_"
    }
}

$allMembers | Export-Csv -Path $reportPath -NoTypeInformation
Write-Host "\nExported all critical group members to: $reportPath" -ForegroundColor Green
```

### Find Domain Users and Computers

```powershell
# Get all domain users
Get-ADUser -Filter * -Properties Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires | 
    Select-Object Name,SamAccountName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\All_Domain_Users.csv" -NoTypeInformation

# Get all domain computers
Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate,Enabled | 
    Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate,Enabled | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\All_Domain_Computers.csv" -NoTypeInformation

# Get all domain controllers
Get-ADDomainController -Filter * | 
    Select-Object Name,Domain,Forest,IPv4Address,OperatingSystem,Site,IsGlobalCatalog,IsReadOnly | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\All_Domain_Controllers.csv" -NoTypeInformation
```

## Password Policies

### Domain Password Policy
```powershell
# Get domain password policy
Get-ADDefaultDomainPasswordPolicy

# Get fine-grained password policies
Get-ADFineGrainedPasswordPolicy -Filter *
```

### Account Lockout
```powershell
# Get account lockout policy
$domain = Get-ADDomain
$policyDN = "CN=Default Domain Policy,CN=System,$($domain.DistinguishedName)"
$policy = Get-ADObject -Identity $policyDN -Properties lockoutDuration, lockoutObservationWindow, lockoutThreshold

[PSCustomObject]@{
    LockoutDuration = [timespan]::FromTicks($policy.lockoutDuration)
    LockoutObservationWindow = [timespan]::FromTicks($policy.lockoutObservationWindow)
    LockoutThreshold = $policy.lockoutThreshold
} | Format-List

# Find locked out accounts
Search-ADAccount -LockedOut | 
    Select-Object Name, SamAccountName, LastBadPasswordAttempt, LockedOut |
    Format-Table -AutoSize
```

## Group Policy Objects

### List GPOs
```powershell
# Get all GPOs
Get-GPO -All | 
    Select-Object DisplayName, DomainName, Owner, Id, CreationTime, ModificationTime, GpoStatus |
    Sort-Object DisplayName | 
    Format-Table -AutoSize
```

### Security Policies
```powershell
# Get GPOs with password policies
Get-GPO -All | Where-Object {
    (Get-GPOReport -Guid $_.Id -ReportType Xml).GPO.Computer.ExtensionData | 
    Where-Object { $_.Name -eq 'Password' -and $_.Enabled -eq 'true' }
} | Select-Object DisplayName, Id | Format-Table -AutoSize

# Get GPOs with user rights assignments
Get-GPO -All | Where-Object {
    (Get-GPOReport -Guid $_.Id -ReportType Xml).GPO.Computer.ExtensionData | 
    Where-Object { $_.Name -eq 'User Rights Assignment' }
} | Select-Object DisplayName, Id | Format-Table -AutoSize
```

## Replication

### Replication Status
```powershell
# Get replication status
repadmin /replsummary

# Get replication partners
Get-ADReplicationPartnerMetadata -Target (Get-ADDomain).DNSRoot -Scope Server | 
    Select-Object Server, Partition, LastReplicationSuccess, LastReplicationAttempt, LastReplicationResult |
    Format-Table -AutoSize

# Check for replication errors
Get-ADReplicationFailure -Target (Get-ADDomain).DNSRoot
```

## Privileged Access

### Protected Accounts
```powershell
# Find users with AdminCount=1 (protected accounts)
Get-ADUser -LDAPFilter "(adminCount=1)" -Properties * | 
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, AdminCount |
    Sort-Object Name | 
    Format-Table -AutoSize
```

### Service Accounts
```powershell
# Find users with SPNs (potential service accounts)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties * | 
    Select-Object Name, SamAccountName, ServicePrincipalName, Enabled, LastLogonDate |
    Sort-Object Name | 
    Format-Table -AutoSize
```

## Security Logs

### Authentication Events
```powershell
# Get failed login attempts (last 24 hours)
$startTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$startTime} -MaxEvents 100 | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser = $_.Properties[5].Value
            SourceIP = $_.Properties[19].Value
            LogonType = $_.Properties[10].Value
            FailureReason = $_.Properties[8].Value
        }
    } | Format-Table -AutoSize
```

### Privileged Access
```powershell
# Get successful logons to privileged groups (last 7 days)
$startTime = (Get-Date).AddDays(-7)
$privilegedGroups = @("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549") # Local Admins, Remote Desktop Users, Backup Operators
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=$startTime} -MaxEvents 1000 | 
    Where-Object { $_.Properties[4].Value -in $privilegedGroups } |
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            User = $_.Properties[5].Value
            Domain = $_.Properties[6].Value
            LogonType = $_.Properties[8].Value
            LogonProcess = $_.Properties[9].Value
            AuthenticationPackage = $_.Properties[10].Value
            SourceIP = $_.Properties[18].Value
        }
    } | Format-Table -AutoSize
```

## Reporting

### Create Reports
```powershell
# Create a timestamp for the output files
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "$env:USERPROFILE\ADAudit_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Export all users
Get-ADUser -Filter * -Properties * | 
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, 
                 PasswordLastSet, PasswordNeverExpires, PasswordExpired, 
                 LockedOut, LastBadPasswordAttempt |
    Export-Csv -Path "$outputDir\AD_Users.csv" -NoTypeInformation

# Export privileged group members
$groups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", 
            "Account Operators", "Server Operators", "Print Operators", "Backup Operators")
$groupMembers = @()

foreach ($group in $groups) {
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop | 
            Get-ADUser -Properties * | 
            Select-Object @{Name="Group";Expression={$group}}, 
                         Name, SamAccountName, Enabled, LastLogonDate
        $groupMembers += $members
    } catch {
        Write-Warning "Error processing group $group : $_"
    }
}

$groupMembers | Export-Csv -Path "$outputDir\Privileged_Group_Members.csv" -NoTypeInformation

Write-Host "AD audit results saved to: $outputDir" -ForegroundColor Green
```

### Quick Checks
```powershell
# Find users with password not required
Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} -Properties * | 
    Select-Object Name, SamAccountName, PasswordNotRequired, PasswordLastSet, LastLogonDate |
    Sort-Object Name | 
    Format-Table -AutoSize

# Find inactive computer accounts (not logged in for 90+ days)
$90days = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonTimeStamp -lt $90days} -Properties LastLogonTimeStamp | 
    Select-Object Name, LastLogonTimeStamp | 
    Sort-Object LastLogonTimeStamp | 
    Format-Table -AutoSize

# Find users with Kerberos pre-authentication disabled (vulnerable to AS-REP roasting)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -Properties DoesNotRequirePreAuth | 
    Select-Object Name, SamAccountName, DoesNotRequirePreAuth |
    Sort-Object Name | 
    Format-Table -AutoSize
```
