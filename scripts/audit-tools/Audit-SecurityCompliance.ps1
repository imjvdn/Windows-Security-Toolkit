<#
.SYNOPSIS
    Audits Windows system against security compliance benchmarks.
.DESCRIPTION
    This script evaluates the current Windows system against common security
    benchmarks like CIS (Center for Internet Security) and NIST (National
    Institute of Standards and Technology) guidelines. It generates a compliance
    report showing which security settings are compliant and which need attention.
.PARAMETER BenchmarkType
    Specifies the security benchmark to audit against. Valid options are 'CIS' and 'NIST'.
.PARAMETER OutputPath
    Specifies the path where the compliance report will be saved.
.EXAMPLE
    .\Audit-SecurityCompliance.ps1 -BenchmarkType CIS -OutputPath "C:\Reports"
    
    Audits the system against CIS benchmarks and saves the report to C:\Reports.
.NOTES
    File Name      : Audit-SecurityCompliance.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('CIS', 'NIST')]
    [string]$BenchmarkType = 'CIS',
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SecurityCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
)

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Initialize results array
$complianceResults = @()

# Function to check password policy compliance
function Test-PasswordPolicy {
    Write-Verbose "Checking password policy settings..."
    
    $passwordPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue
    
    $results = @()
    
    # Check if LM hashes are disabled
    $results += [PSCustomObject]@{
        CheckID = "PWD-001"
        Category = "Password Policy"
        Description = "LM hashes should be disabled"
        ExpectedValue = 1
        ActualValue = $passwordPolicy.NoLMHash
        Status = if ($passwordPolicy.NoLMHash -eq 1) { "Compliant" } else { "Non-Compliant" }
        Remediation = "Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash to 1"
    }
    
    # Get password policy
    $securityPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ErrorAction SilentlyContinue
    
    # Check minimum password length
    $minPwdLength = (net accounts | Where-Object { $_ -match 'Minimum password length' }) -replace '.*:\s*', ''
    $results += [PSCustomObject]@{
        CheckID = "PWD-002"
        Category = "Password Policy"
        Description = "Minimum password length should be at least 14 characters"
        ExpectedValue = "≥ 14"
        ActualValue = $minPwdLength
        Status = if ([int]$minPwdLength -ge 14) { "Compliant" } else { "Non-Compliant" }
        Remediation = "Set minimum password length to at least 14 characters using Group Policy"
    }
    
    return $results
}

# Function to check account lockout policy
function Test-AccountLockoutPolicy {
    Write-Verbose "Checking account lockout policy..."
    
    $results = @()
    
    # Get account lockout threshold
    $lockoutThreshold = (net accounts | Where-Object { $_ -match 'Lockout threshold' }) -replace '.*:\s*', ''
    $results += [PSCustomObject]@{
        CheckID = "ACC-001"
        Category = "Account Lockout Policy"
        Description = "Account lockout threshold should be set to 5 or fewer invalid logon attempts"
        ExpectedValue = "≤ 5"
        ActualValue = $lockoutThreshold
        Status = if ($lockoutThreshold -ne "Never" -and [int]$lockoutThreshold -le 5) { "Compliant" } else { "Non-Compliant" }
        Remediation = "Set account lockout threshold to 5 or fewer invalid attempts using Group Policy"
    }
    
    # Get lockout duration
    $lockoutDuration = (net accounts | Where-Object { $_ -match 'Lockout duration' }) -replace '.*:\s*', ''
    $results += [PSCustomObject]@{
        CheckID = "ACC-002"
        Category = "Account Lockout Policy"
        Description = "Account lockout duration should be set to 15 minutes or more"
        ExpectedValue = "≥ 15"
        ActualValue = $lockoutDuration
        Status = if ($lockoutDuration -ne "Never" -and [int]$lockoutDuration -ge 15) { "Compliant" } else { "Non-Compliant" }
        Remediation = "Set account lockout duration to at least 15 minutes using Group Policy"
    }
    
    return $results
}

# Function to check audit policy
function Test-AuditPolicy {
    Write-Verbose "Checking audit policy settings..."
    
    $results = @()
    
    # Get audit policy settings
    $auditPolicy = auditpol /get /category:* /r | ConvertFrom-Csv
    
    # Check account logon auditing
    $accountLogonAudit = $auditPolicy | Where-Object { $_."Subcategory" -eq "Credential Validation" }
    $results += [PSCustomObject]@{
        CheckID = "AUD-001"
        Category = "Audit Policy"
        Description = "Credential Validation auditing should be enabled for Success and Failure"
        ExpectedValue = "Success and Failure"
        ActualValue = $accountLogonAudit."Inclusion Setting"
        Status = if ($accountLogonAudit."Inclusion Setting" -eq "Success and Failure") { "Compliant" } else { "Non-Compliant" }
        Remediation = "Enable Success and Failure auditing for Credential Validation using Group Policy"
    }
    
    # Check account management auditing
    $accountManagementAudit = $auditPolicy | Where-Object { $_."Subcategory" -eq "User Account Management" }
    $results += [PSCustomObject]@{
        CheckID = "AUD-002"
        Category = "Audit Policy"
        Description = "User Account Management auditing should be enabled for Success and Failure"
        ExpectedValue = "Success and Failure"
        ActualValue = $accountManagementAudit."Inclusion Setting"
        Status = if ($accountManagementAudit."Inclusion Setting" -eq "Success and Failure") { "Compliant" } else { "Non-Compliant" }
        Remediation = "Enable Success and Failure auditing for User Account Management using Group Policy"
    }
    
    return $results
}

# Function to check firewall settings
function Test-FirewallSettings {
    Write-Verbose "Checking Windows Firewall settings..."
    
    $results = @()
    
    # Get firewall profiles
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    
    foreach ($profile in $firewallProfiles) {
        $results += [PSCustomObject]@{
            CheckID = "FW-00$($firewallProfiles.IndexOf($profile) + 1)"
            Category = "Windows Firewall"
            Description = "$($profile.Name) profile should be enabled"
            ExpectedValue = "True"
            ActualValue = $profile.Enabled
            Status = if ($profile.Enabled -eq $true) { "Compliant" } else { "Non-Compliant" }
            Remediation = "Enable the $($profile.Name) firewall profile using Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True"
        }
    }
    
    return $results
}

# Function to check Windows Update settings
function Test-WindowsUpdateSettings {
    Write-Verbose "Checking Windows Update settings..."
    
    $results = @()
    
    # Get Windows Update settings
    $auSettings = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Settings
    
    $results += [PSCustomObject]@{
        CheckID = "UPD-001"
        Category = "Windows Update"
        Description = "Automatic Updates should be enabled"
        ExpectedValue = "True"
        ActualValue = $auSettings.NotificationLevel -ge 3
        Status = if ($auSettings.NotificationLevel -ge 3) { "Compliant" } else { "Non-Compliant" }
        Remediation = "Enable Automatic Updates through Group Policy or Settings app"
    }
    
    return $results
}

# Function to check BitLocker settings
function Test-BitLockerSettings {
    Write-Verbose "Checking BitLocker settings..."
    
    $results = @()
    
    # Check if BitLocker is available
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    
    if ($bitlockerVolumes) {
        foreach ($volume in $bitlockerVolumes) {
            if ($volume.VolumeType -eq 'OperatingSystem') {
                $results += [PSCustomObject]@{
                    CheckID = "BL-001"
                    Category = "BitLocker"
                    Description = "BitLocker should be enabled on the OS drive"
                    ExpectedValue = "On"
                    ActualValue = $volume.ProtectionStatus
                    Status = if ($volume.ProtectionStatus -eq 'On') { "Compliant" } else { "Non-Compliant" }
                    Remediation = "Enable BitLocker on the OS drive using Enable-BitLocker cmdlet or BitLocker Control Panel"
                }
            }
        }
    } else {
        $results += [PSCustomObject]@{
            CheckID = "BL-001"
            Category = "BitLocker"
            Description = "BitLocker should be enabled on the OS drive"
            ExpectedValue = "On"
            ActualValue = "Not Available"
            Status = "Non-Compliant"
            Remediation = "Install BitLocker and enable it on the OS drive"
        }
    }
    
    return $results
}

# Main execution
try {
    Write-Host "Starting Security Compliance Audit against $BenchmarkType benchmarks..." -ForegroundColor Cyan
    
    # Run all compliance checks
    $complianceResults += Test-PasswordPolicy
    $complianceResults += Test-AccountLockoutPolicy
    $complianceResults += Test-AuditPolicy
    $complianceResults += Test-FirewallSettings
    $complianceResults += Test-WindowsUpdateSettings
    $complianceResults += Test-BitLockerSettings
    
    # Calculate compliance statistics
    $totalChecks = $complianceResults.Count
    $compliantChecks = ($complianceResults | Where-Object { $_.Status -eq "Compliant" }).Count
    $nonCompliantChecks = $totalChecks - $compliantChecks
    $compliancePercentage = [math]::Round(($compliantChecks / $totalChecks) * 100, 2)
    
    # Generate summary
    $summary = [PSCustomObject]@{
        BenchmarkType = $BenchmarkType
        TotalChecks = $totalChecks
        CompliantChecks = $compliantChecks
        NonCompliantChecks = $nonCompliantChecks
        CompliancePercentage = $compliancePercentage
        ScanDate = Get-Date
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    }
    
    # Export results to CSV
    $complianceResults | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "ComplianceDetails.csv") -NoTypeInformation
    
    # Export summary to CSV
    $summary | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "ComplianceSummary.csv") -NoTypeInformation
    
    # Display summary
    Write-Host "`nCompliance Summary:" -ForegroundColor Green
    Write-Host "===================" -ForegroundColor Green
    Write-Host "Benchmark Type: $BenchmarkType" -ForegroundColor White
    Write-Host "Total Checks: $totalChecks" -ForegroundColor White
    Write-Host "Compliant Checks: $compliantChecks" -ForegroundColor Green
    Write-Host "Non-Compliant Checks: $nonCompliantChecks" -ForegroundColor Red
    Write-Host "Compliance Percentage: $compliancePercentage%" -ForegroundColor $(if ($compliancePercentage -ge 80) { "Green" } elseif ($compliancePercentage -ge 60) { "Yellow" } else { "Red" })
    Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
    
    return $OutputPath
} catch {
    Write-Error "An error occurred during the compliance audit: $_"
    throw $_
} finally {
    Write-Host "Compliance audit completed." -ForegroundColor Cyan
}
