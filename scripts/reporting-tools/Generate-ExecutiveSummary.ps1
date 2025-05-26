<#
.SYNOPSIS
    Generates an executive summary report from security audit data.
.DESCRIPTION
    This script analyzes security audit data and creates a concise executive summary
    with key findings, risk assessments, and recommended actions.
.EXAMPLE
    .\Generate-ExecutiveSummary.ps1 -AuditDirectory "C:\SecurityAudit\SystemAudit_20250526_123456"
.NOTES
    File Name      : Generate-ExecutiveSummary.ps1
    Author         : Windows Security Toolkit
    Prerequisite   : PowerShell 5.1 or later
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$AuditDirectory,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = (Join-Path -Path $AuditDirectory -ChildPath "ExecutiveSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').pdf")
)

# Ensure the script stops on errors
$ErrorActionPreference = 'Stop'

function Get-SecurityRiskLevel {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [object]$Data
    )
    
    $riskLevel = "Low"
    $findings = @()
    
    switch ($Category) {
        "UserAccounts" {
            # Check for admin accounts
            $adminAccounts = $Data | Where-Object { $_.GroupName -eq "Administrators" }
            if ($adminAccounts.Count -gt 3) {
                $riskLevel = "High"
                $findings += "Excessive number of administrator accounts: $($adminAccounts.Count)"
            }
            
            # Check for password issues
            $passwordIssues = $Data | Where-Object { $_.Enabled -and ($_.PasswordNeverExpires -or -not $_.PasswordRequired) }
            if ($passwordIssues.Count -gt 0) {
                $riskLevel = "High"
                $findings += "Accounts with password security issues: $($passwordIssues.Count)"
            }
        }
        "NetworkSecurity" {
            # Check for open ports
            $listeningPorts = $Data | Where-Object { $_.LocalAddress -eq "0.0.0.0" }
            if ($listeningPorts.Count -gt 5) {
                $riskLevel = "Medium"
                $findings += "High number of open listening ports: $($listeningPorts.Count)"
            }
            
            # Check for SMB1 (vulnerable)
            $smbProtocols = $Data | Where-Object { $_.EnableSMB1Protocol -eq $true }
            if ($smbProtocols.Count -gt 0) {
                $riskLevel = "High"
                $findings += "SMBv1 protocol is enabled (security vulnerability)"
            }
        }
        "SystemSecurity" {
            # Check for missing updates
            $missingUpdates = $Data | Where-Object { $_.Status -eq "Missing" }
            if ($missingUpdates.Count -gt 10) {
                $riskLevel = "High"
                $findings += "High number of missing security updates: $($missingUpdates.Count)"
            } elseif ($missingUpdates.Count -gt 5) {
                $riskLevel = "Medium"
                $findings += "Several missing security updates: $($missingUpdates.Count)"
            }
        }
        default {
            $riskLevel = "Unknown"
        }
    }
    
    return @{
        RiskLevel = $riskLevel
        Findings = $findings
    }
}

try {
    # Verify the audit directory exists
    if (-not (Test-Path -Path $AuditDirectory)) {
        throw "Audit directory not found: $AuditDirectory"
    }
    
    # Get all CSV files in the audit directory
    $csvFiles = Get-ChildItem -Path $AuditDirectory -Filter "*.csv"
    if ($csvFiles.Count -eq 0) {
        throw "No CSV files found in the audit directory"
    }
    
    Write-Host "Analyzing $($csvFiles.Count) audit files for executive summary..." -ForegroundColor Yellow
    
    # Get system information
    $computerInfo = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        ReportGenerated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AuditDirectory = $AuditDirectory
    }
    
    # Categorize and analyze audit data
    $securityRisks = @()
    $recommendations = @()
    
    # Check for user account issues
    $userFiles = $csvFiles | Where-Object { $_.Name -match "User|Account|Admin|Password|Group|Member" }
    foreach ($file in $userFiles) {
        $data = Import-Csv -Path $file.FullName
        $analysis = Get-SecurityRiskLevel -Category "UserAccounts" -Data $data
        
        if ($analysis.RiskLevel -ne "Low") {
            $securityRisks += [PSCustomObject]@{
                Category = "User Account Security"
                RiskLevel = $analysis.RiskLevel
                Findings = $analysis.Findings -join "; "
                Source = $file.Name
            }
            
            # Add recommendations based on findings
            if ($analysis.Findings -match "administrator accounts") {
                $recommendations += "Reduce the number of administrator accounts to the minimum required"
            }
            if ($analysis.Findings -match "password security issues") {
                $recommendations += "Enforce password policies for all accounts (expiration, complexity)"
            }
        }
    }
    
    # Check for network security issues
    $networkFiles = $csvFiles | Where-Object { $_.Name -match "Network|Connection|IP|DNS|Firewall|Port|Share" }
    foreach ($file in $networkFiles) {
        $data = Import-Csv -Path $file.FullName
        $analysis = Get-SecurityRiskLevel -Category "NetworkSecurity" -Data $data
        
        if ($analysis.RiskLevel -ne "Low") {
            $securityRisks += [PSCustomObject]@{
                Category = "Network Security"
                RiskLevel = $analysis.RiskLevel
                Findings = $analysis.Findings -join "; "
                Source = $file.Name
            }
            
            # Add recommendations based on findings
            if ($analysis.Findings -match "listening ports") {
                $recommendations += "Review and close unnecessary open ports"
            }
            if ($analysis.Findings -match "SMBv1") {
                $recommendations += "Disable SMBv1 protocol immediately (critical security vulnerability)"
            }
        }
    }
    
    # Check for system security issues
    $systemFiles = $csvFiles | Where-Object { $_.Name -match "System|Hardware|Software|Service|Process|Task" }
    foreach ($file in $systemFiles) {
        $data = Import-Csv -Path $file.FullName
        $analysis = Get-SecurityRiskLevel -Category "SystemSecurity" -Data $data
        
        if ($analysis.RiskLevel -ne "Low") {
            $securityRisks += [PSCustomObject]@{
                Category = "System Security"
                RiskLevel = $analysis.RiskLevel
                Findings = $analysis.Findings -join "; "
                Source = $file.Name
            }
            
            # Add recommendations based on findings
            if ($analysis.Findings -match "security updates") {
                $recommendations += "Install all missing security updates as soon as possible"
            }
        }
    }
    
    # Add default recommendations if none were found
    if ($recommendations.Count -eq 0) {
        $recommendations += "Conduct regular security audits"
        $recommendations += "Implement security baseline configurations"
        $recommendations += "Maintain up-to-date security patches"
    }
    
    # De-duplicate recommendations
    $recommendations = $recommendations | Select-Object -Unique
    
    # Calculate overall risk level
    $overallRisk = "Low"
    if ($securityRisks | Where-Object { $_.RiskLevel -eq "High" }) {
        $overallRisk = "High"
    } elseif ($securityRisks | Where-Object { $_.RiskLevel -eq "Medium" }) {
        $overallRisk = "Medium"
    }
    
    # Generate the executive summary report
    $reportContent = @"
# Executive Security Summary

## System Information
- **Computer Name:** $($computerInfo.ComputerName)
- **OS Version:** $($computerInfo.OSVersion)
- **Report Generated:** $($computerInfo.ReportGenerated)
- **Audit Source:** $($computerInfo.AuditDirectory)

## Overall Security Assessment
- **Risk Level:** $overallRisk
- **Files Analyzed:** $($csvFiles.Count)
- **Security Issues Found:** $($securityRisks.Count)

## Key Findings
"@

    if ($securityRisks.Count -gt 0) {
        foreach ($risk in $securityRisks) {
            $reportContent += @"

### $($risk.Category) - $($risk.RiskLevel) Risk
- $($risk.Findings)
"@
        }
    } else {
        $reportContent += @"

No significant security issues were found during this audit.
"@
    }

    $reportContent += @"

## Recommendations
"@

    foreach ($recommendation in $recommendations) {
        $reportContent += @"

- $recommendation
"@
    }

    $reportContent += @"

## Next Steps
1. Review the detailed audit reports for more information
2. Prioritize addressing high-risk issues
3. Implement the recommended security measures
4. Schedule a follow-up audit to verify improvements

---
*This report was automatically generated by the Windows Security Toolkit*
"@

    # Save the report as a Markdown file first
    $mdFile = $OutputFile -replace "\.pdf$", ".md"
    $reportContent | Out-File -FilePath $mdFile -Encoding utf8
    
    Write-Host "Executive summary generated as Markdown: $mdFile" -ForegroundColor Green
    
    # Check if pandoc is available to convert to PDF
    $pandocAvailable = $null -ne (Get-Command -Name pandoc -ErrorAction SilentlyContinue)
    
    if ($pandocAvailable) {
        # Convert to PDF using pandoc
        pandoc -s $mdFile -o $OutputFile --pdf-engine=wkhtmltopdf
        Write-Host "Executive summary converted to PDF: $OutputFile" -ForegroundColor Green
        
        # Offer to open the PDF report
        $openReport = Read-Host "`nWould you like to open the PDF report? (Y/N)"
        if ($openReport -match '^[Yy]') {
            Invoke-Item -Path $OutputFile
        }
    } else {
        Write-Warning "Pandoc not found. The report is available as Markdown only."
        Write-Host "To convert to PDF, install Pandoc and wkhtmltopdf, then run:"
        Write-Host "pandoc -s `"$mdFile`" -o `"$OutputFile`" --pdf-engine=wkhtmltopdf" -ForegroundColor Yellow
        
        # Offer to open the Markdown report
        $openReport = Read-Host "`nWould you like to open the Markdown report? (Y/N)"
        if ($openReport -match '^[Yy]') {
            Invoke-Item -Path $mdFile
        }
    }
    
} catch {
    Write-Error "An error occurred: $_"
    Write-Error $_.ScriptStackTrace
    exit 1
}
