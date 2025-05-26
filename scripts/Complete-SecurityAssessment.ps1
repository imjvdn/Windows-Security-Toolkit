<#
.SYNOPSIS
    Performs a comprehensive security assessment of a Windows environment.
.DESCRIPTION
    This script orchestrates a complete security assessment by running multiple
    specialized security tools from the Windows Security Toolkit. It generates
    a consolidated report with findings from system audits, network scans,
    SSL/TLS checks, compliance evaluations, and threat hunting.
.PARAMETER Target
    The primary target for the assessment. Can be a hostname or IP address.
    For local system assessment, use "localhost" or the local machine name.
.PARAMETER NetworkRange
    The network range to scan. Can be a CIDR notation (e.g., 192.168.1.0/24).
    If not specified, only the primary target will be scanned.
.PARAMETER OutputPath
    Path where the assessment results will be saved.
.PARAMETER IncludeNetworkScan
    Include network port scanning in the assessment.
.PARAMETER IncludeSSLCheck
    Include SSL/TLS security checks in the assessment.
.PARAMETER IncludeComplianceScan
    Include security compliance scanning in the assessment.
.PARAMETER IncludeThreatHunting
    Include threat hunting in the assessment.
.PARAMETER Thorough
    Perform a more thorough assessment, which takes longer but provides more detailed results.
.EXAMPLE
    .\Complete-SecurityAssessment.ps1 -Target localhost
    
    Performs a comprehensive security assessment of the local system.
.EXAMPLE
    .\Complete-SecurityAssessment.ps1 -Target 192.168.1.10 -NetworkRange 192.168.1.0/24 -IncludeNetworkScan -IncludeSSLCheck
    
    Performs a security assessment of the target system and scans the specified network range.
.NOTES
    File Name      : Complete-SecurityAssessment.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges recommended
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Target,
    
    [Parameter(Mandatory = $false)]
    [string]$NetworkRange,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SecurityAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')"),
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetworkScan,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSSLCheck,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeComplianceScan,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeThreatHunting,
    
    [Parameter(Mandatory = $false)]
    [switch]$Thorough
)

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Initialize results tracking
$assessmentResults = @{
    StartTime = Get-Date
    EndTime = $null
    Target = $Target
    NetworkRange = $NetworkRange
    Components = @()
    Findings = @{
        Critical = 0
        High = 0
        Medium = 0
        Low = 0
        Info = 0
    }
}

# Function to run a component and track results
function Invoke-AssessmentComponent {
    param (
        [string]$Name,
        [string]$Description,
        [scriptblock]$ScriptBlock
    )
    
    $componentResult = @{
        Name = $Name
        Description = $Description
        StartTime = Get-Date
        EndTime = $null
        Duration = $null
        Status = "Not Started"
        OutputPath = $null
        ErrorMessage = $null
    }
    
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "Starting: $Name" -ForegroundColor Cyan
    Write-Host "Description: $Description" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    
    try {
        $componentResult.Status = "Running"
        $componentOutput = & $ScriptBlock
        $componentResult.Status = "Completed"
        $componentResult.OutputPath = $componentOutput
    } catch {
        $componentResult.Status = "Failed"
        $componentResult.ErrorMessage = $_.Exception.Message
        Write-Host "Error running $Name: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        $componentResult.EndTime = Get-Date
        $componentResult.Duration = $componentResult.EndTime - $componentResult.StartTime
        
        Write-Host "Status: $($componentResult.Status)" -ForegroundColor $(
            switch ($componentResult.Status) {
                "Completed" { "Green" }
                "Failed" { "Red" }
                default { "Yellow" }
            }
        )
        Write-Host "Duration: $($componentResult.Duration.Minutes) minutes, $($componentResult.Duration.Seconds) seconds" -ForegroundColor White
        
        $assessmentResults.Components += $componentResult
    }
}

# Main execution
try {
    $overallStartTime = Get-Date
    Write-Host "Starting comprehensive security assessment of $Target..." -ForegroundColor Cyan
    Write-Host "Results will be saved to: $OutputPath" -ForegroundColor Cyan
    
    # Create component-specific output directories
    $systemAuditDir = Join-Path -Path $OutputPath -ChildPath "SystemAudit"
    $userAccountsDir = Join-Path -Path $OutputPath -ChildPath "UserAccounts"
    $networkSecurityDir = Join-Path -Path $OutputPath -ChildPath "NetworkSecurity"
    $networkScanDir = Join-Path -Path $OutputPath -ChildPath "NetworkScan"
    $sslCheckDir = Join-Path -Path $OutputPath -ChildPath "SSLCheck"
    $complianceScanDir = Join-Path -Path $OutputPath -ChildPath "ComplianceScan"
    $threatHuntingDir = Join-Path -Path $OutputPath -ChildPath "ThreatHunting"
    
    New-Item -Path $systemAuditDir -ItemType Directory -Force | Out-Null
    New-Item -Path $userAccountsDir -ItemType Directory -Force | Out-Null
    New-Item -Path $networkSecurityDir -ItemType Directory -Force | Out-Null
    
    if ($IncludeNetworkScan) {
        New-Item -Path $networkScanDir -ItemType Directory -Force | Out-Null
    }
    
    if ($IncludeSSLCheck) {
        New-Item -Path $sslCheckDir -ItemType Directory -Force | Out-Null
    }
    
    if ($IncludeComplianceScan) {
        New-Item -Path $complianceScanDir -ItemType Directory -Force | Out-Null
    }
    
    if ($IncludeThreatHunting) {
        New-Item -Path $threatHuntingDir -ItemType Directory -Force | Out-Null
    }
    
    # 1. Run system audit
    Invoke-AssessmentComponent -Name "System Security Audit" -Description "Comprehensive system-wide security audit" -ScriptBlock {
        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "audit-tools\Complete-SystemAudit.ps1"
        if (Test-Path $scriptPath) {
            & $scriptPath -OutputPath $systemAuditDir
            return $systemAuditDir
        } else {
            Write-Warning "Script not found: $scriptPath"
            return $null
        }
    }
    
    # 2. Run user accounts audit
    Invoke-AssessmentComponent -Name "User Accounts Audit" -Description "Focused audit of user accounts and permissions" -ScriptBlock {
        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "audit-tools\Audit-UserAccounts.ps1"
        if (Test-Path $scriptPath) {
            & $scriptPath -OutputPath $userAccountsDir
            return $userAccountsDir
        } else {
            Write-Warning "Script not found: $scriptPath"
            return $null
        }
    }
    
    # 3. Run network security audit
    Invoke-AssessmentComponent -Name "Network Security Audit" -Description "Network configuration and security assessment" -ScriptBlock {
        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "audit-tools\Audit-NetworkSecurity.ps1"
        if (Test-Path $scriptPath) {
            & $scriptPath -OutputPath $networkSecurityDir
            return $networkSecurityDir
        } else {
            Write-Warning "Script not found: $scriptPath"
            return $null
        }
    }
    
    # 4. Run network port scan if requested
    if ($IncludeNetworkScan) {
        $scanTarget = if ($NetworkRange) { $NetworkRange } else { $Target }
        $scanType = if ($Thorough) { "Full" } else { "Common" }
        
        Invoke-AssessmentComponent -Name "Network Port Scan" -Description "Scanning network ports on $scanTarget" -ScriptBlock {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "audit-tools\Scan-NetworkPorts.ps1"
            if (Test-Path $scriptPath) {
                & $scriptPath -Target $scanTarget -ScanType $scanType -OutputPath $networkScanDir
                return $networkScanDir
            } else {
                Write-Warning "Script not found: $scriptPath"
                return $null
            }
        }
    }
    
    # 5. Run SSL/TLS security check if requested
    if ($IncludeSSLCheck) {
        Invoke-AssessmentComponent -Name "SSL/TLS Security Check" -Description "Checking SSL/TLS security configuration on $Target" -ScriptBlock {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "audit-tools\Test-SSLSecurity.ps1"
            if (Test-Path $scriptPath) {
                & $scriptPath -Target $Target -OutputPath $sslCheckDir
                return $sslCheckDir
            } else {
                Write-Warning "Script not found: $scriptPath"
                return $null
            }
        }
    }
    
    # 6. Run compliance scan if requested
    if ($IncludeComplianceScan) {
        Invoke-AssessmentComponent -Name "Security Compliance Scan" -Description "Evaluating system against security benchmarks" -ScriptBlock {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "audit-tools\Audit-SecurityCompliance.ps1"
            if (Test-Path $scriptPath) {
                & $scriptPath -OutputPath $complianceScanDir
                return $complianceScanDir
            } else {
                Write-Warning "Script not found: $scriptPath"
                return $null
            }
        }
    }
    
    # 7. Run threat hunting if requested
    if ($IncludeThreatHunting) {
        Invoke-AssessmentComponent -Name "Threat Hunting" -Description "Scanning for indicators of compromise" -ScriptBlock {
            $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "audit-tools\Detect-ThreatIndicators.ps1"
            if (Test-Path $scriptPath) {
                $params = @{
                    OutputPath = $threatHuntingDir
                }
                
                if ($Thorough) {
                    $params.Add("Thorough", $true)
                }
                
                & $scriptPath @params
                return $threatHuntingDir
            } else {
                Write-Warning "Script not found: $scriptPath"
                return $null
            }
        }
    }
    
    # 8. Generate consolidated report
    Invoke-AssessmentComponent -Name "Consolidated Report Generation" -Description "Creating consolidated security assessment report" -ScriptBlock {
        # Count findings from each component
        
        # System Audit findings
        $systemAuditCsv = Join-Path -Path $systemAuditDir -ChildPath "SecurityIssues.csv"
        if (Test-Path $systemAuditCsv) {
            $systemAuditFindings = Import-Csv -Path $systemAuditCsv
            foreach ($finding in $systemAuditFindings) {
                switch ($finding.Severity) {
                    "Critical" { $assessmentResults.Findings.Critical++ }
                    "High" { $assessmentResults.Findings.High++ }
                    "Medium" { $assessmentResults.Findings.Medium++ }
                    "Low" { $assessmentResults.Findings.Low++ }
                    "Info" { $assessmentResults.Findings.Info++ }
                }
            }
        }
        
        # User Accounts findings
        $userAccountsCsv = Join-Path -Path $userAccountsDir -ChildPath "UserSecurityIssues.csv"
        if (Test-Path $userAccountsCsv) {
            $userAccountsFindings = Import-Csv -Path $userAccountsCsv
            foreach ($finding in $userAccountsFindings) {
                switch ($finding.Severity) {
                    "Critical" { $assessmentResults.Findings.Critical++ }
                    "High" { $assessmentResults.Findings.High++ }
                    "Medium" { $assessmentResults.Findings.Medium++ }
                    "Low" { $assessmentResults.Findings.Low++ }
                    "Info" { $assessmentResults.Findings.Info++ }
                }
            }
        }
        
        # Network Security findings
        $networkSecurityCsv = Join-Path -Path $networkSecurityDir -ChildPath "NetworkSecurityIssues.csv"
        if (Test-Path $networkSecurityCsv) {
            $networkSecurityFindings = Import-Csv -Path $networkSecurityCsv
            foreach ($finding in $networkSecurityFindings) {
                switch ($finding.Severity) {
                    "Critical" { $assessmentResults.Findings.Critical++ }
                    "High" { $assessmentResults.Findings.High++ }
                    "Medium" { $assessmentResults.Findings.Medium++ }
                    "Low" { $assessmentResults.Findings.Low++ }
                    "Info" { $assessmentResults.Findings.Info++ }
                }
            }
        }
        
        # Compliance findings
        if ($IncludeComplianceScan) {
            $complianceCsv = Join-Path -Path $complianceScanDir -ChildPath "ComplianceDetails.csv"
            if (Test-Path $complianceCsv) {
                $complianceFindings = Import-Csv -Path $complianceCsv
                foreach ($finding in $complianceFindings) {
                    if ($finding.Status -eq "Non-Compliant") {
                        switch ($finding.CheckID.Substring(0, 2)) {
                            "BL" { $assessmentResults.Findings.High++ }  # BitLocker
                            "FW" { $assessmentResults.Findings.Medium++ }  # Firewall
                            "PWD" { $assessmentResults.Findings.High++ }  # Password
                            "ACC" { $assessmentResults.Findings.Medium++ }  # Account
                            "AUD" { $assessmentResults.Findings.Medium++ }  # Audit
                            "UPD" { $assessmentResults.Findings.Low++ }  # Updates
                            default { $assessmentResults.Findings.Low++ }
                        }
                    }
                }
            }
        }
        
        # Threat Hunting findings
        if ($IncludeThreatHunting) {
            $threatCsv = Join-Path -Path $threatHuntingDir -ChildPath "ThreatIndicators.csv"
            if (Test-Path $threatCsv) {
                $threatFindings = Import-Csv -Path $threatCsv
                foreach ($finding in $threatFindings) {
                    switch ($finding.Risk) {
                        "Critical" { $assessmentResults.Findings.Critical++ }
                        "High" { $assessmentResults.Findings.High++ }
                        "Medium" { $assessmentResults.Findings.Medium++ }
                        "Low" { $assessmentResults.Findings.Low++ }
                        default { $assessmentResults.Findings.Info++ }
                    }
                }
            }
        }
        
        # Network Port Scan findings
        if ($IncludeNetworkScan) {
            $portScanCsv = Join-Path -Path $networkScanDir -ChildPath "PortScanResults.csv"
            if (Test-Path $portScanCsv) {
                $portScanResults = Import-Csv -Path $portScanCsv
                $highRiskPorts = @(21, 23, 445, 3389, 5900)
                $mediumRiskPorts = @(22, 25, 110, 143, 1433, 3306, 5432)
                
                foreach ($result in $portScanResults) {
                    if ($result.Port -in $highRiskPorts) {
                        $assessmentResults.Findings.High++
                    } elseif ($result.Port -in $mediumRiskPorts) {
                        $assessmentResults.Findings.Medium++
                    } else {
                        $assessmentResults.Findings.Low++
                    }
                }
            }
        }
        
        # SSL/TLS Check findings
        if ($IncludeSSLCheck) {
            $sslCsv = Join-Path -Path $sslCheckDir -ChildPath "SSLSecurityResults.csv"
            if (Test-Path $sslCsv) {
                $sslResults = Import-Csv -Path $sslCsv
                foreach ($result in $sslResults) {
                    if ($result.Status -eq "Fail") {
                        switch ($result.Risk) {
                            "Critical" { $assessmentResults.Findings.Critical++ }
                            "High" { $assessmentResults.Findings.High++ }
                            "Medium" { $assessmentResults.Findings.Medium++ }
                            "Low" { $assessmentResults.Findings.Low++ }
                            default { $assessmentResults.Findings.Info++ }
                        }
                    }
                }
            }
        }
        
        # Calculate security score (0-100)
        $totalIssues = $assessmentResults.Findings.Critical * 10 + 
                      $assessmentResults.Findings.High * 5 + 
                      $assessmentResults.Findings.Medium * 2 + 
                      $assessmentResults.Findings.Low * 1
        
        $securityScore = 100
        if ($totalIssues -gt 0) {
            $securityScore = [math]::Max(0, 100 - $totalIssues)
        }
        
        $assessmentResults.SecurityScore = $securityScore
        $assessmentResults.SecurityGrade = switch ($securityScore) {
            {$_ -ge 90} { "A" }
            {$_ -ge 80} { "B" }
            {$_ -ge 70} { "C" }
            {$_ -ge 60} { "D" }
            default { "F" }
        }
        
        # Generate HTML report
        $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
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
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .score {
            font-size: 48px;
            font-weight: bold;
            text-align: center;
            width: 100px;
            height: 100px;
            line-height: 100px;
            border-radius: 50%;
            margin: 0 auto 20px;
        }
        .grade-a {
            background-color: #4caf50;
            color: white;
        }
        .grade-b {
            background-color: #8bc34a;
            color: white;
        }
        .grade-c {
            background-color: #ffc107;
            color: #333;
        }
        .grade-d {
            background-color: #ff9800;
            color: white;
        }
        .grade-f {
            background-color: #f44336;
            color: white;
        }
        .summary-item {
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 10px;
        }
        .findings {
            margin-top: 20px;
        }
        .chart-container {
            width: 100%;
            max-width: 600px;
            margin: 0 auto;
            height: 300px;
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
        .component {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            background-color: #f5f5f5;
        }
        .component-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .component-status {
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
        }
        .status-completed {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        .status-failed {
            background-color: #ffebee;
            color: #c62828;
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
        <div class="header">
            <h1>Windows Security Toolkit</h1>
            <h2>Comprehensive Security Assessment Report</h2>
        </div>
        
        <div class="summary">
            <div class="score grade-$($assessmentResults.SecurityGrade.ToLower())">$($assessmentResults.SecurityGrade)</div>
            <h2>Security Score: $($assessmentResults.SecurityScore)/100</h2>
            <div class="summary-item"><strong>Target:</strong> $($assessmentResults.Target)</div>
            <div class="summary-item"><strong>Network Range:</strong> $($assessmentResults.NetworkRange -or "N/A")</div>
            <div class="summary-item"><strong>Assessment Date:</strong> $($assessmentResults.StartTime)</div>
            <div class="summary-item"><strong>Critical Issues:</strong> $($assessmentResults.Findings.Critical)</div>
            <div class="summary-item"><strong>High Issues:</strong> $($assessmentResults.Findings.High)</div>
            <div class="summary-item"><strong>Medium Issues:</strong> $($assessmentResults.Findings.Medium)</div>
            <div class="summary-item"><strong>Low Issues:</strong> $($assessmentResults.Findings.Low)</div>
            <div class="summary-item"><strong>Info:</strong> $($assessmentResults.Findings.Info)</div>
        </div>

        <div class="findings">
            <h2>Assessment Components</h2>
"@

        foreach ($component in $assessmentResults.Components) {
            $statusClass = switch ($component.Status) {
                "Completed" { "status-completed" }
                "Failed" { "status-failed" }
                default { "" }
            }
            
            $htmlReport += @"
            <div class="component">
                <div class="component-header">
                    <h3>$($component.Name)</h3>
                    <span class="component-status $statusClass">$($component.Status)</span>
                </div>
                <p>$($component.Description)</p>
                <div class="summary-item"><strong>Duration:</strong> $($component.Duration.Minutes) minutes, $($component.Duration.Seconds) seconds</div>
"@

            if ($component.OutputPath) {
                $htmlReport += @"
                <div class="summary-item"><strong>Results:</strong> <a href="file:///$($component.OutputPath)">View Detailed Results</a></div>
"@
            }

            if ($component.ErrorMessage) {
                $htmlReport += @"
                <div class="summary-item"><strong>Error:</strong> $($component.ErrorMessage)</div>
"@
            }

            $htmlReport += @"
            </div>
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
        $htmlReportPath = Join-Path -Path $OutputPath -ChildPath "SecurityAssessmentReport.html"
        $htmlReport | Out-File -FilePath $htmlReportPath -Encoding utf8
        
        # Save assessment results as JSON
        $assessmentResults.EndTime = Get-Date
        $assessmentResultsJson = ConvertTo-Json -InputObject $assessmentResults -Depth 10
        $assessmentResultsJson | Out-File -FilePath (Join-Path -Path $OutputPath -ChildPath "AssessmentResults.json") -Encoding utf8
        
        return $htmlReportPath
    }
    
    # Calculate overall duration
    $overallEndTime = Get-Date
    $overallDuration = $overallEndTime - $overallStartTime
    
    # Display summary
    Write-Host "`nSecurity Assessment Complete!" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    Write-Host "Target: $Target" -ForegroundColor White
    Write-Host "Duration: $($overallDuration.Minutes) minutes, $($overallDuration.Seconds) seconds" -ForegroundColor White
    Write-Host "Security Score: $($assessmentResults.SecurityScore)/100 (Grade: $($assessmentResults.SecurityGrade))" -ForegroundColor $(
        switch ($assessmentResults.SecurityGrade) {
            "A" { "Green" }
            "B" { "Green" }
            "C" { "Yellow" }
            "D" { "Yellow" }
            "F" { "Red" }
            default { "White" }
        }
    )
    Write-Host "Critical Issues: $($assessmentResults.Findings.Critical)" -ForegroundColor $(if ($assessmentResults.Findings.Critical -gt 0) { "Red" } else { "Green" })
    Write-Host "High Issues: $($assessmentResults.Findings.High)" -ForegroundColor $(if ($assessmentResults.Findings.High -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Issues: $($assessmentResults.Findings.Medium)" -ForegroundColor $(if ($assessmentResults.Findings.Medium -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Low Issues: $($assessmentResults.Findings.Low)" -ForegroundColor $(if ($assessmentResults.Findings.Low -gt 0) { "Cyan" } else { "Green" })
    
    # Open HTML report if on Windows
    $htmlReportPath = Join-Path -Path $OutputPath -ChildPath "SecurityAssessmentReport.html"
    if (Test-Path $htmlReportPath) {
        Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
        Write-Host "Opening report: $htmlReportPath" -ForegroundColor Cyan
        
        if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.Platform -ne 'Unix') {
            Start-Process $htmlReportPath
        }
    }
    
    return $OutputPath
} catch {
    Write-Error "An error occurred during the security assessment: $_"
    throw $_
} finally {
    Write-Host "Security assessment process completed." -ForegroundColor Cyan
}
