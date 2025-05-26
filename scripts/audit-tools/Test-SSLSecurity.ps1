<#
.SYNOPSIS
    Tests SSL/TLS security configuration on Windows servers.
.DESCRIPTION
    This script checks SSL/TLS security settings on Windows web servers,
    including protocol versions, cipher suites, and certificate properties.
    It identifies security issues and provides recommendations based on
    current best practices.
.PARAMETER Target
    The target to scan. Can be a hostname or IP address.
.PARAMETER Port
    The port to scan. Default is 443.
.PARAMETER OutputPath
    Path where the scan results will be saved.
.EXAMPLE
    .\Test-SSLSecurity.ps1 -Target example.com
    
    Tests the SSL/TLS security configuration of example.com on port 443.
.EXAMPLE
    .\Test-SSLSecurity.ps1 -Target 192.168.1.1 -Port 8443 -OutputPath "C:\Reports"
    
    Tests the SSL/TLS security configuration of 192.168.1.1 on port 8443.
.NOTES
    File Name      : Test-SSLSecurity.ps1
    Author         : Windows Security Toolkit Team
    Prerequisite   : PowerShell 5.1 or later
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Target,
    
    [Parameter(Mandatory = $false)]
    [int]$Port = 443,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SSLScan_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
)

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Initialize results array
$sslResults = @()

# Function to add a finding to the results
function Add-Finding {
    param (
        [string]$Category,
        [string]$Description,
        [string]$Status,
        [string]$Risk,
        [string]$Recommendation
    )
    
    $sslResults += [PSCustomObject]@{
        Category = $Category
        Description = $Description
        Status = $Status
        Risk = $Risk
        Recommendation = $Recommendation
        TestTime = Get-Date
    }
}

# Function to test SSL/TLS protocol support
function Test-SSLProtocol {
    param (
        [string]$ComputerName,
        [int]$Port,
        [System.Security.Authentication.SslProtocols]$Protocol
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($ComputerName, $Port)
        
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            return $true  # Accept any certificate for testing
        })
        
        try {
            # Try to authenticate using the specified protocol
            $sslStream.AuthenticateAsClient($ComputerName, $null, $Protocol, $false)
            return $true
        } catch {
            return $false
        } finally {
            $sslStream.Close()
        }
    } catch {
        return $false
    } finally {
        if ($tcpClient -ne $null) {
            $tcpClient.Close()
        }
    }
}

# Function to get certificate information
function Get-CertificateInfo {
    param (
        [string]$ComputerName,
        [int]$Port
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($ComputerName, $Port)
        
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            return $true  # Accept any certificate for testing
        })
        
        try {
            # Use TLS 1.2 for the connection to get the certificate
            $sslStream.AuthenticateAsClient($ComputerName)
            
            # Get the certificate
            $certificate = $sslStream.RemoteCertificate
            
            if ($certificate -ne $null) {
                # Convert to X509Certificate2 for more information
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)
                
                # Check certificate validity
                $now = Get-Date
                $notBefore = [DateTime]::Parse($cert.GetEffectiveDateString())
                $notAfter = [DateTime]::Parse($cert.GetExpirationDateString())
                $isValid = ($now -ge $notBefore) -and ($now -le $notAfter)
                
                # Check key size
                $keySize = $cert.PublicKey.Key.KeySize
                
                # Check signature algorithm
                $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                
                # Check subject alternative names
                $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
                $subjectAltNames = "None"
                if ($sanExtension) {
                    $subjectAltNames = $sanExtension.Format($true)
                }
                
                # Return certificate information
                return [PSCustomObject]@{
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    ValidFrom = $notBefore
                    ValidTo = $notAfter
                    IsValid = $isValid
                    DaysUntilExpiration = [math]::Round(($notAfter - $now).TotalDays)
                    KeySize = $keySize
                    SignatureAlgorithm = $signatureAlgorithm
                    Thumbprint = $cert.Thumbprint
                    SerialNumber = $cert.SerialNumber
                    SubjectAlternativeNames = $subjectAltNames
                }
            } else {
                return $null
            }
        } catch {
            Write-Verbose "Error getting certificate: $_"
            return $null
        } finally {
            $sslStream.Close()
        }
    } catch {
        Write-Verbose "Error connecting: $_"
        return $null
    } finally {
        if ($tcpClient -ne $null) {
            $tcpClient.Close()
        }
    }
}

# Main execution
try {
    $startTime = Get-Date
    Write-Host "Starting SSL/TLS security scan on $Target:$Port..." -ForegroundColor Cyan
    
    # Test SSL/TLS protocol support
    Write-Host "Testing SSL/TLS protocol versions..." -ForegroundColor Yellow
    
    # Test SSL 2.0
    $supportsSSL2 = Test-SSLProtocol -ComputerName $Target -Port $Port -Protocol ([System.Security.Authentication.SslProtocols]::Ssl2)
    if ($supportsSSL2) {
        Add-Finding -Category "Protocol" `
            -Description "SSL 2.0 Supported" `
            -Status "Fail" `
            -Risk "Critical" `
            -Recommendation "Disable SSL 2.0 as it is insecure and deprecated"
    } else {
        Add-Finding -Category "Protocol" `
            -Description "SSL 2.0 Not Supported" `
            -Status "Pass" `
            -Risk "None" `
            -Recommendation "No action needed"
    }
    
    # Test SSL 3.0
    $supportsSSL3 = Test-SSLProtocol -ComputerName $Target -Port $Port -Protocol ([System.Security.Authentication.SslProtocols]::Ssl3)
    if ($supportsSSL3) {
        Add-Finding -Category "Protocol" `
            -Description "SSL 3.0 Supported" `
            -Status "Fail" `
            -Risk "High" `
            -Recommendation "Disable SSL 3.0 as it is vulnerable to POODLE attacks"
    } else {
        Add-Finding -Category "Protocol" `
            -Description "SSL 3.0 Not Supported" `
            -Status "Pass" `
            -Risk "None" `
            -Recommendation "No action needed"
    }
    
    # Test TLS 1.0
    $supportsTLS10 = Test-SSLProtocol -ComputerName $Target -Port $Port -Protocol ([System.Security.Authentication.SslProtocols]::Tls)
    if ($supportsTLS10) {
        Add-Finding -Category "Protocol" `
            -Description "TLS 1.0 Supported" `
            -Status "Warning" `
            -Risk "Medium" `
            -Recommendation "Disable TLS 1.0 as it is considered insecure by modern standards"
    } else {
        Add-Finding -Category "Protocol" `
            -Description "TLS 1.0 Not Supported" `
            -Status "Pass" `
            -Risk "None" `
            -Recommendation "No action needed"
    }
    
    # Test TLS 1.1
    $supportsTLS11 = Test-SSLProtocol -ComputerName $Target -Port $Port -Protocol ([System.Security.Authentication.SslProtocols]::Tls11)
    if ($supportsTLS11) {
        Add-Finding -Category "Protocol" `
            -Description "TLS 1.1 Supported" `
            -Status "Warning" `
            -Risk "Low" `
            -Recommendation "Consider disabling TLS 1.1 as it is being deprecated"
    } else {
        Add-Finding -Category "Protocol" `
            -Description "TLS 1.1 Not Supported" `
            -Status "Pass" `
            -Risk "None" `
            -Recommendation "No action needed"
    }
    
    # Test TLS 1.2
    $supportsTLS12 = Test-SSLProtocol -ComputerName $Target -Port $Port -Protocol ([System.Security.Authentication.SslProtocols]::Tls12)
    if ($supportsTLS12) {
        Add-Finding -Category "Protocol" `
            -Description "TLS 1.2 Supported" `
            -Status "Pass" `
            -Risk "None" `
            -Recommendation "No action needed"
    } else {
        Add-Finding -Category "Protocol" `
            -Description "TLS 1.2 Not Supported" `
            -Status "Fail" `
            -Risk "High" `
            -Recommendation "Enable TLS 1.2 as it is a secure protocol required for compliance"
    }
    
    # Test TLS 1.3 if available (.NET Framework 4.8+ or .NET Core 3.0+)
    try {
        $supportsTLS13 = Test-SSLProtocol -ComputerName $Target -Port $Port -Protocol ([System.Security.Authentication.SslProtocols]::Tls13)
        if ($supportsTLS13) {
            Add-Finding -Category "Protocol" `
                -Description "TLS 1.3 Supported" `
                -Status "Pass" `
                -Risk "None" `
                -Recommendation "No action needed"
        } else {
            Add-Finding -Category "Protocol" `
                -Description "TLS 1.3 Not Supported" `
                -Status "Info" `
                -Risk "Low" `
                -Recommendation "Consider enabling TLS 1.3 for improved security and performance"
        }
    } catch {
        # TLS 1.3 not available in this version of .NET
        Add-Finding -Category "Protocol" `
            -Description "TLS 1.3 Test Not Available" `
            -Status "Info" `
            -Risk "Unknown" `
            -Recommendation "Update to .NET Framework 4.8+ or .NET Core 3.0+ to test TLS 1.3 support"
    }
    
    # Get certificate information
    Write-Host "Checking certificate..." -ForegroundColor Yellow
    $certInfo = Get-CertificateInfo -ComputerName $Target -Port $Port
    
    if ($certInfo -ne $null) {
        # Check certificate validity
        if ($certInfo.IsValid) {
            Add-Finding -Category "Certificate" `
                -Description "Certificate is valid" `
                -Status "Pass" `
                -Risk "None" `
                -Recommendation "No action needed"
        } else {
            Add-Finding -Category "Certificate" `
                -Description "Certificate is not valid" `
                -Status "Fail" `
                -Risk "Critical" `
                -Recommendation "Replace with a valid certificate"
        }
        
        # Check certificate expiration
        if ($certInfo.DaysUntilExpiration -lt 0) {
            Add-Finding -Category "Certificate" `
                -Description "Certificate has expired" `
                -Status "Fail" `
                -Risk "Critical" `
                -Recommendation "Replace with a valid certificate"
        } elseif ($certInfo.DaysUntilExpiration -lt 30) {
            Add-Finding -Category "Certificate" `
                -Description "Certificate expires in $($certInfo.DaysUntilExpiration) days" `
                -Status "Warning" `
                -Risk "High" `
                -Recommendation "Renew certificate soon"
        } elseif ($certInfo.DaysUntilExpiration -lt 90) {
            Add-Finding -Category "Certificate" `
                -Description "Certificate expires in $($certInfo.DaysUntilExpiration) days" `
                -Status "Warning" `
                -Risk "Medium" `
                -Recommendation "Plan for certificate renewal"
        } else {
            Add-Finding -Category "Certificate" `
                -Description "Certificate expires in $($certInfo.DaysUntilExpiration) days" `
                -Status "Pass" `
                -Risk "None" `
                -Recommendation "No action needed"
        }
        
        # Check key size
        if ($certInfo.KeySize -lt 2048) {
            Add-Finding -Category "Certificate" `
                -Description "Certificate key size is $($certInfo.KeySize) bits" `
                -Status "Fail" `
                -Risk "High" `
                -Recommendation "Use a certificate with at least 2048-bit key size"
        } else {
            Add-Finding -Category "Certificate" `
                -Description "Certificate key size is $($certInfo.KeySize) bits" `
                -Status "Pass" `
                -Risk "None" `
                -Recommendation "No action needed"
        }
        
        # Check signature algorithm
        if ($certInfo.SignatureAlgorithm -like "*SHA1*" -or $certInfo.SignatureAlgorithm -like "*MD5*") {
            Add-Finding -Category "Certificate" `
                -Description "Certificate uses weak signature algorithm: $($certInfo.SignatureAlgorithm)" `
                -Status "Fail" `
                -Risk "High" `
                -Recommendation "Use a certificate with SHA-256 or stronger signature algorithm"
        } else {
            Add-Finding -Category "Certificate" `
                -Description "Certificate uses strong signature algorithm: $($certInfo.SignatureAlgorithm)" `
                -Status "Pass" `
                -Risk "None" `
                -Recommendation "No action needed"
        }
        
        # Check subject alternative names
        if ($certInfo.SubjectAlternativeNames -eq "None") {
            Add-Finding -Category "Certificate" `
                -Description "Certificate does not have Subject Alternative Names (SAN)" `
                -Status "Warning" `
                -Risk "Medium" `
                -Recommendation "Use a certificate with appropriate SANs for all domain names"
        } else {
            Add-Finding -Category "Certificate" `
                -Description "Certificate has Subject Alternative Names (SAN)" `
                -Status "Pass" `
                -Risk "None" `
                -Recommendation "No action needed"
        }
    } else {
        Add-Finding -Category "Certificate" `
            -Description "Could not retrieve certificate information" `
            -Status "Error" `
            -Risk "Unknown" `
            -Recommendation "Verify the server is properly configured with a valid certificate"
    }
    
    # Calculate statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $totalChecks = $sslResults.Count
    $passedChecks = ($sslResults | Where-Object { $_.Status -eq "Pass" }).Count
    $failedChecks = ($sslResults | Where-Object { $_.Status -eq "Fail" }).Count
    $warningChecks = ($sslResults | Where-Object { $_.Status -eq "Warning" }).Count
    $infoChecks = ($sslResults | Where-Object { $_.Status -eq "Info" }).Count
    $errorChecks = ($sslResults | Where-Object { $_.Status -eq "Error" }).Count
    
    # Calculate security score (0-100)
    $securityScore = 0
    if ($totalChecks -gt 0) {
        $weightedScore = 0
        $totalWeight = 0
        
        foreach ($result in $sslResults) {
            $weight = switch ($result.Risk) {
                "Critical" { 10 }
                "High" { 8 }
                "Medium" { 5 }
                "Low" { 2 }
                "None" { 0 }
                "Unknown" { 0 }
                default { 0 }
            }
            
            $score = switch ($result.Status) {
                "Pass" { 100 }
                "Warning" { 50 }
                "Info" { 75 }
                "Fail" { 0 }
                "Error" { 0 }
                default { 0 }
            }
            
            $weightedScore += $weight * $score
            $totalWeight += $weight
        }
        
        if ($totalWeight -gt 0) {
            $securityScore = [math]::Round($weightedScore / $totalWeight)
        }
    }
    
    # Generate summary
    $summary = [PSCustomObject]@{
        Target = "$Target`:$Port"
        ScanDate = Get-Date
        ScanDuration = "$($duration.Minutes) minutes, $($duration.Seconds) seconds"
        TotalChecks = $totalChecks
        PassedChecks = $passedChecks
        FailedChecks = $failedChecks
        WarningChecks = $warningChecks
        InfoChecks = $infoChecks
        ErrorChecks = $errorChecks
        SecurityScore = $securityScore
        SecurityGrade = switch ($securityScore) {
            {$_ -ge 90} { "A" }
            {$_ -ge 80} { "B" }
            {$_ -ge 70} { "C" }
            {$_ -ge 60} { "D" }
            default { "F" }
        }
    }
    
    # Export results to CSV
    $sslResults | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "SSLSecurityResults.csv") -NoTypeInformation
    
    # Export summary to CSV
    $summary | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "SSLSecuritySummary.csv") -NoTypeInformation
    
    # Export certificate details to CSV if available
    if ($certInfo -ne $null) {
        $certInfo | Export-Csv -Path (Join-Path -Path $OutputPath -ChildPath "CertificateDetails.csv") -NoTypeInformation
    }
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL/TLS Security Report</title>
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
        .pass {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        .warning {
            background-color: #fff8e1;
            color: #ff8f00;
        }
        .fail {
            background-color: #ffebee;
            color: #c62828;
        }
        .info {
            background-color: #e3f2fd;
            color: #1565c0;
        }
        .error {
            background-color: #fafafa;
            color: #616161;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }
        .cert-details {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SSL/TLS Security Report</h1>
        <div class="summary">
            <div class="score grade-$($summary.SecurityGrade.ToLower())">$($summary.SecurityGrade)</div>
            <h2>Security Score: $($summary.SecurityScore)/100</h2>
            <div class="summary-item"><strong>Target:</strong> $($summary.Target)</div>
            <div class="summary-item"><strong>Scan Date:</strong> $($summary.ScanDate)</div>
            <div class="summary-item"><strong>Duration:</strong> $($summary.ScanDuration)</div>
            <div class="summary-item"><strong>Total Checks:</strong> $($summary.TotalChecks)</div>
            <div class="summary-item"><strong>Passed:</strong> $($summary.PassedChecks)</div>
            <div class="summary-item"><strong>Failed:</strong> $($summary.FailedChecks)</div>
            <div class="summary-item"><strong>Warnings:</strong> $($summary.WarningChecks)</div>
            <div class="summary-item"><strong>Info:</strong> $($summary.InfoChecks)</div>
            <div class="summary-item"><strong>Errors:</strong> $($summary.ErrorChecks)</div>
        </div>

        <div class="findings">
            <h2>SSL/TLS Security Findings</h2>
            <table>
                <tr>
                    <th>Category</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Recommendation</th>
                </tr>
"@

    foreach ($finding in $sslResults) {
        $statusClass = $finding.Status.ToLower()
        
        $htmlReport += @"
                <tr class="$statusClass">
                    <td>$($finding.Category)</td>
                    <td>$($finding.Description)</td>
                    <td>$($finding.Status)</td>
                    <td>$($finding.Risk)</td>
                    <td>$($finding.Recommendation)</td>
                </tr>
"@
    }
    
    $htmlReport += @"
            </table>
        </div>
"@

    if ($certInfo -ne $null) {
        $htmlReport += @"
        <div class="cert-details">
            <h2>Certificate Details</h2>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Subject</td>
                    <td>$($certInfo.Subject)</td>
                </tr>
                <tr>
                    <td>Issuer</td>
                    <td>$($certInfo.Issuer)</td>
                </tr>
                <tr>
                    <td>Valid From</td>
                    <td>$($certInfo.ValidFrom)</td>
                </tr>
                <tr>
                    <td>Valid To</td>
                    <td>$($certInfo.ValidTo)</td>
                </tr>
                <tr>
                    <td>Days Until Expiration</td>
                    <td>$($certInfo.DaysUntilExpiration)</td>
                </tr>
                <tr>
                    <td>Key Size</td>
                    <td>$($certInfo.KeySize) bits</td>
                </tr>
                <tr>
                    <td>Signature Algorithm</td>
                    <td>$($certInfo.SignatureAlgorithm)</td>
                </tr>
                <tr>
                    <td>Thumbprint</td>
                    <td>$($certInfo.Thumbprint)</td>
                </tr>
                <tr>
                    <td>Serial Number</td>
                    <td>$($certInfo.SerialNumber)</td>
                </tr>
                <tr>
                    <td>Subject Alternative Names</td>
                    <td>$($certInfo.SubjectAlternativeNames)</td>
                </tr>
            </table>
        </div>
"@
    }
    
    $htmlReport += @"
        <div class="footer">
            <p>Generated by Windows Security Toolkit - $(Get-Date)</p>
        </div>
    </div>
</body>
</html>
"@

    # Save HTML report
    $htmlReport | Out-File -FilePath (Join-Path -Path $OutputPath -ChildPath "SSLSecurityReport.html") -Encoding utf8
    
    # Display summary
    Write-Host "`nSSL/TLS Security Scan Summary:" -ForegroundColor Green
    Write-Host "=============================" -ForegroundColor Green
    Write-Host "Target: $Target`:$Port" -ForegroundColor White
    Write-Host "Security Score: $($summary.SecurityScore)/100 (Grade: $($summary.SecurityGrade))" -ForegroundColor $(
        switch ($summary.SecurityGrade) {
            "A" { "Green" }
            "B" { "Green" }
            "C" { "Yellow" }
            "D" { "Yellow" }
            "F" { "Red" }
            default { "White" }
        }
    )
    Write-Host "Passed Checks: $($summary.PassedChecks)" -ForegroundColor Green
    Write-Host "Failed Checks: $($summary.FailedChecks)" -ForegroundColor $(if ($summary.FailedChecks -gt 0) { "Red" } else { "Green" })
    Write-Host "Warning Checks: $($summary.WarningChecks)" -ForegroundColor $(if ($summary.WarningChecks -gt 0) { "Yellow" } else { "Green" })
    Write-Host "`nResults saved to: $OutputPath" -ForegroundColor Cyan
    
    # Open HTML report if on Windows
    if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.Platform -ne 'Unix') {
        $htmlReportPath = Join-Path -Path $OutputPath -ChildPath "SSLSecurityReport.html"
        Start-Process $htmlReportPath
    }
    
    return $OutputPath
} catch {
    Write-Error "An error occurred during SSL/TLS security scanning: $_"
    throw $_
} finally {
    Write-Host "SSL/TLS security scan completed." -ForegroundColor Cyan
}
