<#
.SYNOPSIS
    Runs all Pester tests for the Windows Security Toolkit module.
.DESCRIPTION
    This script runs all Pester tests for the Windows Security Toolkit module
    and generates a test report in the specified output directory.
.PARAMETER OutputPath
    The path where test results should be saved. Defaults to "TestResults" in the module root.
.EXAMPLE
    .\Run-Tests.ps1
    
    Runs all tests and saves results to the default location.
.EXAMPLE
    .\Run-Tests.ps1 -OutputPath "C:\TestResults"
    
    Runs all tests and saves results to C:\TestResults.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath "TestResults")
)

# Set up the test environment
. (Join-Path -Path $PSScriptRoot -ChildPath "environment\TestSetup.ps1")

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Configure Pester
$pesterConfig = New-PesterConfiguration
$pesterConfig.Run.Path = $PSScriptRoot
$pesterConfig.Run.PassThru = $true
$pesterConfig.Output.Verbosity = 'Detailed'
$pesterConfig.TestResult.Enabled = $true
$pesterConfig.TestResult.OutputPath = Join-Path -Path $OutputPath -ChildPath "TestResults.xml"
$pesterConfig.CodeCoverage.Enabled = $true
$pesterConfig.CodeCoverage.Path = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath "src"
$pesterConfig.CodeCoverage.OutputPath = Join-Path -Path $OutputPath -ChildPath "CodeCoverage.xml"

# Run the tests
Write-Host "Running Pester tests..." -ForegroundColor Cyan
$testResults = Invoke-Pester -Configuration $pesterConfig

# Display test results summary
Write-Host "`nTest Results Summary:" -ForegroundColor Cyan
Write-Host "  Total Tests: $($testResults.TotalCount)" -ForegroundColor White
Write-Host "  Passed: $($testResults.PassedCount)" -ForegroundColor Green
Write-Host "  Failed: $($testResults.FailedCount)" -ForegroundColor Red
Write-Host "  Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow
Write-Host "  Not Run: $($testResults.NotRunCount)" -ForegroundColor Gray

# Display code coverage summary if available
if ($testResults.CodeCoverage) {
    $coverage = $testResults.CodeCoverage.CoveragePercent
    Write-Host "`nCode Coverage: $coverage%" -ForegroundColor Cyan
}

Write-Host "`nTest results saved to: $($pesterConfig.TestResult.OutputPath)" -ForegroundColor Green
if ($pesterConfig.CodeCoverage.Enabled) {
    Write-Host "Code coverage report saved to: $($pesterConfig.CodeCoverage.OutputPath)" -ForegroundColor Green
}

# Return success/failure based on test results
exit $testResults.FailedCount
