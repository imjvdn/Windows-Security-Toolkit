<#
.SYNOPSIS
    Example script demonstrating how to use the Windows Security Toolkit module.
.DESCRIPTION
    This script imports the Windows Security Toolkit module and runs a security audit.
    It's designed to be simple to understand and modify.
.EXAMPLE
    .\Run-SecurityAudit.ps1 -OutputDirectory "C:\SecurityAudit"
.NOTES
    File Name      : Run-SecurityAudit.ps1
    Author         : Your Name
    Prerequisite   : PowerShell 5.1 or later, Administrative privileges recommended
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = (Join-Path -Path $env:USERPROFILE -ChildPath "Documents\SecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
)

# Ensure the script stops on errors
$ErrorActionPreference = 'Stop'

try {
    # Import the module
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\src\WindowsSecurityToolkit.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
    
    Write-Host "=== Windows Security Toolkit ===" -ForegroundColor Cyan
    Write-Host "Running security audit..." -ForegroundColor Yellow
    
    # Run the security audit
    $auditPath = Get-SystemSecurityAudit -OutputDirectory $OutputDirectory -ErrorAction Stop
    
    Write-Host "`nAudit completed successfully!" -ForegroundColor Green
    Write-Host "Reports saved to: $auditPath" -ForegroundColor Cyan
    
    # Offer to open the output directory
    $openFolder = Read-Host "`nWould you like to open the output directory? (Y/N)"
    if ($openFolder -match '^[Yy]') {
        Invoke-Item -Path $auditPath
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
