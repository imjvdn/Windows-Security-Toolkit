<#
.SYNOPSIS
    Sets up the test environment for Windows Security Toolkit tests.
.DESCRIPTION
    This script prepares the environment for running Pester tests against
    the Windows Security Toolkit module. It ensures that Pester is installed
    and sets up any required test dependencies.
#>

# Ensure Pester module is installed
if (-not (Get-Module -Name Pester -ListAvailable)) {
    Write-Host "Installing Pester module..." -ForegroundColor Yellow
    Install-Module -Name Pester -Force -SkipPublisherCheck -Scope CurrentUser
}

# Import Pester module
Import-Module -Name Pester -Force

# Set up test constants
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:moduleName = "WindowsSecurityToolkit"
$script:moduleManifestPath = Join-Path -Path $script:moduleRoot -ChildPath "src\$($script:moduleName).psd1"

# Create a temporary directory for test artifacts
$script:testArtifactsDir = Join-Path -Path $env:TEMP -ChildPath "WindowsSecurityToolkitTests"
if (-not (Test-Path -Path $script:testArtifactsDir)) {
    New-Item -Path $script:testArtifactsDir -ItemType Directory -Force | Out-Null
}

Write-Host "Test environment setup complete." -ForegroundColor Green
Write-Host "Module Root: $script:moduleRoot" -ForegroundColor Cyan
Write-Host "Module Name: $script:moduleName" -ForegroundColor Cyan
Write-Host "Test Artifacts Directory: $script:testArtifactsDir" -ForegroundColor Cyan

# Return environment variables for use in tests
return @{
    ModuleRoot = $script:moduleRoot
    ModuleName = $script:moduleName
    ModuleManifestPath = $script:moduleManifestPath
    TestArtifactsDir = $script:testArtifactsDir
}
