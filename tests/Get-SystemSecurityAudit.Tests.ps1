<#
.SYNOPSIS
    Tests for Get-SystemSecurityAudit function.
.DESCRIPTION
    This file contains Pester tests for the Get-SystemSecurityAudit function.
    It verifies that the function works correctly and produces the expected output.
#>

# Import Pester module if not already loaded
if (-not (Get-Module -Name Pester -ListAvailable)) {
    throw "Pester module is required to run tests. Please install it using: Install-Module -Name Pester -Force"
}

# Set the script root
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:moduleName = "WindowsSecurityToolkit"
$script:moduleManifestPath = Join-Path -Path $script:moduleRoot -ChildPath "src\$($script:moduleName).psd1"

Describe "Get-SystemSecurityAudit Function Tests" {
    BeforeAll {
        # Import the module for testing
        Import-Module -Name $script:moduleManifestPath -Force -ErrorAction Stop
        
        # Create a temporary directory for test output
        $script:testOutputDir = Join-Path -Path $TestDrive -ChildPath "SecurityAuditTest"
        New-Item -Path $script:testOutputDir -ItemType Directory -Force | Out-Null
    }

    Context "Parameter Validation" {
        It "Accepts a custom output directory" {
            { Get-SystemSecurityAudit -OutputDirectory $script:testOutputDir -ErrorAction Stop } | Should -Not -Throw
        }

        It "Creates the output directory if it doesn't exist" {
            $newOutputDir = Join-Path -Path $TestDrive -ChildPath "NewSecurityAuditDir"
            Get-SystemSecurityAudit -OutputDirectory $newOutputDir
            Test-Path -Path $newOutputDir | Should -Be $true
        }
    }

    Context "Function Output" {
        BeforeAll {
            # Run the function and capture its output
            $script:functionOutput = Get-SystemSecurityAudit -OutputDirectory $script:testOutputDir
        }

        It "Returns the output directory path" {
            $script:functionOutput | Should -Be $script:testOutputDir
        }

        It "Creates CSV files in the output directory" {
            $csvFiles = Get-ChildItem -Path $script:testOutputDir -Filter "*.csv" -Recurse
            $csvFiles.Count | Should -BeGreaterThan 0
        }
    }

    Context "Mock Tests" {
        BeforeAll {
            # Create mock functions for commands used in Get-SystemSecurityAudit
            Mock Get-ComputerInfo { 
                return [PSCustomObject]@{
                    CsName = "TestComputer"
                    OsName = "Windows 10 Pro"
                    OsVersion = "10.0.19042"
                }
            }
            
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name = "TestUser"
                        Enabled = $true
                        PasswordLastSet = (Get-Date).AddDays(-30)
                        PasswordExpires = (Get-Date).AddDays(60)
                    }
                )
            }
        }

        It "Calls Get-ComputerInfo" {
            Get-SystemSecurityAudit -OutputDirectory $script:testOutputDir
            Should -Invoke Get-ComputerInfo -Times 1 -Exactly
        }

        It "Calls Get-LocalUser" {
            Get-SystemSecurityAudit -OutputDirectory $script:testOutputDir
            Should -Invoke Get-LocalUser -Times 1 -Exactly
        }
    }

    AfterAll {
        # Remove the module after testing
        Remove-Module -Name $script:moduleName -Force -ErrorAction SilentlyContinue
        
        # Clean up test output directory
        if (Test-Path -Path $script:testOutputDir) {
            Remove-Item -Path $script:testOutputDir -Recurse -Force
        }
    }
}
