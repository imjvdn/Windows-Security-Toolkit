<#
.SYNOPSIS
    Tests for WindowsSecurityToolkit PowerShell module.
.DESCRIPTION
    This file contains Pester tests for the WindowsSecurityToolkit module.
    It verifies that the module loads correctly and exports the expected functions.
#>

# Import Pester module if not already loaded
if (-not (Get-Module -Name Pester -ListAvailable)) {
    throw "Pester module is required to run tests. Please install it using: Install-Module -Name Pester -Force"
}

# Set the script root
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:moduleName = "WindowsSecurityToolkit"
$script:moduleManifestPath = Join-Path -Path $script:moduleRoot -ChildPath "src\$($script:moduleName).psd1"
$script:moduleScriptPath = Join-Path -Path $script:moduleRoot -ChildPath "src\$($script:moduleName).psm1"

Describe "WindowsSecurityToolkit Module Tests" {
    Context "Module Structure" {
        It "Has a valid module manifest" {
            Test-Path -Path $script:moduleManifestPath | Should -Be $true
        }

        It "Has a valid module script file" {
            Test-Path -Path $script:moduleScriptPath | Should -Be $true
        }

        It "Module manifest can be imported" {
            { Import-Module -Name $script:moduleManifestPath -Force -ErrorAction Stop } | Should -Not -Throw
        }
    }

    Context "Module Exports" {
        BeforeAll {
            # Import the module for testing
            Import-Module -Name $script:moduleManifestPath -Force
        }

        It "Exports the Get-SystemSecurityAudit function" {
            Get-Command -Module $script:moduleName -Name "Get-SystemSecurityAudit" | Should -Not -BeNullOrEmpty
        }

        It "Get-SystemSecurityAudit should be a function" {
            (Get-Command -Module $script:moduleName -Name "Get-SystemSecurityAudit").CommandType | Should -Be "Function"
        }

        AfterAll {
            # Remove the module after testing
            Remove-Module -Name $script:moduleName -Force -ErrorAction SilentlyContinue
        }
    }
}
