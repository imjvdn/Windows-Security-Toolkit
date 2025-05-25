<#
.SYNOPSIS
    Windows Security Toolkit - PowerShell module for security analysis and auditing.
.DESCRIPTION
    This module provides various cmdlets for security analysis, auditing, and 
    incident response on Windows systems.
.NOTES
    File Name      : WindowsSecurityToolkit.psm1
    Author         : Your Name
    Prerequisite   : PowerShell 5.1 or later
    Copyright      : (c) 2025. All rights reserved.
#>

# Import all public functions
$publicFunctions = @(Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue)

foreach ($function in $publicFunctions) {
    try {
        . $function.FullName
    } catch {
        Write-Error "Failed to import function $($function.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $publicFunctions.BaseName

# Module initialization code can go here
Write-Verbose "Windows Security Toolkit module loaded successfully."
