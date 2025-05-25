@{
    RootModule        = 'WindowsSecurityToolkit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a1b2c3d4-e5f6-4a5b-8c7d-9e0f1a2b3c4d'
    Author            = 'Your Name'
    CompanyName       = 'Your Company'
    Copyright         = '(c) 2025. All rights reserved.'
    Description       = 'A collection of PowerShell tools for Windows security analysis and auditing.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('*')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('Security', 'Audit', 'Windows', 'DFIR')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/yourusername/Windows-Security-Toolkit'
            ReleaseNotes = 'Initial release'
        }
    }
}
