# 📧 Exchange Online Security Commands

## 📋 Table of Contents
1. [Connection & Setup](#connection--setup)
2. [Mailbox Security](#mailbox-security)
3. [Email Forwarding](#email-forwarding)
4. [Mail Flow Rules](#mail-flow-rules)
5. [Anti-Spam & Anti-Malware](#anti-spam--anti-malware)
6. [Authentication & Access](#authentication--access)
7. [Auditing & Reporting](#auditing--reporting)
8. [Security Best Practices](#security-best-practices)

## Connection & Setup

### Module Installation
```powershell
# Install the Exchange Online Management module
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
}

# Import the module
Import-Module ExchangeOnlineManagement
```

### Connect to Exchange Online
```powershell
# Connect with modern authentication (will prompt for credentials)
Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com -ShowProgress $true

# Verify connection
Get-OrganizationConfig | Select-Object Name, DisplayName
```

## Mailbox Security

### Mailbox Permission Audit
```powershell
# Get all mailboxes with full access permissions
Get-Mailbox -ResultSize Unlimited | 
    Get-MailboxPermission | 
    Where-Object {$_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-21*"} | 
    Select-Object Identity, User, AccessRights, IsInherited | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\MailboxPermissions.csv" -NoTypeInformation

# Check for full access permissions on specific mailboxes
$vipMailboxes = Get-Mailbox -Filter {RecipientTypeDetails -eq "UserMailbox"} -ResultSize Unlimited | 
    Where-Object {$_.DisplayName -like "*CEO*" -or $_.DisplayName -like "*CFO*" -or $_.DisplayName -like "*CTO*"}

foreach ($mailbox in $vipMailboxes) {
    Write-Host "\nChecking permissions for: $($mailbox.DisplayName)" -ForegroundColor Cyan
    Get-MailboxPermission -Identity $mailbox.Identity | 
        Where-Object {$_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-21*" -and $_.IsInherited -eq $false} | 
        Select-Object User, AccessRights
}
```

### Send-As and Send-On-Behalf Permissions
```powershell
# Check for Send-As permissions
Get-Mailbox -ResultSize Unlimited | 
    ForEach-Object {
        $mailbox = $_
        Get-RecipientPermission -Identity $mailbox.Identity | 
            Where-Object {$_.Trustee -ne "NT AUTHORITY\SELF" -and $_.AccessRights -like "*Send*"} | 
            Select-Object @{Name="Mailbox";Expression={$mailbox.DisplayName}}, 
                         @{Name="MailboxPrimarySmtpAddress";Expression={$mailbox.PrimarySmtpAddress}}, 
                         Trustee, AccessRights
    } | Export-Csv -Path "$env:USERPROFILE\Desktop\SendAsPermissions.csv" -NoTypeInformation

# Check for Send-On-Behalf permissions
Get-Mailbox -ResultSize Unlimited | 
    Where-Object {$_.GrantSendOnBehalfTo -ne $null} | 
    Select-Object DisplayName, PrimarySmtpAddress, 
               @{Name="SendOnBehalfTo";Expression={[string]::Join(", ", $_.GrantSendOnBehalfTo)}} | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\SendOnBehalfPermissions.csv" -NoTypeInformation
```

## Email Forwarding

### Mailbox Forwarding
```powershell
# Find mailboxes with forwarding enabled
Get-Mailbox -ResultSize Unlimited | 
    Where-Object {$_.ForwardingAddress -ne $null -or $_.ForwardingSmtpAddress -ne $null} | 
    Select-Object DisplayName, UserPrincipalName, ForwardingAddress, 
               ForwardingSmtpAddress, DeliverToMailboxAndForward | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\MailboxForwarding.csv" -NoTypeInformation
```

### Inbox Rules with Forwarding
```powershell
# Find inbox rules that forward emails
$forwardingRules = @()

Get-Mailbox -ResultSize Unlimited | ForEach-Object {
    $mailbox = $_
    Get-InboxRule -Mailbox $mailbox.Identity | 
        Where-Object {$_.RedirectTo -ne $null -or $_.ForwardTo -ne $null -or $_.ForwardAsAttachmentTo -ne $null} | 
        ForEach-Object {
            $forwardingRules += [PSCustomObject]@{
                Mailbox = $mailbox.DisplayName
                MailboxUPN = $mailbox.UserPrincipalName
                RuleName = $_.Name
                RuleDescription = $_.Description
                RedirectTo = $_.RedirectTo -join ", "
                ForwardTo = $_.ForwardTo -join ", "
                ForwardAsAttachmentTo = $_.ForwardAsAttachmentTo -join ", "
                Enabled = $_.Enabled
            }
        }
}

$forwardingRules | Export-Csv -Path "$env:USERPROFILE\Desktop\ForwardingRules.csv" -NoTypeInformation
```

## Mail Flow Rules

### Transport Rule Audit
```powershell
# List all mail flow rules
Get-TransportRule | 
    Select-Object Name, State, Priority, Mode, Description | 
    Sort-Object Priority | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\TransportRules.csv" -NoTypeInformation

# Check for suspicious rules (forwarding, redirecting, etc.)
Get-TransportRule | 
    Where-Object {$_.RedirectMessageTo -ne $null -or 
                 $_.ForwardTo -ne $null -or 
                 $_.BccTo -ne $null -or 
                 $_.AddToRecipients -ne $null -or 
                 $_.SetSCL -ne $null} | 
    Select-Object Name, State, Priority, 
               @{Name="RedirectTo";Expression={$_.RedirectMessageTo -join ", "}}, 
               @{Name="ForwardTo";Expression={$_.ForwardTo -join ", "}}, 
               @{Name="BccTo";Expression={$_.BccTo -join ", "}}, 
               @{Name="AddToRecipients";Expression={$_.AddToRecipients -join ", "}}, 
               SetSCL, Description | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\SuspiciousRules.csv" -NoTypeInformation
```

## Anti-Spam & Anti-Malware

### Anti-Spam Policies
```powershell
# Get anti-spam policies
Get-HostedContentFilterPolicy | 
    Select-Object Name, IsDefault, EnableEndUserSpamNotifications, 
               HighConfidenceSpamAction, SpamAction, 
               BulkThreshold, 
               HighConfidencePhishAction, PhishSpamAction, 
               PhishZapEnabled, SpamZapEnabled | 
    Format-List
```

### Malware Filter Policies
```powershell
# Get malware filter policies
Get-MalwareFilterPolicy | 
    Select-Object Name, Action, EnableFileFilter, 
               FileTypeAction, ZapEnabled, 
               QuarantineTag, CustomNotifications | 
    Format-List

# Get malware filter rules
Get-MalwareFilterRule | 
    Select-Object Name, State, Priority, MalwareFilterPolicy | 
    Format-Table -AutoSize
```

### Safe Links & Safe Attachments
```powershell
# Get Safe Links policies
Get-SafeLinksPolicy | 
    Select-Object Name, IsEnabled, ScanUrls, DeliverMessageAfterScan, 
               EnableForInternalSenders, DoNotRewriteUrls, 
               DoNotAllowClickThrough, EnableOrganizationBranding | 
    Format-List

# Get Safe Attachments policies
Get-SafeAttachmentPolicy | 
    Select-Object Name, Enable, Action, ActionOnError, 
               Redirect, RedirectAddress | 
    Format-List
```

## Authentication & Access

### Authentication Status
```powershell
# Check for basic authentication status
Get-OrganizationConfig | 
    Select-Object Name, DefaultAuthenticationPolicy | 
    Format-List

# Check authentication policies
Get-AuthenticationPolicy | 
    Select-Object Name, AllowBasicAuthActiveSync, AllowBasicAuthAutodiscover, 
               AllowBasicAuthImap, AllowBasicAuthPop, 
               AllowBasicAuthPowershell, AllowBasicAuthSmtp, 
               AllowBasicAuthWebServices | 
    Format-List
```

### Protocol Access
```powershell
# Check for legacy authentication protocols
Get-CASMailbox -ResultSize Unlimited | 
    Select-Object DisplayName, 
               ActiveSyncEnabled, OWAEnabled, 
               ImapEnabled, PopEnabled, 
               MAPIEnabled, EwsEnabled, 
               UniversalOutlookEnabled | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\ProtocolAccess.csv" -NoTypeInformation

# Find mailboxes with IMAP/POP enabled
Get-CASMailbox -ResultSize Unlimited | 
    Where-Object {$_.ImapEnabled -eq $true -or $_.PopEnabled -eq $true} | 
    Select-Object DisplayName, ImapEnabled, PopEnabled | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\ImapPopEnabled.csv" -NoTypeInformation
```

## Auditing & Reporting

### Mailbox Access Audit
```powershell
# Enable mailbox auditing for all users (if not already enabled)
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true

# Check mailbox audit configuration
Get-Mailbox -ResultSize Unlimited | 
    Select-Object DisplayName, AuditEnabled, 
               @{Name="AuditAdmin";Expression={$_.AuditAdmin -join ", "}}, 
               @{Name="AuditDelegate";Expression={$_.AuditDelegate -join ", "}}, 
               @{Name="AuditOwner";Expression={$_.AuditOwner -join ", "}} | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\MailboxAuditConfig.csv" -NoTypeInformation
```

### Message Tracking
```powershell
# Get message trace for suspicious activity (last 24 hours)
$startDate = (Get-Date).AddDays(-1)
$endDate = Get-Date

Get-MessageTrace -StartDate $startDate -EndDate $endDate -PageSize 1000 | 
    Where-Object { $_.Status -eq "Failed" -or $_.ToIP -ne "" } | 
    Select-Object Received, SenderAddress, RecipientAddress, 
               Subject, Status, MessageId, ToIP, FromIP | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\MessageTrace.csv" -NoTypeInformation
```

### Admin Activity
```powershell
# Get admin audit logs (last 7 days)
$startDate = (Get-Date).AddDays(-7)
$endDate = Get-Date

Search-AdminAuditLog -StartDate $startDate -EndDate $endDate -ResultSize 5000 | 
    Select-Object CreationDate, UserIds, CmdletName, ObjectModified, ModifiedProperties | 
    Export-Csv -Path "$env:USERPROFILE\Desktop\AdminAuditLog.csv" -NoTypeInformation
```

## Security Best Practices

1. **Enable Modern Authentication**
   ```powershell
   # Enable modern authentication for Exchange Online
   Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
   ```

2. **Disable Legacy Authentication**
   ```powershell
   # Create an authentication policy that blocks legacy auth
   New-AuthenticationPolicy -Name "Block Legacy Auth"
   
   # Apply the policy to all users
   Get-User -ResultSize Unlimited | Set-User -AuthenticationPolicy "Block Legacy Auth"
   
   # Set as default for new mailboxes
   Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Legacy Auth"
   ```

3. **Enable Mailbox Auditing**
   ```powershell
   # Enable auditing for all mailboxes
   Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180
   ```

4. **Regular Forwarding Checks**
   ```powershell
   # Create a scheduled task to check for new forwarding rules daily
   # Example PowerShell script to run daily
   $date = Get-Date -Format "yyyyMMdd"
   Get-Mailbox -ResultSize Unlimited | 
       Where-Object {$_.ForwardingAddress -ne $null -or $_.ForwardingSmtpAddress -ne $null} | 
       Export-Csv -Path "C:\Reports\Forwarding_$date.csv" -NoTypeInformation
   ```

5. **Disconnect When Done**
   ```powershell
   # Disconnect from Exchange Online
   Disconnect-ExchangeOnline -Confirm:$false
   
   # Remove all sessions (if needed)
   Get-PSSession | Remove-PSSession
   ```
