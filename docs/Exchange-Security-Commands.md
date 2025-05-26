# 🔐 Exchange Online Security Commands

This document contains essential PowerShell one-liners for auditing and securing Exchange Online environments. These commands require the Exchange Online PowerShell module and appropriate permissions.

## 🔌 Prerequisites

```powershell
# Install the Exchange Online Management module
Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser

# Connect to Exchange Online (modern authentication)
Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com
```

## 🔍 Mailbox Security

### List Mailbox Permissions
```powershell
# Get all mailboxes with full access permissions
Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | Where-Object {$_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-21*"} | Select-Object Identity,User,AccessRights

# Check for full access permissions on a specific mailbox
Get-MailboxPermission -Identity "user@domain.com" | Where-Object {$_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-21*"}
```

### Check for Forwarding Rules
```powershell
# Find mailboxes with forwarding enabled
Get-Mailbox -ResultSize Unlimited | Where-Object {$_.ForwardingAddress -ne $null -or $_.ForwardingSmtpAddress -ne $null} | Select-Object UserPrincipalName,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward

# Check inbox rules that forward emails
Get-InboxRule -Mailbox "user@domain.com" | Where-Object {$_.RedirectTo -ne $null -or $_.ForwardTo -ne $null -or $_.ForwardAsAttachmentTo -ne $null} | Select-Object Name,Description,RedirectTo,ForwardTo,ForwardAsAttachmentTo
```

## 🔒 Mail Flow Rules (Transport Rules)

```powershell
# List all mail flow rules
Get-TransportRule | Select-Object Name,State,Priority,Description | Sort-Object Priority

# Check for rules that bypass spam filtering
Get-TransportRule | Where-Object {$_.SetSCL -eq $null -or $_.SetSCL -gt 0} | Select-Object Name,Priority,SetSCL,Description
```

## 🛡️ Anti-Spam & Anti-Malware

```powershell
# Get current anti-spam policies
Get-HostedContentFilterPolicy | Select-Object Name,HighConfidenceSpamAction,SpamAction,HighConfidencePhishAction,PhishSpamAction,PhishZapEnabled,SpamZapEnabled

# Get malware filter policies
Get-MalwareFilterPolicy | Select-Object Name,Action,AdminDisplayName,EnableFileFilter,CustomNotifications,QuarantineTag
```

## 🔐 Authentication & Access

```powershell
# Check for basic authentication status
Get-OrganizationConfig | Select-Object Name,DefaultAuthenticationPolicy,DefaultDomainName,IsDehydrated

# Check for legacy authentication protocols
Get-CASMailbox -ResultSize Unlimited | Select-Object DisplayName,ActiveSyncEnabled,OWAEnabled,ImapEnabled,PopEnabled,MAPIEnabled,EwsEnabled,UniversalOutlookEnabled
```

## 📊 Reporting

```powershell
# Get mailbox login statistics (last 90 days)
$startDate = (Get-Date).AddDays(-90)
$endDate = Get-Date
Get-Mailbox -ResultSize Unlimited | Get-MailboxStatistics | Where-Object {$_.LastLogonTime -ne $null} | Select-Object DisplayName,LastLogonTime,LastLogoffTime,LastUserAccessTime,LastUserAccessTime,LastUserAction,ItemCount,TotalItemSize,Database | Export-Csv -Path "MailboxLogins_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Get admin audit logs
Search-AdminAuditLog -StartDate $startDate -EndDate $endDate -ResultSize 5000 | Select-Object CreationDate,UserIds,Operations,ObjectModified,Parameters | Export-Csv -Path "AdminAuditLog_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

## 🧹 Clean Up

```powershell
# Disconnect from Exchange Online
Disconnect-ExchangeOnline -Confirm:$false

# Remove all sessions (if needed)
Get-PSSession | Remove-PSSession
```

## 🚨 Security Best Practices

1. **Regularly Audit Permissions**: Run mailbox permission reports monthly
2. **Monitor Forwarding Rules**: Check for suspicious email forwarding
3. **Review Mail Flow Rules**: Ensure no rules bypass security controls
4. **Disable Legacy Auth**: If not needed, disable legacy authentication protocols
5. **Enable MFA**: Ensure all admin accounts have MFA enabled

## 📝 Notes

- Always test commands in a development environment first
- Some commands may require specific admin roles in Exchange Online
- Consider using the `-WhatIf` parameter for potentially destructive operations
- For large environments, use `-ResultSize Unlimited` and consider filtering results

## 📚 Additional Resources

- [Microsoft Exchange Online PowerShell](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps)
- [Exchange Online Protection PowerShell](https://docs.microsoft.com/en-us/powershell/exchange/exchange-eop/exchange-eop-powershell?view=exchange-ps)
- [Secure Messaging Policies](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/secure-email-recommended-policies?view=o365-worldwide)
