# STIG-Implementation-WN11-AU-000585

# Initial scan results 

The initial scan has over 149 failures out of 263.

{image]

I'm going to select to fix the failed audit:

> WN11-AC-000010 - The number of allowed bad logon attempts must be configured to three or less

This is a big issue because external bad actors have unlimited attempts to breach the VM without any defense mechanisms in place, such as account lockouts.

## Manual work + Stigaview results

[image]

Now that I know the manual solution, I'm going to log into the VM and edit the group policy with these instructions:

1. Verify the effective setting in Local Group Policy Editor. Run "gpedit.msc".
2. Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.
3. If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding

## Manual Work

[image]

As you can see above, the current lockout settings are set to 10, which is an unreasonably high number. To guarantee a success rating on the next scan, I'm going to change the number of attempts to 3.

Now that I've updated it within group policy, im going to restart the computer and rerun the scan to make sure the manual configuration went well.

[image]

The scan now shows a success against the audit for WN11-AC-000010, which proves the manual remediation worked. 

## I'm now going to undo the manual remediation, rescan, and confirm it is back to the original point.

To undo the manual remediation, I have to go back within the group policy and edit the lockout policy back to 10.

[image]

As expected, the manual remediation was removed, and now the scan is showing WN11-AC-000010 is failing the audit.

[image]





## Now I am going to create the pragmatic solution through PowerShell

# Configure Account Lockout Threshold to 3 invalid logon attempts with Powershell

Ive created this PowerShell Script through Claude to meet the audit requirements for a pass.

```powershell
Write-Host "Setting Account Lockout Threshold to 3..." -ForegroundColor Cyan

net accounts /lockoutthreshold:3

Write-Host "`nVerifying current account lockout policy..." -ForegroundColor Cyan
net accounts
```

[image]

## I am now going to run the scan to confirm that it now passes.
