<#
.SYNOPSIS
    This PowerShell script ensures the account lockout threshold is configured to 3 or fewer invalid logon attempts.
.NOTES
    Author          : Mohamed Yagoub
    LinkedIn        : linkedin.com/in/mohamed-yagoub/
    GitHub          : github.com/goubx
    Date Created    : 2026-06-29
    Last Modified   : 2026-06-29
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000010
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AC-000010/
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 
.USAGE
    Run this script in an elevated PowerShell session on the target Windows 11 host.
    This setting lives in Local Security Policy (not the registry), so it is applied via secedit.
    After execution, run 'gpupdate /force' and rescan with Tenable Nessus to validate.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AC-000010).ps1
#>

# STIG WN11-AC-000010: Account lockout threshold must be 3 or fewer invalid logon attempts (not 0)
$Threshold = 3
$InfPath   = "$env:TEMP\WN11-AC-000010.inf"
$DbPath    = "$env:TEMP\WN11-AC-000010.sdb"

# Build a minimal security template
$InfContent = @"
[Unicode]
Unicode=yes
[System Access]
LockoutBadCount = $Threshold
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

Set-Content -Path $InfPath -Value $InfContent -Encoding Unicode -Force
Write-Host "Wrote security template: $InfPath"

# Apply the policy via secedit
secedit /configure /db $DbPath /cfg $InfPath /areas SECURITYPOLICY | Out-Null
Write-Host "Applied LockoutBadCount = $Threshold via secedit"

# Verify using net accounts
$Current = (net accounts | Select-String 'Lockout threshold' | ForEach-Object { ($_ -split ':')[1].Trim() })
if ($Current -match '^\d+$' -and [int]$Current -le 3 -and [int]$Current -gt 0) {
    Write-Host "Compliant: Lockout threshold = $Current"
} else {
    Write-Warning "Non-compliant: Lockout threshold = $Current, expected 1 to 3"
}

# Cleanup
Remove-Item $InfPath, $DbPath -ErrorAction SilentlyContinue
