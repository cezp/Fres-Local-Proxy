<#
.SYNOPSIS
    Links a GPO to all site OUs matching the pattern OU=<XXX>,OU=<CC>,DC=... in a domain.

.DESCRIPTION
    Queries Active Directory for all OUs that match the naming pattern:
      OU=<3-letter site code>,OU=<2-letter country code>,DC=<domain components>
    and creates a GPO link on each matching OU.

    Use the -Server parameter to target a specific domain controller or domain,
    allowing the script to be reused across multiple domains.

.PARAMETER GPOName
    The display name of the GPO to link.

.PARAMETER Server
    The domain controller or domain DNS name to connect to.

.PARAMETER LinkEnabled
    Whether the GPO link should be enabled. Defaults to $true.

.PARAMETER Enforced
    Whether the GPO link should be enforced. Defaults to $false.

.EXAMPLE
    .\Link-GPO-To-SiteOUs.ps1 -GPOName "My Security Policy" -Server "domain.com"

.EXAMPLE
    .\Link-GPO-To-SiteOUs.ps1 -GPOName "My Security Policy" -Server "dc01.domain.com" -Enforced $true

.NOTES
    Requires the GroupPolicy and ActiveDirectory PowerShell modules.
    The account running this script must have permission to create GPO links.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Display name of the GPO to link.")]
    [string]$GPOName,

    [Parameter(Mandatory = $true, HelpMessage = "Domain controller or domain DNS name to connect to.")]
    [string]$Server,

    [Parameter(Mandatory = $false)]
    [bool]$LinkEnabled = $true,

    [Parameter(Mandatory = $false)]
    [bool]$Enforced = $false
)

#Requires -Modules GroupPolicy, ActiveDirectory

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Verify the GPO exists on the target domain
Write-Verbose "Verifying GPO '$GPOName' exists on server '$Server'..."
try {
    $gpo = Get-GPO -Name $GPOName -Server $Server
}
catch {
    Write-Error "GPO '$GPOName' was not found on '$Server'. $_"
    exit 1
}
Write-Verbose "Found GPO: $($gpo.DisplayName) [$($gpo.Id)]"

# Retrieve the domain's distinguished name root from the server
Write-Verbose "Retrieving domain root DN from '$Server'..."
$domain      = Get-ADDomain -Server $Server
$domainDN    = $domain.DistinguishedName   # e.g. DC=Domain,DC=com

# Find all OUs whose DN matches: OU=<3 letters>,OU=<2 letters>,DC=...
# The filter uses a regex applied after retrieval because Get-ADOrganizationalUnit
# LDAPFilter does not support full regex; we filter client-side.
Write-Verbose "Searching for site OUs under '$domainDN'..."
$siteOUPattern = '^OU=[A-Za-z]{3},OU=[A-Za-z]{2},' + [regex]::Escape($domainDN) + '$'

$allOUs = Get-ADOrganizationalUnit -Filter * -Server $Server -SearchBase $domainDN -SearchScope Subtree

$siteOUs = $allOUs | Where-Object { $_.DistinguishedName -match $siteOUPattern }

if (-not $siteOUs) {
    Write-Warning "No OUs matching the site pattern (OU=XXX,OU=CC,$domainDN) were found."
    exit 0
}

Write-Host "Found $(@($siteOUs).Count) matching site OU(s)." -ForegroundColor Cyan

$linked   = [System.Collections.Generic.List[string]]::new()
$skipped  = [System.Collections.Generic.List[string]]::new()
$failed   = [System.Collections.Generic.List[string]]::new()

foreach ($ou in $siteOUs) {
    $ouDN = $ou.DistinguishedName
    Write-Verbose "Processing OU: $ouDN"

    # Check whether the GPO is already linked to this OU
    $existingLinks = (Get-GPInheritance -Target $ouDN -Server $Server).GpoLinks
    $alreadyLinked = $existingLinks | Where-Object { $_.DisplayName -eq $GPOName }

    if ($alreadyLinked) {
        Write-Host "  [SKIP]   $ouDN — GPO already linked." -ForegroundColor Yellow
        $skipped.Add($ouDN)
        continue
    }

    if ($PSCmdlet.ShouldProcess($ouDN, "New-GPLink '$GPOName'")) {
        try {
            New-GPLink -Name $GPOName -Target $ouDN -Server $Server `
                       -LinkEnabled $(if ($LinkEnabled) { 'Yes' } else { 'No' }) `
                       -Enforced    $(if ($Enforced)    { 'Yes' } else { 'No' }) | Out-Null

            Write-Host "  [LINKED] $ouDN" -ForegroundColor Green
            $linked.Add($ouDN)
        }
        catch {
            Write-Warning "  [FAILED] $ouDN — $_"
            $failed.Add($ouDN)
        }
    }
}

Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  Linked : $($linked.Count)"
Write-Host "  Skipped: $($skipped.Count)"
Write-Host "  Failed : $($failed.Count)"

if ($failed.Count -gt 0) {
    Write-Warning "The following OUs failed to link:"
    $failed | ForEach-Object { Write-Warning "  $_" }
    exit 1
}
