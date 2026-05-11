<#
.SYNOPSIS
Creates a Windows portproxy rule for local TCP forwarding.

.DESCRIPTION
Uses the native netsh portproxy feature instead of creating a TcpListener in PowerShell.
This avoids the "Only core types are supported in this language mode" error that occurs in constrained language sessions.

.PARAMETER BindIp
The local IPv4 address to listen on.

.PARAMETER BindPort
The local TCP port to listen on.

.PARAMETER TargetIp
The destination IPv4 address that receives forwarded traffic.

.PARAMETER TargetPort
The destination TCP port that receives forwarded traffic.

.PARAMETER ReplaceExistingRule
Removes an existing rule for the same listen address and port before creating the new rule.

.EXAMPLE
.\New-FresLocalPortProxy.ps1 -BindIp 127.0.0.2 -BindPort 8080 -TargetIp 10.0.0.10 -TargetPort 80

.EXAMPLE
.\New-FresLocalPortProxy.ps1 -BindIp 127.0.0.2 -BindPort 8080 -TargetIp 10.0.0.10 -TargetPort 80 -ReplaceExistingRule
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.Net.IPAddress]$BindIp,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$BindPort,

    [Parameter(Mandatory = $true)]
    [System.Net.IPAddress]$TargetIp,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$TargetPort,

    [switch]$ReplaceExistingRule
)

$whoAmIOutput = & whoami /groups /fo csv /nh 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Unable to determine whether the current session is elevated. whoami output: $($whoAmIOutput -join ' ')"
}

$isElevated = $false
foreach ($group in ($whoAmIOutput | ConvertFrom-Csv -Header "GroupName", "Type", "SID", "Attributes")) {
    if ($group.SID -eq "S-1-5-32-544" -and $group.Attributes -match "Enabled group") {
        $isElevated = $true
        break
    }
}

if (-not $isElevated) {
    throw "This script must be run from an elevated PowerShell session (Run as Administrator)."
}

$listenAddress = $BindIp.IPAddressToString
$connectAddress = $TargetIp.IPAddressToString

$existingRules = & netsh interface portproxy show v4tov4 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Unable to query existing portproxy rules. Run PowerShell as Administrator. netsh output: $($existingRules -join ' ')"
}

$rulePattern = "(?m)^\s*$([regex]::Escape($listenAddress))\s+$BindPort\s+"
if ($existingRules -match $rulePattern) {
    if (-not $ReplaceExistingRule) {
        throw "A portproxy rule already exists for $listenAddress`:$BindPort. Re-run with -ReplaceExistingRule to overwrite it."
    }

    $deleteResult = & netsh interface portproxy delete v4tov4 listenaddress=$listenAddress listenport=$BindPort 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove the existing portproxy rule for $listenAddress`:$BindPort. netsh output: $($deleteResult -join ' ')"
    }
}

$addResult = & netsh interface portproxy add v4tov4 listenaddress=$listenAddress listenport=$BindPort connectaddress=$connectAddress connectport=$TargetPort 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create the portproxy rule. Run PowerShell as Administrator and verify the address and port values. netsh output: $($addResult -join ' ')"
}

Write-Host "Port proxy configured: $listenAddress`:$BindPort -> $connectAddress`:$TargetPort"
