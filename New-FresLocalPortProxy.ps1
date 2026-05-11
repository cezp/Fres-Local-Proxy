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
