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

$languageMode = $ExecutionContext.SessionState.LanguageMode
$listenAddress = $BindIp.IPAddressToString
$connectAddress = $TargetIp.IPAddressToString

if ($languageMode -eq [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage) {
    Write-Warning "PowerShell is running in ConstrainedLanguage mode, so TcpListener cannot be created. Using netsh portproxy instead."
}

$existingRules = (& netsh interface portproxy show v4tov4) 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Unable to query existing portproxy rules. Run PowerShell as Administrator."
}

$rulePattern = "(?m)^\s*$([regex]::Escape($listenAddress))\s+$BindPort\s+"
if ($existingRules -match $rulePattern) {
    if (-not $ReplaceExistingRule) {
        throw "A portproxy rule already exists for $listenAddress`:$BindPort. Re-run with -ReplaceExistingRule to overwrite it."
    }

    & netsh interface portproxy delete v4tov4 listenaddress=$listenAddress listenport=$BindPort | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove the existing portproxy rule for $listenAddress`:$BindPort."
    }
}

& netsh interface portproxy add v4tov4 listenaddress=$listenAddress listenport=$BindPort connectaddress=$connectAddress connectport=$TargetPort | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create the portproxy rule. Run PowerShell as Administrator and verify the address and port values."
}

Write-Host "Port proxy configured: $listenAddress`:$BindPort -> $connectAddress`:$TargetPort"
