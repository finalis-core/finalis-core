[CmdletBinding()]
param(
    [string]$DataDir = "",
    [int]$P2PPort = 19440,
    [int]$LightserverPort = 19444,
    [int]$ExplorerPort = 18080,
    [string]$LightserverBind = "127.0.0.1",
    [string]$ExplorerBind = "127.0.0.1",
    [bool]$WithExplorer = $true,
    [switch]$ConfigureFirewall,
    [switch]$NoStart,
    [switch]$PublicNode,
    [ValidateSet("auto", "bootstrap", "joiner")]
    [string]$NodeRole = "auto"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DataDir)) {
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        $DataDir = Join-Path $env:APPDATA ".finalis\mainnet"
    } elseif (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $DataDir = Join-Path $env:USERPROFILE ".finalis\mainnet"
    } else {
        $DataDir = ".finalis\mainnet"
    }
}

$appRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$binDir = Join-Path $appRoot "bin"
$nodeExe = Join-Path $binDir "finalis-node.exe"
$explorerExe = Join-Path $binDir "finalis-explorer.exe"
$seedsJson = Join-Path $appRoot "mainnet\SEEDS.json"
$logDir = Join-Path $DataDir "logs"

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "keystore") | Out-Null

if (-not (Test-Path $nodeExe)) {
    throw "finalis-node.exe not found at $nodeExe"
}

function Ensure-FirewallRule {
    param(
        [string]$DisplayName,
        [int]$Port,
        [string]$ProgramPath
    )

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($existing) {
        return
    }

    $params = @{
        DisplayName = $DisplayName
        Direction   = "Inbound"
        Action      = "Allow"
        Enabled     = "True"
        Profile     = "Any"
        Protocol    = "TCP"
        LocalPort   = $Port
    }
    if ($ProgramPath -and (Test-Path $ProgramPath)) {
        $params["Program"] = $ProgramPath
    }
    New-NetFirewallRule @params | Out-Null
}

function Ensure-FinalisFirewallRules {
    try {
        Ensure-FirewallRule -DisplayName "Finalis P2P ($P2PPort)" -Port $P2PPort -ProgramPath $nodeExe
        Ensure-FirewallRule -DisplayName "Finalis Lightserver RPC ($LightserverPort)" -Port $LightserverPort -ProgramPath $nodeExe
        if ($WithExplorer -and (Test-Path $explorerExe)) {
            Ensure-FirewallRule -DisplayName "Finalis Explorer ($ExplorerPort)" -Port $ExplorerPort -ProgramPath $explorerExe
        }
    } catch {
        Write-Warning "Firewall rule setup failed: $($_.Exception.Message)"
    }
}

if ($ConfigureFirewall.IsPresent) {
    Ensure-FinalisFirewallRules
}

if ($NoStart.IsPresent) {
    Write-Host "Finalis firewall configuration complete."
    Write-Host "Data dir: $DataDir"
    exit 0
}

$nodeArgs = @(
    "--db", $DataDir,
    "--port", $P2PPort,
    "--with-lightserver",
    "--lightserver-bind", $LightserverBind,
    "--lightserver-port", $LightserverPort
)

if ($PublicNode.IsPresent) {
    $nodeArgs += "--public"
}

switch ($NodeRole) {
    "bootstrap" {
        $nodeArgs += @("--listen", "--bind", "0.0.0.0", "--no-dns-seeds", "--outbound-target", "0")
    }
    "joiner" {
        $nodeArgs += @("--no-dns-seeds", "--outbound-target", "1")
    }
    default {
        if (Test-Path $seedsJson) {
            $nodeArgs += @("--no-dns-seeds", "--outbound-target", "1")
        } else {
            $nodeArgs += @("--listen", "--bind", "127.0.0.1", "--no-dns-seeds", "--outbound-target", "0")
        }
    }
}

if ((Test-Path $seedsJson) -and $NodeRole -ne "bootstrap") {
    $seedList = Get-Content $seedsJson -Raw | ConvertFrom-Json
    foreach ($seed in $seedList) {
        if ($seed) {
            $nodeArgs += @("--peers", [string]$seed)
        }
    }
}

Ensure-FinalisFirewallRules

$nodeLog = Join-Path $logDir "node.log"
$nodeErr = Join-Path $logDir "node.err.log"
Start-Process -FilePath $nodeExe -ArgumentList $nodeArgs -WorkingDirectory $appRoot -RedirectStandardOutput $nodeLog -RedirectStandardError $nodeErr | Out-Null

if ($WithExplorer -and (Test-Path $explorerExe)) {
    $explorerArgs = @(
        "--bind", $ExplorerBind,
        "--port", $ExplorerPort,
        "--rpc-url", "http://127.0.0.1:$LightserverPort/rpc"
    )
    $explorerLog = Join-Path $logDir "explorer.log"
    $explorerErr = Join-Path $logDir "explorer.err.log"
    Start-Process -FilePath $explorerExe -ArgumentList $explorerArgs -WorkingDirectory $appRoot -RedirectStandardOutput $explorerLog -RedirectStandardError $explorerErr | Out-Null
}

Write-Host "Finalis node started."
Write-Host "Data dir: $DataDir"
Write-Host "Lightserver RPC: http://127.0.0.1:$LightserverPort/rpc"
if ($WithExplorer -and (Test-Path $explorerExe)) {
    Write-Host "Explorer: http://127.0.0.1:$ExplorerPort"
}
