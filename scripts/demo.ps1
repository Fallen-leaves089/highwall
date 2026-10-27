#Requires -Version 5.1
<#
.SYNOPSIS
Run a one-machine HighWall demo and print a deterministic transcript.

.DESCRIPTION
Starts the existing quickstart demo upstream and HighWall on loopback, sends
normal and blocked requests, prints the resulting audit events, then stops both
processes. No administrator rights, public binding, firewall changes, or
network access are required.
#>
[CmdletBinding()]
param(
    [int]$UpstreamPort = 0,
    [int]$ListenPort = 0,
    [string]$RuntimeDir = '',
    [switch]$KeepRuntime,
    [string]$Python = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = [System.Text.UTF8Encoding]::new($false)
try {
    [Console]::OutputEncoding = $utf8
}
catch {
}
$OutputEncoding = $utf8

$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    throw 'Cannot determine the script path.'
}
$scriptRoot = Split-Path -Parent $scriptPath
$repoRoot = Split-Path -Parent $scriptRoot
$quickstart = Join-Path $scriptRoot 'quickstart.ps1'
if (-not (Test-Path -LiteralPath $quickstart -PathType Leaf)) {
    throw ("quickstart.ps1 was not found: {0}" -f $quickstart)
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Send-RawRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$HostHeader
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 5000
        $client.SendTimeout = 5000
        $client.Connect('127.0.0.1', $ListenPort)
        $stream = $client.GetStream()
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::ASCII)
        $writer.NewLine = "`r`n"
        $writer.AutoFlush = $true
        $writer.WriteLine(("{0} {1} HTTP/1.1" -f $Method, $Path))
        $writer.WriteLine(("Host: {0}" -f $HostHeader))
        $writer.WriteLine('Connection: close')
        $writer.WriteLine('')

        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::ASCII)
        $statusLine = $reader.ReadLine()
        if ($null -eq $statusLine -or $statusLine -notmatch '^HTTP/\d\.\d\s+(\d{3})') {
            throw 'HighWall returned a malformed or empty HTTP status line.'
        }
        return [int]$Matches[1]
    }
    finally {
        $client.Dispose()
    }
}

function Invoke-Quickstart {
    param([string[]]$Arguments)

    Push-Location -LiteralPath $repoRoot
    try {
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $quickstart @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = @($output)
    }
}

if ($UpstreamPort -le 0) {
    $UpstreamPort = Get-FreeTcpPort
}
if ($ListenPort -le 0) {
    do {
        $ListenPort = Get-FreeTcpPort
    }
    while ($ListenPort -eq $UpstreamPort)
}

if ([string]::IsNullOrWhiteSpace($RuntimeDir)) {
    $RuntimeDir = Join-Path $repoRoot ('.runtime-demo-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID)
}
$RuntimeDir = [System.IO.Path]::GetFullPath($RuntimeDir)
New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null

$failed = $false
$started = $false
try {
    $setupArgs = @(
        '-WithDemoUpstream',
        '-Reconfigure',
        '-RuntimeDir', $RuntimeDir,
        '-UpstreamUrl', ("http://127.0.0.1:{0}" -f $UpstreamPort),
        '-ListenPort', [string]$ListenPort,
        '-AllowedHost', 'app.internal'
    )
    if (-not [string]::IsNullOrWhiteSpace($Python)) {
        $setupArgs += @('-Python', $Python)
    }

    $setup = Invoke-Quickstart -Arguments $setupArgs
    Set-Content -LiteralPath (Join-Path $RuntimeDir 'demo-setup.log') -Value $setup.Output -Encoding UTF8
    if ($setup.ExitCode -ne 0) {
        $setup.Output | ForEach-Object { Write-Output $_ }
        throw ("quickstart failed with exit code {0}" -f $setup.ExitCode)
    }
    $started = $true

    Write-Output 'HighWall single-machine demo'
    Write-Output ("  listen:   127.0.0.1:{0}" -f $ListenPort)
    Write-Output ("  upstream: 127.0.0.1:{0}" -f $UpstreamPort)
    Write-Output ''

    $cases = @(
        [pscustomobject]@{ Name = 'normal'; Method = 'GET'; Path = '/'; HostHeader = 'app.internal'; Expected = 200 },
        [pscustomobject]@{ Name = 'bad host'; Method = 'GET'; Path = '/'; HostHeader = 'evil.invalid'; Expected = 403 },
        [pscustomobject]@{ Name = 'sqli'; Method = 'GET'; Path = '/?id=1%27%20OR%20%271%27%3D%271'; HostHeader = 'app.internal'; Expected = 403 },
        [pscustomobject]@{ Name = 'traversal'; Method = 'GET'; Path = '/%2e%2e%2f%2e%2e%2fetc%2fpasswd'; HostHeader = 'app.internal'; Expected = 400 },
        [pscustomobject]@{ Name = 'honeypot'; Method = 'GET'; Path = '/.env'; HostHeader = 'app.internal'; Expected = 200 },
        [pscustomobject]@{ Name = 'trace'; Method = 'TRACE'; Path = '/'; HostHeader = 'app.internal'; Expected = 405 }
    )

    foreach ($case in $cases) {
        $status = Send-RawRequest -Method $case.Method -Path $case.Path -HostHeader $case.HostHeader
        if ($status -eq $case.Expected) {
            $result = 'PASS'
        }
        else {
            $result = 'FAIL'
            $failed = $true
        }
        Write-Output ('[{0}] {1,-12} status={2} expected={3}' -f $result, $case.Name, $status, $case.Expected)
    }

    Start-Sleep -Milliseconds 200
    $auditPath = Join-Path $RuntimeDir 'audit.jsonl'
    if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
        throw 'audit.jsonl was not created.'
    }

    $events = @()
    foreach ($line in Get-Content -LiteralPath $auditPath -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        try {
            $events += ($line | ConvertFrom-Json)
        }
        catch {
        }
    }

    $interesting = @($events | Where-Object { $_.event -eq 'request_blocked' -or $_.event -eq 'honeypot_hit' } | Select-Object -Last 8)
    if ($interesting.Count -eq 0) {
        throw 'No blocked or honeypot audit events were recorded.'
    }
    if (-not ($interesting | Where-Object { $_.event -eq 'honeypot_hit' })) {
        throw 'The honeypot request did not produce a honeypot_hit event.'
    }

    Write-Output ''
    foreach ($event in $interesting) {
        Write-Output ('[audit] {0,-15} status={1} rule={2}' -f $event.event, $event.status, $event.rule_id)
    }
}
catch {
    $failed = $true
    Write-Output ("[FAIL] {0}" -f $_.Exception.Message)
}
finally {
    if ($started) {
        $stop = Invoke-Quickstart -Arguments @('-Stop', '-RuntimeDir', $RuntimeDir)
        if ($stop.ExitCode -ne 0) {
            $stop.Output | ForEach-Object { Write-Output $_ }
            $failed = $true
        }
    }

    if (-not $KeepRuntime) {
        $rootFull = [System.IO.Path]::GetFullPath($repoRoot)
        $runtimeFull = [System.IO.Path]::GetFullPath($RuntimeDir)
        $leaf = Split-Path -Leaf $runtimeFull
        $rootPrefix = $rootFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
        if ($runtimeFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and $leaf.StartsWith('.runtime-demo')) {
            if ([System.IO.Directory]::Exists($runtimeFull)) {
                foreach ($file in [System.IO.Directory]::GetFiles($runtimeFull)) {
                    if (-not $file.StartsWith($runtimeFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw ("refusing to delete unexpected file: {0}" -f $file)
                    }
                    [System.IO.File]::Delete($file)
                }
                [System.IO.Directory]::Delete($runtimeFull, $false)
            }
        }
        else {
            Write-Output ("[info] runtime retained: {0}" -f $runtimeFull)
        }
    }
    else {
        Write-Output ("[info] runtime retained: {0}" -f $RuntimeDir)
    }
}

if ($failed) {
    exit 1
}
exit 0
