#Requires -Version 5.1
<#
.SYNOPSIS
Start a local HighWall instance with minimal manual setup.

.DESCRIPTION
Creates a compact configuration, validates it, starts a hidden HighWall
process, verifies the effective policy, and records the PID for later status
and stop operations. Existing configuration files are never replaced unless
-Reconfigure is explicit.

This script is intended for a local test or lab instance. It does not create a
Windows service, change firewall rules, change ACLs, or register startup tasks.
#>
[CmdletBinding()]
param(
    [string]$UpstreamUrl = 'http://127.0.0.1:8080',
    [string]$AllowedHost = 'app.internal',
    [string]$ListenHost = '127.0.0.1',
    [int]$ListenPort = 18090,
    [string[]]$Methods = @('GET', 'HEAD', 'POST'),
    [string[]]$HoneypotPresets = @('common'),
    [switch]$NoHoneypot,
    [string]$RuntimeDir = '',
    [switch]$Reconfigure,
    [switch]$WithDemoUpstream,
    [switch]$Status,
    [switch]$Stop,
    [switch]$AllowNetworkBinding,
    [string]$Python = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = New-Object System.Text.UTF8Encoding($false)
try {
    [Console]::OutputEncoding = $utf8
}
catch {
}
$OutputEncoding = $utf8

if ($Status -and $Stop) {
    throw 'Use either -Status or -Stop, not both.'
}

if ($NoHoneypot -and $PSBoundParameters.ContainsKey('HoneypotPresets')) {
    throw 'Use either -NoHoneypot or -HoneypotPresets, not both.'
}
if ((-not $NoHoneypot) -and $PSBoundParameters.ContainsKey('HoneypotPresets') -and @($HoneypotPresets).Count -eq 0) {
    throw 'HoneypotPresets must contain at least one preset; use -NoHoneypot to disable the honeypot.'
}

$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    throw 'Cannot determine the script path.'
}
$scriptRoot = Split-Path -Parent $scriptPath
$repoRoot = Split-Path -Parent $scriptRoot
if ([string]::IsNullOrWhiteSpace($RuntimeDir)) {
    $RuntimeDir = Join-Path $repoRoot '.runtime'
}
$RuntimeDir = [System.IO.Path]::GetFullPath($RuntimeDir)
$ConfigPath = Join-Path $RuntimeDir 'config.json'
$HighWallRecordPath = Join-Path $RuntimeDir 'highwall.pid.json'
$UpstreamRecordPath = Join-Path $RuntimeDir 'upstream.pid.json'

function Test-LoopbackName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }
    if ($Name -ieq 'localhost') {
        return $true
    }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($Name, [ref]$address)) {
        return [System.Net.IPAddress]::IsLoopback($address)
    }
    return $false
}

function Get-ProbeAddress {
    param([string]$BindHost)

    if ($BindHost -eq '0.0.0.0' -or $BindHost -eq '*' -or $BindHost -eq '::' -or $BindHost -eq '[::]') {
        return '127.0.0.1'
    }
    if ($BindHost -ieq 'localhost') {
        return '127.0.0.1'
    }
    return $BindHost
}

function Resolve-Python {
    if (-not [string]::IsNullOrWhiteSpace($Python)) {
        $candidate = $Python
    }
    else {
        $command = Get-Command 'python.exe' -ErrorAction SilentlyContinue
        if ($null -eq $command) {
            $command = Get-Command 'python' -ErrorAction SilentlyContinue
        }
        if ($null -eq $command) {
            throw 'Python was not found on PATH; pass -Python with python.exe.'
        }
        $candidate = $command.Source
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw ("Python executable does not exist: {0}" -f $candidate)
    }
    $version = & $candidate -c "import sys; print('.'.join(str(x) for x in sys.version_info[:3]))"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($version -join ''))) {
        throw 'Python version check failed.'
    }
    $text = (@($version) -join '').Trim()
    & $candidate -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
    if ($LASTEXITCODE -ne 0) {
        throw ("Python 3.10 or newer is required; found {0}." -f $text)
    }
    return $candidate
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMilliseconds = 400
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($TargetHost, $Port)
        if (-not $task.Wait($TimeoutMilliseconds)) {
            return $false
        }
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Wait-TcpPort {
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSeconds = 10
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (Test-TcpPort -TargetHost $TargetHost -Port $Port) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    while ([DateTime]::UtcNow -lt $deadline)
    return $false
}

function Get-HttpStatusCode {
    param(
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$HostHeader,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$TimeoutMilliseconds = 5000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.ReceiveTimeout = $TimeoutMilliseconds
        $client.SendTimeout = $TimeoutMilliseconds
        $client.Connect($TargetHost, $Port)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::ASCII)
        $writer.NewLine = "`r`n"
        $writer.AutoFlush = $true
        $writer.WriteLine(("GET {0} HTTP/1.1" -f $Path))
        $writer.WriteLine(("Host: {0}" -f $HostHeader))
        $writer.WriteLine('Connection: close')
        $writer.WriteLine('')
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
        $statusLine = $reader.ReadLine()
        if ($null -eq $statusLine -or $statusLine -notmatch '^HTTP/\d\.\d\s+(\d{3})') {
            throw 'The proxy returned a malformed or empty HTTP status line.'
        }
        return [int]$Matches[1]
    }
    finally {
        $client.Dispose()
    }
}

function Read-ProcessRecord {
    param([Parameter(Mandatory = $true)][string]$RecordPath)

    if (-not (Test-Path -LiteralPath $RecordPath -PathType Leaf)) {
        return $null
    }
    try {
        $text = Get-Content -Raw -LiteralPath $RecordPath
        return ($text | ConvertFrom-Json)
    }
    catch {
        return $null
    }
}

function Get-RecordedProcess {
    param([Parameter(Mandatory = $true)][string]$RecordPath)

    $record = Read-ProcessRecord -RecordPath $RecordPath
    if ($null -eq $record) {
        return $null
    }
    try {
        $process = Get-Process -Id ([int]$record.pid) -ErrorAction Stop
        $recordedStart = [DateTime]::Parse(
            [string]$record.startTimeUtc,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
        $actualStart = $process.StartTime.ToUniversalTime()
        if ([Math]::Abs(($actualStart - $recordedStart.ToUniversalTime()).TotalSeconds) -gt 2.0) {
            return $null
        }
        return $process
    }
    catch {
        return $null
    }
}

function Remove-ProcessRecord {
    param([Parameter(Mandatory = $true)][string]$RecordPath)

    if (Test-Path -LiteralPath $RecordPath -PathType Leaf) {
        Remove-Item -LiteralPath $RecordPath -ErrorAction SilentlyContinue
    }
}

function Stop-RecordedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$RecordPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $process = Get-RecordedProcess -RecordPath $RecordPath
    if ($null -eq $process) {
        Remove-ProcessRecord -RecordPath $RecordPath
        return $false
    }
    $processId = [int]$process.Id
    try {
        Stop-Process -Id $processId -ErrorAction SilentlyContinue
    }
    catch {
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(5)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if ($null -ne (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
    Remove-ProcessRecord -RecordPath $RecordPath
    return $true
}

function Start-ManagedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$StandardOutput,
        [Parameter(Mandatory = $true)][string]$StandardError,
        [Parameter(Mandatory = $true)][string]$RecordPath,
        [Parameter(Mandatory = $true)][string]$Kind,
        [hashtable]$Details = @{}
    )

    foreach ($logPath in @($StandardOutput, $StandardError)) {
        if (Test-Path -LiteralPath $logPath -PathType Leaf) {
            Remove-Item -LiteralPath $logPath -Force
        }
    }
    $launcher = Join-Path $scriptRoot 'launch_detached.py'
    if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
        throw ("Detached launcher is missing: {0}" -f $launcher)
    }
    $launcherArguments = @(
        $launcher,
        '--stdout', $StandardOutput,
        '--stderr', $StandardError,
        '--working-dir', $WorkingDirectory,
        '--',
        $FilePath
    ) + $Arguments
    $launchResult = & $FilePath @launcherArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'The detached process launcher failed.'
    }
    $launchText = (@($launchResult) -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($launchText)) {
        throw 'The detached process launcher returned no process information.'
    }
    $launchInfo = $launchText | ConvertFrom-Json
    $process = Get-Process -Id ([int]$launchInfo.pid) -ErrorAction Stop
    $record = [ordered]@{
        kind = $Kind
        pid = [int]$process.Id
        startTimeUtc = $process.StartTime.ToUniversalTime().ToString('o')
        details = $Details
    }
    ($record | ConvertTo-Json -Depth 4 -Compress) | Set-Content -LiteralPath $RecordPath -Encoding UTF8
    return $process
}

function Get-StderrTail {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ''
    }
    return ((Get-Content -LiteralPath $Path -Tail 20 -ErrorAction SilentlyContinue) -join [Environment]::NewLine)
}

function Get-EffectiveConfiguration {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $json = & $PythonPath -m highwall inspect -c $Path
    if ($LASTEXITCODE -ne 0) {
        throw 'The effective configuration could not be inspected.'
    }
    $text = (@($json) -join "`n")
    return ($text | ConvertFrom-Json)
}

function Assert-ConfigurationCheck {
    param(
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [Parameter(Mandatory = $true)][string]$Path
    )

    & $PythonPath -m highwall check -c $Path | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'The effective configuration failed highwall check.'
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    $stream = $null
    $sha256 = $null
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $digest = $sha256.ComputeHash($stream)
        return ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $sha256) {
            $sha256.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Get-ConfigFileState {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    $recordedHash = $null
    if ($null -ne $Record.PSObject.Properties['details']) {
        $details = $Record.details
        if ($null -ne $details -and $null -ne $details.PSObject.Properties['configSha256']) {
            $recordedHash = [string]$details.configSha256
        }
    }
    $currentHash = Get-FileSha256 -Path $ConfigPath
    if ([string]::IsNullOrWhiteSpace($recordedHash)) {
        return 'unknown'
    }
    if ([string]::IsNullOrWhiteSpace($currentHash)) {
        return 'changed'
    }
    if ($recordedHash.ToLowerInvariant() -eq $currentHash) {
        return 'match'
    }
    return 'changed'
}

function Assert-StringEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [AllowEmptyString()][string]$Expected,
        [AllowEmptyString()][string]$Actual
    )

    if ($Expected -ine $Actual) {
        throw ("Requested {0} '{1}' does not match effective value '{2}'." -f $Label, $Expected, $Actual)
    }
}

function Assert-RequestedConfiguration {
    param(
        [Parameter(Mandatory = $true)]$Effective,
        [string[]]$Only
    )

    $check = {
        param([string]$Name)
        return ($null -eq $Only -or $Only -contains $Name)
    }

    if (& $check 'UpstreamUrl') {
        try {
            $requested = [Uri]$UpstreamUrl
        }
        catch {
            throw 'Requested upstream URL is malformed.'
        }
        if (-not $requested.IsAbsoluteUri -or $requested.Scheme -notin @('http', 'https')) {
            throw 'Requested upstream URL must be an absolute http or https URL.'
        }
        if (-not [string]::IsNullOrEmpty($requested.UserInfo)) {
            throw 'Requested upstream URL must not contain user information.'
        }
        if ($requested.AbsolutePath -ne '/' -or -not [string]::IsNullOrEmpty($requested.Query) -or -not [string]::IsNullOrEmpty($requested.Fragment)) {
            throw 'Requested upstream URL must not contain a path, query, or fragment.'
        }
        Assert-StringEqual -Label 'upstream scheme' -Expected $requested.Scheme -Actual ([string]$Effective.upstream.scheme)
        $requestedHost = $requested.Host.TrimStart('[').TrimEnd(']')
        Assert-StringEqual -Label 'upstream host' -Expected $requestedHost -Actual ([string]$Effective.upstream.host)
        if ($requested.Port -ne [int]$Effective.upstream.port) {
            throw ("Requested upstream port {0} does not match effective port {1}." -f $requested.Port, [int]$Effective.upstream.port)
        }
    }
    if (& $check 'AllowedHost') {
        $actualHosts = @($Effective.policy.allowed_hosts | ForEach-Object { [string]$_ })
        $expectedHost = $AllowedHost.Trim().TrimEnd('.').ToLowerInvariant()
        if ($actualHosts -notcontains $expectedHost) {
            throw ("Requested allowed host '{0}' is not present in the effective configuration." -f $AllowedHost)
        }
    }
    if (& $check 'ListenHost') {
        Assert-StringEqual -Label 'listen host' -Expected $ListenHost -Actual ([string]$Effective.server.listen_host)
    }
    if (& $check 'ListenPort') {
        if ([int]$Effective.server.listen_port -ne $ListenPort) {
            throw ("Requested listen port {0} does not match effective port {1}." -f $ListenPort, [int]$Effective.server.listen_port)
        }
    }
    if (& $check 'Methods') {
        $actualMethods = @($Effective.policy.allowed_methods | ForEach-Object { [string]$_ })
        $expectedMethods = @($Methods | ForEach-Object { ([string]$_).ToUpperInvariant() })
        if (($actualMethods -join ',') -ine ($expectedMethods -join ',')) {
            throw 'Requested methods do not match the effective allowed methods.'
        }
    }
    if ($NoHoneypot -and [bool]$Effective.policy.honeypot.enabled) {
        throw 'Honeypot was requested off but is still enabled in the effective configuration.'
    }
    if ((-not $NoHoneypot) -and ($null -eq $Only -or $Only -contains 'HoneypotPresets')) {
        if (-not [bool]$Effective.policy.honeypot.enabled) {
            throw 'Honeypot presets were requested but the effective configuration disables the honeypot.'
        }
        if (@($Effective.policy.honeypot.routes).Count -eq 0) {
            throw 'Honeypot is enabled but no effective routes were expanded.'
        }
    }
}

function Get-ProvidedConfigParameterNames {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$BoundParameters)

    $names = New-Object System.Collections.ArrayList
    foreach ($name in @('UpstreamUrl', 'AllowedHost', 'ListenHost', 'ListenPort', 'Methods', 'HoneypotPresets', 'NoHoneypot')) {
        if (-not $BoundParameters.ContainsKey($name)) {
            continue
        }
        if ($name -eq 'NoHoneypot' -and -not $NoHoneypot) {
            continue
        }
        [void]$names.Add($name)
    }
    return @($names)
}

function Test-RuntimeDirectory {
    if (-not (Test-Path -LiteralPath $RuntimeDir)) {
        New-Item -ItemType Directory -Path $RuntimeDir | Out-Null
        return
    }
    $item = Get-Item -LiteralPath $RuntimeDir -Force
    if (-not $item.PSIsContainer) {
        throw ("Runtime path is not a directory: {0}" -f $RuntimeDir)
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw ("Runtime directory must not be a reparse point: {0}" -f $RuntimeDir)
    }
}

try {
    if ($Status) {
        $record = Read-ProcessRecord -RecordPath $HighWallRecordPath
        $process = Get-RecordedProcess -RecordPath $HighWallRecordPath
        if ($null -eq $process) {
            if ($null -ne $record) {
                Remove-ProcessRecord -RecordPath $HighWallRecordPath
            }
            Write-Output 'HighWall status: stopped'
            exit 1
        }

        $details = $record.details
        $configState = Get-ConfigFileState -Record $record -ConfigPath ([string]$details.configPath)
        $targetHost = [string]$details.listenHost
        $port = [int]$details.listenPort
        $reachable = Test-TcpPort -TargetHost (Get-ProbeAddress -BindHost $targetHost) -Port $port
        Write-Output 'HighWall status: running'
        Write-Output ("  pid: {0}" -f $process.Id)
        Write-Output ("  listen: {0}:{1}" -f $targetHost, $port)
        Write-Output ("  config: {0}" -f $details.configPath)
        Write-Output ("  port reachable: {0}" -f $reachable)
        if ($configState -eq 'match') {
            Write-Output '  configuration changed since start: False'
        }
        elseif ($configState -eq 'changed') {
            Write-Output '  configuration changed since start: True'
            Write-Output '  warning: the running process has not reloaded the changed configuration; restart it.'
        }
        else {
            Write-Output '  configuration changed since start: unknown'
        }
        $demo = Get-RecordedProcess -RecordPath $UpstreamRecordPath
        if ($null -eq $demo) {
            Write-Output '  demo upstream: not running'
        }
        else {
            Write-Output ("  demo upstream: running (pid {0})" -f $demo.Id)
        }
        if ($reachable -and $configState -ne 'changed') {
            exit 0
        }
        exit 1
    }

    if ($Stop) {
        $stopped = Stop-RecordedProcess -RecordPath $HighWallRecordPath -Label 'HighWall'
        $demoStopped = Stop-RecordedProcess -RecordPath $UpstreamRecordPath -Label 'demo upstream'
        if (-not $stopped -and -not $demoStopped) {
            Write-Output 'HighWall is already stopped.'
        }
        else {
            if ($stopped) {
                Write-Output 'Stopped HighWall.'
            }
            if ($demoStopped) {
                Write-Output 'Stopped demo upstream.'
            }
        }
        exit 0
    }

    $pythonPath = Resolve-Python
    Test-RuntimeDirectory
    $configExists = Test-Path -LiteralPath $ConfigPath -PathType Leaf
    $mergeExisting = $configExists -and $Reconfigure
    $effective = $null
    $providedNames = Get-ProvidedConfigParameterNames -BoundParameters $PSBoundParameters
    $runningAtStart = Get-RecordedProcess -RecordPath $HighWallRecordPath
    if ($null -ne $runningAtStart -and $Reconfigure) {
        throw 'HighWall is running; stop it before using -Reconfigure.'
    }

    if ($configExists) {
        $effective = Get-EffectiveConfiguration -PythonPath $pythonPath -Path $ConfigPath
        if (-not $Reconfigure) {
            if ($providedNames -contains 'HoneypotPresets') {
                throw 'Existing configuration cannot prove that newly requested honeypot presets were applied; use -Reconfigure.'
            }
            $driftNames = @($providedNames | Where-Object { $_ -ne 'NoHoneypot' })
            if ($NoHoneypot -and [bool]$effective.policy.honeypot.enabled) {
                $driftNames += 'NoHoneypot'
            }
            if ($driftNames.Count -gt 0) {
                Assert-RequestedConfiguration -Effective $effective -Only $driftNames
            }
        }
        else {
            $stamp = Get-Date -Format 'yyyyMMddHHmmssfff'
            $backupPath = ("{0}.bak.{1}" -f $ConfigPath, $stamp)
            Copy-Item -LiteralPath $ConfigPath -Destination $backupPath
            Write-Output ("Existing configuration backed up to {0}" -f $backupPath)
        }
    }

    if ($mergeExisting) {
        if ($PSBoundParameters.ContainsKey('AllowedHost') -and [string]::IsNullOrWhiteSpace($AllowedHost)) {
            throw 'AllowedHost must not be empty.'
        }
        if ($PSBoundParameters.ContainsKey('Methods') -and @($Methods).Count -eq 0) {
            throw 'Methods must contain at least one method.'
        }
        $initArguments = @(
            '-m', 'highwall', 'init',
            '--base', $ConfigPath,
            '--output', $ConfigPath,
            '--force'
        )
        if ($PSBoundParameters.ContainsKey('UpstreamUrl')) {
            $initArguments += @('--upstream', $UpstreamUrl)
        }
        if ($PSBoundParameters.ContainsKey('AllowedHost')) {
            $initArguments += @('--allowed-host', $AllowedHost)
        }
        if ($PSBoundParameters.ContainsKey('ListenHost')) {
            $initArguments += @('--listen-host', $ListenHost)
        }
        if ($PSBoundParameters.ContainsKey('ListenPort')) {
            $initArguments += @('--listen-port', [string]$ListenPort)
        }
        if ($PSBoundParameters.ContainsKey('Methods')) {
            foreach ($method in $Methods) {
                $initArguments += @('--method', [string]$method)
            }
        }
        if ($NoHoneypot) {
            $initArguments += '--no-honeypot'
        }
        elseif ($PSBoundParameters.ContainsKey('HoneypotPresets')) {
            foreach ($preset in $HoneypotPresets) {
                $initArguments += @('--honeypot-preset', [string]$preset)
            }
        }
        & $pythonPath @initArguments
        if ($LASTEXITCODE -ne 0) {
            throw 'Configuration merge failed.'
        }
        Write-Output 'Existing configuration merged; unspecified settings preserved.'
        $effective = Get-EffectiveConfiguration -PythonPath $pythonPath -Path $ConfigPath
        Assert-RequestedConfiguration -Effective $effective -Only $providedNames
    }
    elseif (-not $configExists) {
        if ([string]::IsNullOrWhiteSpace($AllowedHost)) {
            throw 'AllowedHost must not be empty.'
        }
        if ($null -eq $Methods -or @($Methods).Count -eq 0) {
            throw 'Methods must contain at least one method.'
        }
        $initArguments = @(
            '-m', 'highwall', 'init',
            '--output', $ConfigPath,
            '--upstream', $UpstreamUrl,
            '--allowed-host', $AllowedHost,
            '--listen-host', $ListenHost,
            '--listen-port', [string]$ListenPort,
            '--audit-path', 'audit.jsonl'
        )
        foreach ($method in $Methods) {
            $initArguments += @('--method', [string]$method)
        }
        if ($NoHoneypot -or @($HoneypotPresets).Count -eq 0) {
            $initArguments += '--no-honeypot'
        }
        else {
            foreach ($preset in $HoneypotPresets) {
                $initArguments += @('--honeypot-preset', [string]$preset)
            }
        }
        & $pythonPath @initArguments
        if ($LASTEXITCODE -ne 0) {
            throw 'Configuration generation failed.'
        }
        $effective = Get-EffectiveConfiguration -PythonPath $pythonPath -Path $ConfigPath
        Assert-RequestedConfiguration -Effective $effective
    }

    Assert-ConfigurationCheck -PythonPath $pythonPath -Path $ConfigPath

    $effectiveListenHost = [string]$effective.server.listen_host
    $effectiveListenPort = [int]$effective.server.listen_port
    $effectiveUpstreamScheme = [string]$effective.upstream.scheme
    $effectiveUpstreamHost = [string]$effective.upstream.host
    $effectiveUpstreamPort = [int]$effective.upstream.port
    $probeHost = Get-ProbeAddress -BindHost $effectiveListenHost

    if ((-not (Test-LoopbackName $effectiveListenHost)) -and (-not $AllowNetworkBinding)) {
        throw ("Refusing non-loopback listen host '{0}' without -AllowNetworkBinding." -f $effectiveListenHost)
    }
    if ($WithDemoUpstream) {
        if ($effectiveUpstreamScheme -ne 'http') {
            throw 'The demo upstream only supports an http upstream.'
        }
        if (-not (Test-LoopbackName $effectiveUpstreamHost)) {
            throw 'The demo upstream is only allowed for a loopback upstream.'
        }
        if ($effectiveUpstreamPort -eq $effectiveListenPort) {
            throw 'The demo upstream port must differ from the HighWall listen port.'
        }
    }

    $alreadyRunning = Get-RecordedProcess -RecordPath $HighWallRecordPath
    if ($null -ne $alreadyRunning) {
        if (Test-TcpPort -TargetHost $probeHost -Port $effectiveListenPort) {
            $runningRecord = Read-ProcessRecord -RecordPath $HighWallRecordPath
            if ($null -eq $runningRecord) {
                throw 'The HighWall process record disappeared while it was running.'
            }
            $configState = Get-ConfigFileState -Record $runningRecord -ConfigPath ([string]$runningRecord.details.configPath)
            if ($configState -eq 'changed') {
                throw 'The configuration changed after HighWall started; stop it before restarting or reconfiguring.'
            }
            Write-Output ("HighWall is already running (pid {0})." -f $alreadyRunning.Id)
            exit 0
        }
        throw 'A recorded HighWall process is running but its listen port is not reachable; use -Stop and retry.'
    }
    Remove-ProcessRecord -RecordPath $HighWallRecordPath
    if (Test-TcpPort -TargetHost $probeHost -Port $effectiveListenPort) {
        throw ("Listen port {0}:{1} is already in use by another process." -f $effectiveListenHost, $effectiveListenPort)
    }

    $demoProcess = $null
    $highwallProcess = $null
    try {
        if ($WithDemoUpstream) {
            if (Test-TcpPort -TargetHost (Get-ProbeAddress -BindHost $effectiveUpstreamHost) -Port $effectiveUpstreamPort) {
                throw ("Demo upstream port {0} is already in use; refusing to hide an existing service." -f $effectiveUpstreamPort)
            }
            $demoProcess = Start-ManagedProcess `
                -FilePath $pythonPath `
                -Arguments @('-m', 'http.server', [string]$effectiveUpstreamPort, '--bind', $effectiveUpstreamHost) `
                -WorkingDirectory $repoRoot `
                -StandardOutput (Join-Path $RuntimeDir 'upstream.stdout.log') `
                -StandardError (Join-Path $RuntimeDir 'upstream.stderr.log') `
                -RecordPath $UpstreamRecordPath `
                -Kind 'demo-upstream' `
                -Details @{ host = $effectiveUpstreamHost; port = $effectiveUpstreamPort }
            if (-not (Wait-TcpPort -TargetHost (Get-ProbeAddress -BindHost $effectiveUpstreamHost) -Port $effectiveUpstreamPort)) {
                $tail = Get-StderrTail -Path (Join-Path $RuntimeDir 'upstream.stderr.log')
                throw ("Demo upstream did not become ready. {0}" -f $tail)
            }
        }

        $configSha256 = Get-FileSha256 -Path $ConfigPath
        if ([string]::IsNullOrWhiteSpace($configSha256)) {
            throw 'The configuration file disappeared before HighWall startup.'
        }
        $highwallProcess = Start-ManagedProcess `
            -FilePath $pythonPath `
            -Arguments @('-m', 'highwall', 'serve', '-c', $ConfigPath) `
            -WorkingDirectory $repoRoot `
            -StandardOutput (Join-Path $RuntimeDir 'highwall.stdout.log') `
            -StandardError (Join-Path $RuntimeDir 'highwall.stderr.log') `
            -RecordPath $HighWallRecordPath `
            -Kind 'highwall' `
            -Details @{
                configPath = $ConfigPath
                listenHost = $effectiveListenHost
                listenPort = $effectiveListenPort
                upstream = ("{0}://{1}:{2}" -f $effectiveUpstreamScheme, $effectiveUpstreamHost, $effectiveUpstreamPort)
                configSha256 = $configSha256
            }

        if (-not (Wait-TcpPort -TargetHost $probeHost -Port $effectiveListenPort -TimeoutSeconds 10)) {
            if ($null -ne (Get-Process -Id $highwallProcess.Id -ErrorAction SilentlyContinue)) {
                Stop-Process -Id $highwallProcess.Id -Force -ErrorAction SilentlyContinue
            }
            $tail = Get-StderrTail -Path (Join-Path $RuntimeDir 'highwall.stderr.log')
            throw ("HighWall did not become ready. {0}" -f $tail)
        }

        $tlsEnabled = [bool]$effective.server.tls_enabled
        if (-not $tlsEnabled) {
            $badHostStatus = Get-HttpStatusCode -TargetHost $probeHost -Port $effectiveListenPort -HostHeader 'not-allowed.invalid' -Path '/'
            if ($badHostStatus -ne 403) {
                throw ("Host policy check failed: expected 403, received {0}." -f $badHostStatus)
            }
            $probeHostName = $AllowedHost
            if ($configExists -and -not $PSBoundParameters.ContainsKey('AllowedHost')) {
                $configuredHosts = @($effective.policy.allowed_hosts)
                if ($configuredHosts.Count -gt 0) {
                    $probeHostName = [string]$configuredHosts[0]
                }
            }
            $acceptedStatus = Get-HttpStatusCode -TargetHost $probeHost -Port $effectiveListenPort -HostHeader $probeHostName -Path '/'
            if ($acceptedStatus -eq 403) {
                throw ("Allowed Host '{0}' was rejected with 403." -f $probeHostName)
            }
            if ($WithDemoUpstream -and $acceptedStatus -ne 200) {
                throw ("Demo upstream check failed: expected 200, received {0}." -f $acceptedStatus)
            }
            if ((-not $WithDemoUpstream) -and $acceptedStatus -in @(502, 504)) {
                throw ("Upstream connection check failed: HighWall returned {0}." -f $acceptedStatus)
            }
            if ([bool]$effective.policy.honeypot.enabled) {
                $routes = @($effective.policy.honeypot.routes)
                if ($routes.Count -gt 0) {
                    $route = $routes[0]
                    $honeypotStatus = Get-HttpStatusCode -TargetHost $probeHost -Port $effectiveListenPort -HostHeader $probeHostName -Path ([string]$route.path)
                    if ($honeypotStatus -ne [int]$route.status) {
                        throw ("Honeypot check failed for {0}: expected {1}, received {2}." -f $route.path, [int]$route.status, $honeypotStatus)
                    }
                }
            }
        }

        $auditPath = [string]$effective.audit.path
        if (-not $tlsEnabled) {
            if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
                Start-Sleep -Milliseconds 200
            }
            if (-not (Test-Path -LiteralPath $auditPath -PathType Leaf)) {
                throw ("Audit file was not created after verification requests: {0}" -f $auditPath)
            }
        }

        Write-Output 'HighWall ready.'
        Write-Output ("  config: {0}" -f $ConfigPath)
        Write-Output ("  listen: {0}:{1}" -f $effectiveListenHost, $effectiveListenPort)
        Write-Output ("  upstream: {0}://{1}:{2}" -f $effectiveUpstreamScheme, $effectiveUpstreamHost, $effectiveUpstreamPort)
        Write-Output ("  honeypot: {0}" -f ([bool]$effective.policy.honeypot.enabled))
        Write-Output ("  admin: {0}" -f ([bool]$effective.admin.enabled))
        Write-Output ("  logs: {0}" -f $RuntimeDir)
        if ($WithDemoUpstream) {
            Write-Output '  demo upstream: running'
        }
        Write-Output ("Stop with: powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"{0}`" -RuntimeDir `"{1}`" -Stop" -f $scriptPath, $RuntimeDir)
        exit 0
    }
    catch {
        Stop-RecordedProcess -RecordPath $HighWallRecordPath -Label 'HighWall' | Out-Null
        Stop-RecordedProcess -RecordPath $UpstreamRecordPath -Label 'demo upstream' | Out-Null
        throw
    }
}
catch {
    Write-Output ("error: {0}" -f $_.Exception.Message)
    exit 2
}
