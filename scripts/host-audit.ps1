#Requires -Version 5.1
<#
.SYNOPSIS
Read-only Windows host audit for a HighWall deployment.

.DESCRIPTION
Collects host hardening evidence without changing firewall, portproxy,
services, ACLs, credentials, or HighWall configuration. The script is a
baseline checklist, not a vulnerability scanner and not a fixer.

.PARAMETER Json
Emit a single JSON report instead of a formatted table.

.PARAMETER FailOn
Minimum severity of a FAIL result that produces exit code 1.

.PARAMETER HighWallRoot
HighWall checkout or install directory whose ACL is reviewed.

.PARAMETER ConfigPath
Optional deployed HighWall config file whose ACL is reviewed.

.PARAMETER AuditPath
Optional deployed HighWall audit file or directory whose ACL is reviewed.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\host-audit.ps1

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\host-audit.ps1 -Json

.NOTES
Some checks require elevation. Missing access is reported as WARN rather than
treated as proof that the host is secure. Nothing is remediated automatically.
#>
[CmdletBinding()]
param(
    [switch]$Json,
    [ValidateSet('Low', 'Medium', 'High')]
    [string]$FailOn = 'High',
    [string]$HighWallRoot = '',
    [string]$ConfigPath = '',
    [string]$AuditPath = ''
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

if ([string]::IsNullOrWhiteSpace($HighWallRoot)) {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw 'Cannot determine the script path; pass -HighWallRoot explicitly.'
    }
    $HighWallRoot = Split-Path -Parent (Split-Path -Parent $scriptPath)
}

$checks = New-Object System.Collections.ArrayList

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Info', 'Low', 'Medium', 'High')]
        [string]$Severity,
        [Parameter(Mandatory = $true)][string]$Detail
    )

    [void]$checks.Add(
        [pscustomobject]@{
            name = $Name
            status = $Status
            severity = $Severity
            detail = $Detail
        }
    )
}

function Invoke-AuditCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    try {
        & $Body
    }
    catch {
        Add-Check -Name $Name -Status 'WARN' -Severity 'Medium' -Detail ("Unable to inspect: " + $_.Exception.Message)
    }
}

function Test-LoopbackAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return $false
    }
    $value = $Address.Trim()
    if ($value -eq 'localhost') {
        return $true
    }
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($value, [ref]$parsed)) {
        return [System.Net.IPAddress]::IsLoopback($parsed)
    }
    return $false
}

function Get-BroadAclFindings {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$IncludeRead
    )

    $broadSids = @(
        'S-1-1-0',
        'S-1-5-32-545',
        'S-1-5-11',
        'S-1-5-32-555'
    )
    $writePattern = 'Write|Modify|FullControl|TakeOwnership|ChangePermissions|Delete'
    $readPattern = 'Read|ListDirectory|ReadAndExecute|FullControl'
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $findings = New-Object System.Collections.ArrayList

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        try {
            $sid = $rule.IdentityReference.Translate(
                [System.Security.Principal.SecurityIdentifier]
            ).Value
        }
        catch {
            continue
        }
        if ($broadSids -notcontains $sid) {
            continue
        }
        $rights = [string]$rule.FileSystemRights
        if ($rights -match $writePattern) {
            [void]$findings.Add(("broad write: {0} [{1}]" -f $rule.IdentityReference.Value, $rights))
        }
        elseif ($IncludeRead -and $rights -match $readPattern) {
            [void]$findings.Add(("broad read: {0} [{1}]" -f $rule.IdentityReference.Value, $rights))
        }
    }
    return @($findings)
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Check -Name 'Audit identity' -Status 'INFO' -Severity 'Info' `
    -Detail ("user={0}; elevated={1}; host={2}" -f $identity.Name, $elevated, $env:COMPUTERNAME)
if (-not $elevated) {
    Add-Check -Name 'Elevation' -Status 'WARN' -Severity 'Medium' `
        -Detail 'Run elevated for complete Defender, SMB, and ACL visibility; missing access is not a PASS.'
}

Invoke-AuditCheck -Name 'Operating system' {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    Add-Check -Name 'Operating system' -Status 'INFO' -Severity 'Info' `
        -Detail ("{0} build {1}; last boot {2:o}" -f $os.Caption, $os.BuildNumber, $os.LastBootUpTime)
}

Invoke-AuditCheck -Name 'Firewall profiles' {
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -eq 0) {
        Add-Check -Name 'Firewall profiles' -Status 'WARN' -Severity 'High' `
            -Detail 'No active Windows Firewall profiles were returned.'
        return
    }
    foreach ($profile in $profiles) {
        $name = "Firewall profile: $($profile.Name)"
        if (-not [bool]$profile.Enabled) {
            Add-Check -Name $name -Status 'FAIL' -Severity 'High' `
                -Detail 'Profile is disabled.'
            continue
        }
        if ([string]$profile.DefaultInboundAction -ne 'Block') {
            Add-Check -Name $name -Status 'WARN' -Severity 'High' `
                -Detail ("Enabled, but DefaultInboundAction={0}." -f $profile.DefaultInboundAction)
        }
        else {
            Add-Check -Name $name -Status 'PASS' -Severity 'Info' `
                -Detail 'Enabled with default inbound Block.'
        }
    }
}

Invoke-AuditCheck -Name 'Active network profiles' {
    $networks = @(Get-NetConnectionProfile -ErrorAction Stop)
    if ($networks.Count -eq 0) {
        Add-Check -Name 'Active network profiles' -Status 'INFO' -Severity 'Info' `
            -Detail 'No active network profile returned.'
        return
    }
    foreach ($network in $networks) {
        Add-Check -Name "Network profile: $($network.InterfaceAlias)" -Status 'INFO' -Severity 'Info' `
            -Detail ("Category={0}; IPv4={1}" -f $network.NetworkCategory, ($network.IPv4Connectivity))
    }
}

Invoke-AuditCheck -Name 'Sensitive TCP listeners' {
    $sensitivePorts = @{
        135 = 'RPC endpoint mapper'
        139 = 'NetBIOS session'
        445 = 'SMB'
        3389 = 'Remote Desktop'
        5985 = 'WinRM HTTP'
        5986 = 'WinRM HTTPS'
    }
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
    $seen = @{}
    foreach ($listener in $listeners) {
        $port = [int]$listener.LocalPort
        if (-not $sensitivePorts.ContainsKey($port)) {
            continue
        }
        if (Test-LoopbackAddress ([string]$listener.LocalAddress)) {
            continue
        }
        $key = "{0}:{1}" -f $listener.LocalAddress, $port
        if ($seen.ContainsKey($key)) {
            continue
        }
        $seen[$key] = $true
        Add-Check -Name ("Listener: {0}" -f $sensitivePorts[$port]) -Status 'WARN' -Severity 'High' `
            -Detail ("Listening on {0}; confirm host firewall scope and that the service is required." -f $key)
    }
    if ($seen.Count -eq 0) {
        Add-Check -Name 'Sensitive TCP listeners' -Status 'PASS' -Severity 'Info' `
            -Detail 'No matching high-risk service is listening on a non-loopback address.'
    }
}

Invoke-AuditCheck -Name 'Sensitive UDP listeners' {
    $sensitivePorts = @{
        137 = 'NetBIOS name'
        138 = 'NetBIOS datagram'
    }
    $endpoints = @(Get-NetUDPEndpoint -ErrorAction Stop)
    $seen = @{}
    foreach ($endpoint in $endpoints) {
        $port = [int]$endpoint.LocalPort
        if (-not $sensitivePorts.ContainsKey($port)) {
            continue
        }
        if (Test-LoopbackAddress ([string]$endpoint.LocalAddress)) {
            continue
        }
        $key = "{0}:{1}" -f $endpoint.LocalAddress, $port
        if ($seen.ContainsKey($key)) {
            continue
        }
        $seen[$key] = $true
        Add-Check -Name ("UDP listener: {0}" -f $sensitivePorts[$port]) -Status 'WARN' -Severity 'High' `
            -Detail ("Listening on {0}; NetBIOS should normally be disabled." -f $key)
    }
    if ($seen.Count -eq 0) {
        Add-Check -Name 'Sensitive UDP listeners' -Status 'PASS' -Severity 'Info' `
            -Detail 'No matching high-risk UDP endpoint is listening on a non-loopback address.'
    }
}

Invoke-AuditCheck -Name 'Port proxy table' {
    $found = 0
    foreach ($protocol in @('tcp', 'udp')) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\$protocol"
        if (-not (Test-Path -LiteralPath $key)) {
            continue
        }
        $entry = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        foreach ($property in $entry.PSObject.Properties) {
            if ($property.Name -like 'PS*') {
                continue
            }
            $found++
            $local = [string]$property.Name
            $remote = [string]$property.Value
            if ($local -match '^(0\.0\.0\.0|\*|\[::\])') {
                Add-Check -Name 'Port proxy exposure' -Status 'FAIL' -Severity 'High' `
                    -Detail ("{0} {1} -> {2} listens on a wildcard address." -f $protocol, $local, $remote)
            }
            elseif ($local -match '^127\.') {
                Add-Check -Name 'Port proxy exposure' -Status 'WARN' -Severity 'Medium' `
                    -Detail ("{0} {1} -> {2} is loopback-only; verify ownership." -f $protocol, $local, $remote)
            }
            else {
                Add-Check -Name 'Port proxy exposure' -Status 'WARN' -Severity 'High' `
                    -Detail ("{0} {1} -> {2} listens on a non-loopback address." -f $protocol, $local, $remote)
            }
        }
    }
    if ($found -eq 0) {
        Add-Check -Name 'Port proxy table' -Status 'PASS' -Severity 'Info' `
            -Detail 'No v4tov4 portproxy entry found.'
    }
}

Invoke-AuditCheck -Name 'Remote Desktop' {
    $terminalServer = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name 'fDenyTSConnections' -ErrorAction Stop
    if ([int]$terminalServer.fDenyTSConnections -eq 0) {
        Add-Check -Name 'Remote Desktop' -Status 'WARN' -Severity 'High' `
            -Detail 'RDP is enabled; confirm firewall scope, MFA, and account lockout.'
    }
    else {
        Add-Check -Name 'Remote Desktop' -Status 'PASS' -Severity 'Info' `
            -Detail 'RDP is disabled by TermService policy.'
    }
}

Invoke-AuditCheck -Name 'SMB server' {
    $smb = Get-SmbServerConfiguration -ErrorAction Stop
    if ([bool]$smb.EnableSMB1Protocol) {
        Add-Check -Name 'SMBv1' -Status 'FAIL' -Severity 'High' `
            -Detail 'SMBv1 is enabled.'
    }
    else {
        Add-Check -Name 'SMBv1' -Status 'PASS' -Severity 'Info' `
            -Detail 'SMBv1 is disabled.'
    }
    if (-not [bool]$smb.EnableSecuritySignature) {
        Add-Check -Name 'SMB signing' -Status 'WARN' -Severity 'Medium' `
            -Detail 'SMB security signature is disabled.'
    }
    else {
        Add-Check -Name 'SMB signing' -Status 'PASS' -Severity 'Info' `
            -Detail 'SMB security signature is enabled.'
    }
}

Invoke-AuditCheck -Name 'WinRM' {
    $service = Get-Service -Name 'WinRM' -ErrorAction Stop
    if ($service.Status -eq 'Running') {
        Add-Check -Name 'WinRM' -Status 'WARN' -Severity 'High' `
            -Detail 'WinRM service is running; confirm scope, HTTPS, and authorization.'
    }
    else {
        Add-Check -Name 'WinRM' -Status 'PASS' -Severity 'Info' `
            -Detail ("WinRM service state is {0}." -f $service.Status)
    }
}

Invoke-AuditCheck -Name 'Microsoft Defender' {
    $status = Get-MpComputerStatus -ErrorAction Stop
    if (-not [bool]$status.AntivirusEnabled) {
        Add-Check -Name 'Defender antivirus' -Status 'WARN' -Severity 'High' `
            -Detail 'Microsoft Defender antivirus is disabled; verify a supported third-party AV/EDR.'
    }
    else {
        Add-Check -Name 'Defender antivirus' -Status 'PASS' -Severity 'Info' `
            -Detail 'Microsoft Defender antivirus is enabled.'
    }
    if (-not [bool]$status.RealTimeProtectionEnabled) {
        Add-Check -Name 'Defender real-time protection' -Status 'WARN' -Severity 'High' `
            -Detail 'Real-time protection is disabled; verify a supported third-party AV/EDR.'
    }
    else {
        Add-Check -Name 'Defender real-time protection' -Status 'PASS' -Severity 'Info' `
            -Detail 'Real-time protection is enabled.'
    }
    if ($status.PSObject.Properties.Match('IsTamperProtected').Count -gt 0 -and -not [bool]$status.IsTamperProtected) {
        Add-Check -Name 'Defender tamper protection' -Status 'WARN' -Severity 'High' `
            -Detail 'Tamper protection is disabled.'
    }
}

Invoke-AuditCheck -Name 'Attack surface reduction' {
    $preference = Get-MpPreference -ErrorAction Stop
    $ids = @($preference.AttackSurfaceReductionRules_Ids)
    $actions = @($preference.AttackSurfaceReductionRules_Actions)
    if ($ids.Count -eq 0) {
        Add-Check -Name 'ASR rules' -Status 'WARN' -Severity 'Medium' `
            -Detail 'No Attack Surface Reduction rule is configured.'
    }
    else {
        $blocking = 0
        foreach ($action in $actions) {
            if ([int]$action -eq 1) {
                $blocking++
            }
        }
        if ($blocking -eq 0) {
            Add-Check -Name 'ASR rules' -Status 'WARN' -Severity 'Medium' `
                -Detail ("{0} ASR rule(s) configured, none in Block mode." -f $ids.Count)
        }
        else {
            Add-Check -Name 'ASR rules' -Status 'PASS' -Severity 'Info' `
                -Detail ("{0} of {1} ASR rule(s) are in Block mode." -f $blocking, $ids.Count)
        }
    }
    if ($preference.PSObject.Properties.Match('EnableControlledFolderAccess').Count -gt 0) {
        $cfa = [int]$preference.EnableControlledFolderAccess
        if ($cfa -eq 1) {
            Add-Check -Name 'Controlled Folder Access' -Status 'PASS' -Severity 'Info' `
                -Detail 'Controlled Folder Access is enabled.'
        }
        elseif ($cfa -eq 2) {
            Add-Check -Name 'Controlled Folder Access' -Status 'WARN' -Severity 'Medium' `
                -Detail 'Controlled Folder Access is in audit-only mode.'
        }
        else {
            Add-Check -Name 'Controlled Folder Access' -Status 'WARN' -Severity 'Medium' `
                -Detail 'Controlled Folder Access is disabled.'
        }
    }
}

Invoke-AuditCheck -Name 'Backup and recovery' {
    $shadowQueryFailed = $false
    try {
        $shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop)
    }
    catch {
        $shadowQueryFailed = $true
        Add-Check -Name 'Volume shadow copies' -Status 'WARN' -Severity 'High' `
            -Detail ("Shadow copy enumeration failed: {0}; verify an off-host, immutable backup manually." -f $_.Exception.Message)
    }
    if (-not $shadowQueryFailed) {
        if ($shadows.Count -eq 0) {
            Add-Check -Name 'Volume shadow copies' -Status 'WARN' -Severity 'High' `
                -Detail 'No volume shadow copy found; verify an off-host, immutable backup and restore test.'
        }
        else {
            Add-Check -Name 'Volume shadow copies' -Status 'PASS' -Severity 'Info' `
                -Detail ("{0} shadow copy object(s) found; off-host restore must still be tested." -f $shadows.Count)
        }
    }
    if (Get-Command -Name Get-WBSummary -ErrorAction SilentlyContinue) {
        try {
            $summary = Get-WBSummary -ErrorAction Stop
            Add-Check -Name 'Windows Server Backup' -Status 'INFO' -Severity 'Info' `
                -Detail ("Last backup: {0}; result HRESULT: {1}" -f $summary.LastSuccessfulBackupTime, $summary.LastBackupResultHRESULT)
        }
        catch {
            Add-Check -Name 'Windows Server Backup' -Status 'WARN' -Severity 'Medium' `
                -Detail ("Unable to read Windows Server Backup summary: {0}" -f $_.Exception.Message)
        }
    }
}

Invoke-AuditCheck -Name 'WSL host boundary' {
    $service = @(Get-Service -Name 'LxssManager', 'WSLService' -ErrorAction SilentlyContinue)
    if ($service.Count -eq 0) {
        Add-Check -Name 'WSL service' -Status 'INFO' -Severity 'Info' `
            -Detail 'No LxssManager or WSLService was found.'
    }
    else {
        foreach ($item in $service) {
            Add-Check -Name 'WSL service' -Status 'INFO' -Severity 'Info' `
                -Detail ("{0} state: {1}" -f $item.Name, $item.Status)
        }
    }
    $wslAddresses = @(
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.InterfaceAlias -match 'WSL' }
    )
    if ($wslAddresses.Count -eq 0) {
        Add-Check -Name 'WSL host addresses' -Status 'INFO' -Severity 'Info' `
            -Detail 'No active WSL IPv4 adapter found.'
    }
    else {
        foreach ($address in $wslAddresses) {
            Add-Check -Name 'WSL host addresses' -Status 'INFO' -Severity 'Info' `
                -Detail ("{0} on {1}; host-firewall scope must cover every host address, not only this adapter." -f $address.IPAddress, $address.InterfaceAlias)
        }
    }
    Add-Check -Name 'WSL netns boundary' -Status 'INFO' -Severity 'Info' `
        -Detail 'Windows firewall cannot inspect a WSL-internal loopback/netns; isolate the agent netns and credentials separately.'
}

Invoke-AuditCheck -Name 'HighWall code ACL' {
    if (-not (Test-Path -LiteralPath $HighWallRoot)) {
        Add-Check -Name 'HighWall code ACL' -Status 'WARN' -Severity 'High' `
            -Detail ("HighWall root does not exist: {0}" -f $HighWallRoot)
        return
    }
    $findings = @(Get-BroadAclFindings -Path $HighWallRoot)
    if ($findings.Count -eq 0) {
        Add-Check -Name 'HighWall code ACL' -Status 'PASS' -Severity 'Info' `
            -Detail ("No broad write ACE found on {0}." -f $HighWallRoot)
    }
    else {
        foreach ($finding in $findings) {
            Add-Check -Name 'HighWall code ACL' -Status 'WARN' -Severity 'High' `
                -Detail ("{0} on {1}; acceptable only for a development checkout, not a production install." -f $finding, $HighWallRoot)
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    Invoke-AuditCheck -Name 'HighWall config ACL' {
        if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
            Add-Check -Name 'HighWall config ACL' -Status 'WARN' -Severity 'High' `
                -Detail ("Config file does not exist: {0}" -f $ConfigPath)
            return
        }
        $findings = @(Get-BroadAclFindings -Path $ConfigPath)
        if ($findings.Count -eq 0) {
            Add-Check -Name 'HighWall config ACL' -Status 'PASS' -Severity 'Info' `
                -Detail ("No broad write ACE found on {0}." -f $ConfigPath)
        }
        else {
            foreach ($finding in $findings) {
                Add-Check -Name 'HighWall config ACL' -Status 'FAIL' -Severity 'High' `
                    -Detail ("{0} on {1}." -f $finding, $ConfigPath)
            }
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($AuditPath)) {
    Invoke-AuditCheck -Name 'HighWall audit ACL' {
        if (-not (Test-Path -LiteralPath $AuditPath)) {
            Add-Check -Name 'HighWall audit ACL' -Status 'WARN' -Severity 'Medium' `
                -Detail ("Audit path does not exist yet: {0}" -f $AuditPath)
            return
        }
        $findings = @(Get-BroadAclFindings -Path $AuditPath -IncludeRead)
        if ($findings.Count -eq 0) {
            Add-Check -Name 'HighWall audit ACL' -Status 'PASS' -Severity 'Info' `
                -Detail ("No broad read/write ACE found on {0}." -f $AuditPath)
        }
        else {
            foreach ($finding in $findings) {
                $status = 'WARN'
                $severity = 'Medium'
                if ($finding -match '^broad write:') {
                    $status = 'FAIL'
                    $severity = 'High'
                }
                Add-Check -Name 'HighWall audit ACL' -Status $status -Severity $severity `
                    -Detail ("{0} on {1}." -f $finding, $AuditPath)
            }
        }
    }
}

$counts = [ordered]@{ PASS = 0; WARN = 0; FAIL = 0; INFO = 0 }
foreach ($check in $checks) {
    $counts[$check.status] = [int]$counts[$check.status] + 1
}
$severityRank = @{ Info = 0; Low = 1; Medium = 2; High = 3 }
$threshold = [int]$severityRank[$FailOn]
$severeFailures = @(
    $checks | Where-Object {
        $_.status -eq 'FAIL' -and [int]$severityRank[$_.severity] -ge $threshold
    }
)
$exitCode = 0
if ($severeFailures.Count -gt 0) {
    $exitCode = 1
}

$report = [pscustomobject]@{
    schemaVersion = 1
    generatedAt = [DateTimeOffset]::Now.ToString('o')
    host = $env:COMPUTERNAME
    user = $identity.Name
    elevated = $elevated
    failOn = $FailOn
    exitCode = $exitCode
    summary = [pscustomobject]$counts
    checks = @($checks)
    limitations = @(
        'Read-only baseline; no remediation was performed.',
        'WSL-internal loopback, netns, DSH credentials, and host memory are outside this script.',
        'A PASS is not proof of compromise absence; correlate with EDR, firewall, backup, and application logs.'
    )
}

if ($Json) {
    Write-Output ($report | ConvertTo-Json -Depth 8)
    exit $exitCode
}

$statusOrder = @{ FAIL = 0; WARN = 1; PASS = 2; INFO = 3 }
$sorted = @(
    $checks | Sort-Object `
        @{ Expression = { $statusOrder[$_.status] } }, `
        @{ Expression = { $_.name } }
)
Write-Output ("HighWall host audit | host={0} | elevated={1} | FAIL={2} WARN={3} PASS={4} INFO={5}" -f `
    $env:COMPUTERNAME, $elevated, $counts.FAIL, $counts.WARN, $counts.PASS, $counts.INFO)
Write-Output ($sorted | Format-Table -AutoSize | Out-String -Width 240).TrimEnd()
Write-Output 'Read-only audit only. Missing access is a WARN, not a PASS.'
exit $exitCode
