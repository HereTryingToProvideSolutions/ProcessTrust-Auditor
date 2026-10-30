# ProcessTrust Auditor v1.3 - read-only process and TCP evidence
# PowerShell 5.1+; run elevated for best process visibility.

$ErrorActionPreference = 'Continue'
$startedAt = (Get-Date).ToString('o')
$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
$tcp = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
$processes = @(Get-Process)
$dir = Join-Path $env:USERPROFILE 'ProcessTrust'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$processFile = Join-Path $dir "ProcessTrust_v1_3_Processes_$stamp.csv"
$networkFile = Join-Path $dir "ProcessTrust_v1_3_Connections_$stamp.csv"
$rdapCache = @{}
$ptrCache = @{}

function Get-ServiceExecutable([string]$command) {
    if ([string]::IsNullOrWhiteSpace($command)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($command)
    if ($expanded -match '^\s*"([^"]+?\.exe)"') { return $matches[1] }
    if ($expanded -match '^\s*(.+?\.exe)(?:\s|$)') { return $matches[1] }
    return $null
}
function Test-PublicIPv4([string]$address) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $parsed.GetAddressBytes()
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 2) { return $false }
    if ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) { return $false }
    if ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113) { return $false }
    if ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19)) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 0) { return $false }
    return $true
}
function Get-IPContext([string]$ip) {
    if (-not (Test-PublicIPv4 $ip)) {
        return @{ PTR = ''; Owner = ''; Lookup = 'NotPublicIPv4OrUnsupported' }
    }
    if (-not $ptrCache.ContainsKey($ip)) {
        $ptr = ''
        try {
            $r = Resolve-DnsName -Name $ip -Type PTR -DnsOnly -ErrorAction Stop
            $ptr = (@($r | Where-Object { $_.Type -eq 'PTR' } | Select-Object -ExpandProperty NameHost) -join '; ')
        } catch { }
        $ptrCache[$ip] = $ptr
    }
    if (-not $rdapCache.ContainsKey($ip)) {
        $owner = ''
        $status = 'Unavailable'
        try {
            # RDAP bootstrap redirects to the appropriate regional registry.
            $r = Invoke-RestMethod -Uri "https://rdap.org/ip/$ip" -TimeoutSec 5 -ErrorAction Stop
            $owner = [string]$r.name
            if ([string]::IsNullOrWhiteSpace($owner)) { $status = 'NoOwnerName' }
            else { $status = 'RDAPNameOnly' }
        } catch { $status = 'LookupFailed' }
        $rdapCache[$ip] = @{ Owner = $owner; Lookup = $status }
    }
    return @{ PTR = $ptrCache[$ip]; Owner = $rdapCache[$ip].Owner; Lookup = $rdapCache[$ip].Lookup }
}

$processRows = @(
    foreach ($p in $processes) {
        $matching = @($services | Where-Object { $_.ProcessId -eq $p.Id -and $_.ProcessId -ne 0 })
        $serviceNames = (@($matching | Select-Object -ExpandProperty Name) -join '; ')
        $path = $null
        $sig = 'NotChecked'
        $reason = 'Running path unavailable'
        try {
            $path = $p.Path
            if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
                $sig = (Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop).Status.ToString()
                $reason = 'Running executable signature checked'
            }
        } catch { $reason = 'Running executable inspection failed' }
        $svcPath = ''
        $svcSig = 'NotChecked'
        if ($sig -eq 'NotChecked') {
            foreach ($s in $matching) {
                $candidate = Get-ServiceExecutable $s.PathName
                if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                    $svcPath = $candidate
                    try { $svcSig = (Get-AuthenticodeSignature -LiteralPath $candidate -ErrorAction Stop).Status.ToString() }
                    catch { $svcSig = 'CheckFailed' }
                    break
                }
            }
        }
        $matchesTCP = @($tcp | Where-Object { $_.OwningProcess -eq $p.Id })
        $score = 0
        $flags = @()
        if ($sig -in @('HashMismatch','NotTrusted','UnknownError')) { $score += 50; $flags += 'SignatureProblem' }
        if ($sig -eq 'NotSigned') { $score += 10; $flags += 'UnsignedExecutable' }
        if ($path -and $path -match '(?i)\\(temp|downloads|appdata\\local\\temp)\\') { $score += 20; $flags += 'UserWritableOrDownloadLocation' }
        if ($matchesTCP.Count -gt 0 -and ($sig -eq 'NotSigned' -or $sig -in @('HashMismatch','NotTrusted','UnknownError'))) {
            $score += 15; $flags += 'NetworkActivityWithSignatureConcern'
        }
        $priority = if ($score -ge 50) { 'HighReview' } elseif ($score -ge 20) { 'Review' } elseif ($score -gt 0) { 'Informational' } else { 'NoFlags' }
        [PSCustomObject]@{
            SnapshotTime = $startedAt; ProcessName = $p.ProcessName; PID = $p.Id
            RunningPath = $path; RunningSignature = $sig; Services = $serviceNames
            ServicePath = $svcPath; ServiceSignature = $svcSig
            EstablishedTCP = $matchesTCP.Count; RiskScore = $score
            ReviewPriority = $priority; RiskIndicators = ($flags -join '; '); Reason = $reason
        }
    }
)

# One row per observed established connection; preserve unknowns rather than guessing domains or URLs.
$networkRows = @(
    foreach ($conn in $tcp) {
        $pRow = $processRows | Where-Object { $_.PID -eq $conn.OwningProcess } | Select-Object -First 1
        $ctx = Get-IPContext ([string]$conn.RemoteAddress)
        [PSCustomObject]@{
            SnapshotTime = $startedAt; PID = $conn.OwningProcess
            ProcessName = if ($pRow) { $pRow.ProcessName } else { 'UnknownOrExited' }
            RunningPath = if ($pRow) { $pRow.RunningPath } else { '' }
            RunningSignature = if ($pRow) { $pRow.RunningSignature } else { 'NotChecked' }
            LocalAddress = $conn.LocalAddress; LocalPort = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress; RemotePort = $conn.RemotePort
            State = $conn.State; ReverseDNS = $ctx.PTR
            RDAPNetworkName = $ctx.Owner; EnrichmentStatus = $ctx.Lookup
            RequestedDomain = 'Unknown'; RequestedURL = 'Unknown'; RequestedContent = 'Unknown'
            ReviewPriority = if ($pRow) { $pRow.ReviewPriority } else { 'Unassessed' }
        }
    }
)
$processRows | Export-Csv -LiteralPath $processFile -NoTypeInformation -Encoding UTF8
$networkRows | Export-Csv -LiteralPath $networkFile -NoTypeInformation -Encoding UTF8
Write-Host "`n=== ProcessTrust v1.3 ===" -ForegroundColor Cyan
Write-Host "Processes: $($processRows.Count) | Established TCP connections: $($tcp.Count)"
$processRows | Group-Object ReviewPriority | Select-Object Name,Count | Format-Table -AutoSize
Write-Host "Process report: $processFile" -ForegroundColor Green
Write-Host "Connection report: $networkFile" -ForegroundColor Green
Write-Host 'RDAP network names and reverse DNS are context, not proof of the requested domain or safety.'
