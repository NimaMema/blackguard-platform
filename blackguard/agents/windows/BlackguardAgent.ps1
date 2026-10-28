<#
.SYNOPSIS
  BLACKGUARD Windows Security collector (read-only). PowerShell 5.1+.

.DESCRIPTION
  Enroll once with a one-time code from the dashboard, then run continuously
  (or install as a startup scheduled task). Reads selected Security/System
  event IDs, buffers them durably on disk, and delivers them to the BLACKGUARD
  server with a per-agent credential. Never changes Windows security settings,
  firewall rules or accounts.

  State: %ProgramData%\BLACKGUARD\agent (ACL: Administrators + SYSTEM only)
  Credential: encrypted with DPAPI (LocalMachine scope).

.EXAMPLE
  .\BlackguardAgent.ps1 -Enroll -Server https://192.168.1.50:8443 -Code ABCD-EFGH-JKLM-NPQR -CertThumbprint 3F...A1
  .\BlackguardAgent.ps1 -Run
  .\BlackguardAgent.ps1 -Install      # scheduled task at startup, runs as SYSTEM
  .\BlackguardAgent.ps1 -Status
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Enroll', Mandatory)] [switch]$Enroll,
    [Parameter(ParameterSetName = 'Enroll', Mandatory)] [string]$Server,
    [Parameter(ParameterSetName = 'Enroll', Mandatory)] [string]$Code,
    [Parameter(ParameterSetName = 'Enroll')] [string]$CertThumbprint = '',
    [Parameter(ParameterSetName = 'Run')] [switch]$Run,
    [Parameter(ParameterSetName = 'Run')] [switch]$FromStart,
    [Parameter(ParameterSetName = 'Run')] [switch]$Once,
    [Parameter(ParameterSetName = 'Run')] [ValidateRange(5, 300)] [int]$IntervalSeconds = 10,
    [Parameter(ParameterSetName = 'Run')] [ValidateRange(1000, 1000000)] [int]$SpoolMaxEvents = 100000,
    [Parameter(ParameterSetName = 'Install', Mandatory)] [switch]$Install,
    [Parameter(ParameterSetName = 'Uninstall', Mandatory)] [switch]$Uninstall,
    [Parameter(ParameterSetName = 'Status', Mandatory)] [switch]$Status,
    [string]$StateDir = (Join-Path $env:ProgramData 'BLACKGUARD\agent')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$AgentVersion = '0.5.0'
Add-Type -AssemblyName System.Security

# ------------------------------------------------------------------ helpers
function Write-Log([string]$Level, [string]$Message) {
    $line = '{0} {1} {2}' -f (Get-Date).ToUniversalTime().ToString('s'), $Level, $Message
    Write-Host $line
    try { Add-Content -Path (Join-Path $StateDir 'agent.log') -Value $line -Encoding UTF8 } catch { }
}

function Initialize-StateDir {
    if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    foreach ($sub in 'spool', 'tmp') { $p = Join-Path $StateDir $sub; if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null } }
    # Restrict to Administrators and SYSTEM; remove inherited access.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $StateDir -AclObject $acl
}

function Write-Atomic([string]$Path, [string]$Content) {
    $tmp = Join-Path (Join-Path $StateDir 'tmp') ([guid]::NewGuid().ToString() + '.tmp')
    [System.IO.File]::WriteAllText($tmp, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $Path -Force
}

function Protect-Secret([string]$Plain) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, [System.Text.Encoding]::UTF8.GetBytes('blackguard-agent'), 'LocalMachine')
    return [Convert]::ToBase64String($enc)
}

function Unprotect-Secret([string]$Cipher) {
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Cipher), [System.Text.Encoding]::UTF8.GetBytes('blackguard-agent'), 'LocalMachine')
    return [System.Text.Encoding]::UTF8.GetString($bytes)
}

function Get-Fingerprint {
    $guid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("blackguard-agent-v1:$guid"))
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Format-Fingerprint([string]$Fp) { return (($Fp.Substring(0, 32) -split '(.{4})' | Where-Object { $_ }) -join ' ') }

function Test-ServerUrl([string]$Url) {
    $uri = [Uri]$Url
    if ($uri.Scheme -eq 'https') { return $Url.TrimEnd('/') }
    if ($uri.Scheme -eq 'http' -and @('127.0.0.1', 'localhost', '::1', '[::1]') -contains $uri.Host) { return $Url.TrimEnd('/') }
    throw 'Use https:// for a remote BLACKGUARD server (http:// only for localhost).'
}

function Set-TlsPolicy([string]$Thumbprint) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    if ($Thumbprint) {
        # Pin the server's self-signed certificate by SHA-1 thumbprint (Windows PowerShell 5.1).
        $script:PinnedThumbprint = $Thumbprint.Replace(' ', '').ToUpperInvariant()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($sender, $certificate, $chain, $errors)
            return ($certificate.GetCertHashString().ToUpperInvariant() -eq $script:PinnedThumbprint)
        }
    }
}

$script:Config = $null
$script:Credential = ''

function Invoke-Api([string]$Method, [string]$Route, $Body, [switch]$NoAuth) {
    $headers = @{ 'User-Agent' = 'blackguard-agent-windows' }
    if (-not $NoAuth) { $headers['Authorization'] = "Bearer $script:Credential" }
    $params = @{ Uri = "$($script:Config.server)$Route"; Method = $Method; Headers = $headers; TimeoutSec = 30; UseBasicParsing = $true }
    if ($null -ne $Body) { $params['Body'] = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Body -Depth 8 -Compress)); $params['ContentType'] = 'application/json' }
    try {
        $response = Invoke-WebRequest @params
        if ($response.Content) { return ($response.Content | ConvertFrom-Json) }
        return $null
    } catch [System.Net.WebException] {
        $status = 0
        $message = $_.Exception.Message
        if ($_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $message = ($reader.ReadToEnd() | ConvertFrom-Json).error
            } catch { }
        }
        $err = New-Object System.Exception("HTTP $status`: $message")
        $err.Data['status'] = $status
        throw $err
    }
}

function Get-Status($ex) { if ($ex.Exception.Data.Contains('status')) { return [int]$ex.Exception.Data['status'] }; return 0 }

# ------------------------------------------------------------------ event mapping
$SecurityIds = @(4624, 4625, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 4740, 4719, 4739, 1102, 4697)
$SystemIds = @(104, 7045)
$IgnoredAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', '-', '')

function Get-Data($xml, [string]$Name) {
    $node = $xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
    if ($null -eq $node) { return '' }
    return [string]$node.'#text'
}

function Get-CleanIp([string]$Ip) {
    if (-not $Ip -or $Ip -eq '-' -or $Ip -eq '::1' -or $Ip -eq '127.0.0.1') { return '' }
    $Ip = $Ip -replace '^::ffff:', ''
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) { return $parsed.ToString() }
    return ''
}

function ConvertTo-BgEvent($Record, [string]$Log) {
    [xml]$xml = $Record.ToXml()
    $id = [int]$Record.Id
    $subject = Get-Data $xml 'SubjectUserName'
    $target = Get-Data $xml 'TargetUserName'
    $ip = Get-CleanIp (Get-Data $xml 'IpAddress')
    $details = @{ windows_event_id = $id; log = $Log; time_source = 'log' }
    $kind = $null; $actor = 'unknown'; $tgt = ''; $msg = ''
    switch ($id) {
        4624 {
            $logonType = Get-Data $xml 'LogonType'
            if ($logonType -in @('0', '5') -or $target.EndsWith('$') -or $IgnoredAccounts -contains $target -or $target -like 'DWM-*' -or $target -like 'UMFD-*') { return $null }
            $kind = 'auth_success'; $actor = $target; $details['logon_type'] = $logonType
            $msg = "Windows 4624: sign-in by $target (logon type $logonType)"
        }
        4625 {
            $kind = 'auth_failure'; $actor = $target; $details['logon_type'] = Get-Data $xml 'LogonType'; $details['status'] = Get-Data $xml 'SubStatus'
            $msg = "Windows 4625: failed sign-in for $target"
        }
        4720 { $kind = 'account_created'; $actor = $subject; $tgt = $target; $msg = "Windows 4720: account $target created by $subject" }
        4722 { $kind = 'account_enabled'; $actor = $subject; $tgt = $target; $msg = "Windows 4722: account $target enabled by $subject" }
        4725 { $kind = 'account_disabled'; $actor = $subject; $tgt = $target; $msg = "Windows 4725: account $target disabled by $subject" }
        4726 { $kind = 'account_deleted'; $actor = $subject; $tgt = $target; $msg = "Windows 4726: account $target deleted by $subject" }
        4724 { $kind = 'password_reset'; $actor = $subject; $tgt = $target; $msg = "Windows 4724: password reset for $target by $subject" }
        { $_ -in 4728, 4732, 4756 } {
            $member = Get-Data $xml 'MemberName'; if (-not $member) { $member = Get-Data $xml 'MemberSid' }
            $kind = 'group_membership_change'; $actor = $subject; $tgt = $member; $details['group'] = $target
            $msg = "Windows ${id}: $member added to group $target by $subject"
        }
        4740 { $kind = 'account_locked'; $tgt = $target; $actor = $target; $msg = "Windows 4740: account $target locked out" }
        4719 { $kind = 'policy_change'; $actor = $subject; $msg = "Windows 4719: system audit policy changed by $subject" }
        4739 { $kind = 'policy_change'; $actor = $subject; $msg = "Windows 4739: domain policy changed by $subject" }
        1102 {
            $who = [string]$xml.Event.UserData.LogFileCleared.SubjectUserName
            $kind = 'audit_log_cleared'; $actor = $who; $msg = "Windows 1102: Security log cleared by $who"
        }
        104 { $kind = 'audit_log_cleared'; $msg = 'Windows 104: an event log was cleared (System log)' }
        { $_ -in 4697, 7045 } {
            $svc = Get-Data $xml 'ServiceName'; $img = Get-Data $xml 'ServiceFileName'; if (-not $img) { $img = Get-Data $xml 'ImagePath' }
            $kind = 'service_installed'; $actor = $subject; $tgt = $svc; $details['image_path'] = $img
            $msg = "Windows ${id}: service '$svc' installed ($img)"
        }
    }
    if (-not $kind) { return $null }
    if (-not $actor) { $actor = 'unknown' }
    return @{
        uid = "win:${Log}:$($Record.RecordId)"; type = $kind; host = $env:COMPUTERNAME; source_ip = $ip; actor = $actor; target = $tgt
        message = $msg; timestamp = $Record.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); details = $details
    }
}

# ------------------------------------------------------------------ spool + cursors
function Get-Cursor([string]$Log) {
    $path = Join-Path $StateDir "cursor-$Log.json"
    if (Test-Path $path) { return [long]((Get-Content $path -Raw | ConvertFrom-Json).record_id) }
    return $null
}
function Set-Cursor([string]$Log, [long]$RecordId) { Write-Atomic (Join-Path $StateDir "cursor-$Log.json") (ConvertTo-Json @{ record_id = $RecordId }) }

$script:Seq = 0
function Get-SpoolCount($File) {
    # New batch files carry their event count in the name (…-n123.json); older ones are read once.
    if ($File.Name -match '-n(\d+)\.json$') { return [int]$Matches[1] }
    return @(Get-Content $File.FullName -Raw | ConvertFrom-Json).Count
}

function Get-SpoolDepth {
    $total = 0
    foreach ($f in @(Get-ChildItem (Join-Path $StateDir 'spool') -Filter *.json)) { $total += Get-SpoolCount $f }
    return $total
}

function Add-Spool($Events) {
    if ($Events.Count -eq 0) { return }
    $script:Seq++
    $name = '{0:D20}-{1:D6}-n{2}.json' -f [DateTime]::UtcNow.Ticks, $script:Seq, $Events.Count
    Write-Atomic (Join-Path (Join-Path $StateDir 'spool') $name) (ConvertTo-Json -InputObject @($Events) -Depth 6 -Compress)
    # Bound disk use: drop the oldest batches beyond the limit and report them as data loss.
    $files = @(Get-ChildItem (Join-Path $StateDir 'spool') -Filter *.json | Sort-Object Name)
    $depth = 0
    foreach ($f in $files) { $depth += Get-SpoolCount $f }
    while ($depth -gt $SpoolMaxEvents -and $files.Count -gt 1) {
        $dropped = Get-SpoolCount $files[0]
        Remove-Item $files[0].FullName -Force
        $script:Meta.dropped_total += $dropped
        Save-Meta
        $depth -= $dropped
        $files = $files[1..($files.Count - 1)]
    }
}

function Save-Meta { Write-Atomic (Join-Path $StateDir 'meta.json') (ConvertTo-Json $script:Meta) }

function Read-Log([string]$Log, [int[]]$Ids) {
    $cursor = Get-Cursor $Log
    if ($null -eq $cursor) {
        if ($FromStart) { $cursor = 0 } else {
            $latest = Get-WinEvent -LogName $Log -MaxEvents 1 -ErrorAction SilentlyContinue
            $cursor = if ($latest) { [long]$latest.RecordId } else { 0 }
            Set-Cursor $Log $cursor
            return 0
        }
    }
    $total = 0
    $idFilter = ($Ids | ForEach-Object { "EventID=$_" }) -join ' or '
    do {
        $xpath = "*[System[($idFilter) and EventRecordID > $cursor]]"
        $records = @(Get-WinEvent -LogName $Log -FilterXPath $xpath -Oldest -MaxEvents 500 -ErrorAction SilentlyContinue)
        if ($records.Count -eq 0) { break }
        $events = @($records | ForEach-Object { ConvertTo-BgEvent $_ $Log } | Where-Object { $null -ne $_ })
        Add-Spool $events
        $cursor = [long]$records[-1].RecordId
        Set-Cursor $Log $cursor      # after the spool write: a crash re-reads (server deduplicates by uid)
        $total += $events.Count
    } while ($records.Count -eq 500)
    return $total
}

# ------------------------------------------------------------------ delivery
$script:Backoff = 0
$script:NextDelivery = [DateTime]::MinValue
$script:LastError = $null
$script:ServerStatus = 'unknown'
$script:UnreachableSince = $null   # when deliveries started failing for transport reasons
$script:StartedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$script:BootTime = $null
try { $script:BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { }

function Set-Unreachable { if (-not $script:UnreachableSince) { $script:UnreachableSince = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') } }

function Send-Spool {
    if ([DateTime]::UtcNow -lt $script:NextDelivery) { return }
    foreach ($file in @(Get-ChildItem (Join-Path $StateDir 'spool') -Filter *.json | Sort-Object Name | Select-Object -First 20)) {
        $events = @(Get-Content $file.FullName -Raw | ConvertFrom-Json)
        try {
            $result = Invoke-Api 'POST' '/api/v1/agent/events' @{ source = 'windows_security'; events = $events }
            if ($result.rejected) { foreach ($r in $result.rejected) { Write-Log 'WARN' "Server rejected an event: $($r.error)" }; $script:Meta.rejected_total += @($result.rejected).Count }
            Remove-Item $file.FullName -Force
            $script:Meta.delivered_total += [int]$result.accepted
            $script:Backoff = 0; $script:LastError = $null; $script:ServerStatus = 'active'; $script:UnreachableSince = $null
        } catch {
            $status = Get-Status $_
            $script:LastError = $_.Exception.Message
            if ($status -eq 401) { throw "Server rejected this agent's credential (revoked?). Re-enroll with a new code. $($_.Exception.Message)" }
            if ($status -eq 403) { $script:ServerStatus = 'pending-or-suspended'; Write-Log 'INFO' "Waiting for administrator approval: $($_.Exception.Message)"; $script:NextDelivery = [DateTime]::UtcNow.AddSeconds(60); return }
            Set-Unreachable
            $script:Backoff = [Math]::Min(300, [Math]::Max(2, $script:Backoff * 2))
            $script:NextDelivery = [DateTime]::UtcNow.AddSeconds($script:Backoff * (0.8 + (Get-Random -Maximum 0.4)))
            Write-Log 'WARN' "Server unavailable ($($_.Exception.Message)); retrying in $([int]$script:Backoff)s. Events remain buffered."
            return
        }
    }
    Save-Meta
}

function Send-Heartbeat {
    $spoolFiles = @(Get-ChildItem (Join-Path $StateDir 'spool') -Filter *.json)
    $health = @{
        agent_version = $AgentVersion; spool_files = $spoolFiles.Count; spool_depth = (Get-SpoolDepth); spool_limit = $SpoolMaxEvents
        boot_time = $script:BootTime; agent_started_at = $script:StartedAt; server_unreachable_since = $script:UnreachableSince
        dropped_total = [int]$script:Meta.dropped_total; rejected_total = [int]$script:Meta.rejected_total
        delivered_total = [int]$script:Meta.delivered_total; last_error = $script:LastError
        sources = @(@{ name = 'windows:Security'; kind = 'windows_security'; last_error = $script:SourceError; events_total = [int]$script:Meta.collected_total })
    }
    try {
        $reply = Invoke-Api 'POST' '/api/v1/agent/heartbeat' @{ fingerprint = $script:Fingerprint; agent_version = $AgentVersion; health = $health }
        $script:ServerStatus = $reply.status
        $script:UnreachableSince = $null
        if ($reply.rotate -and $reply.status -eq 'active') { Invoke-Rotation }
    } catch {
        $status = Get-Status $_
        if ($status -eq 401) { throw "Credential rejected (revoked?). $($_.Exception.Message)" }
        if ($status -eq 0 -or $status -ge 500) { Set-Unreachable }
        $script:LastError = $_.Exception.Message
    }
}

function Invoke-Rotation {
    $reply = Invoke-Api 'POST' '/api/v1/agent/rotate' @{}
    $script:Config.credential = Protect-Secret $reply.credential
    Write-Atomic (Join-Path $StateDir 'agent.json') (ConvertTo-Json $script:Config)   # persist before first use
    $script:Credential = $reply.credential
    Write-Log 'INFO' 'Credential rotated.'
}

function Import-Config {
    $path = Join-Path $StateDir 'agent.json'
    if (-not (Test-Path $path)) { throw "Not enrolled. Run: .\BlackguardAgent.ps1 -Enroll -Server <url> -Code <code>" }
    $script:Config = Get-Content $path -Raw | ConvertFrom-Json
    $script:Credential = Unprotect-Secret $script:Config.credential
    Set-TlsPolicy $script:Config.cert_thumbprint
    $metaPath = Join-Path $StateDir 'meta.json'
    $script:Meta = if (Test-Path $metaPath) { Get-Content $metaPath -Raw | ConvertFrom-Json } else { [pscustomobject]@{ dropped_total = 0; rejected_total = 0; delivered_total = 0; collected_total = 0 } }
    $script:Fingerprint = Get-Fingerprint
}

# ------------------------------------------------------------------ commands
if ($Enroll) {
    Initialize-StateDir
    $script:Config = [pscustomobject]@{ server = (Test-ServerUrl $Server); cert_thumbprint = $CertThumbprint }
    Set-TlsPolicy $CertThumbprint
    $fp = Get-Fingerprint
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $reply = Invoke-Api 'POST' '/api/v1/agent/enroll' @{ code = $Code; hostname = $env:COMPUTERNAME; platform = "Windows $os"; fingerprint = $fp; agent_version = $AgentVersion; sources = @('windows_security') } -NoAuth
    $script:Config | Add-Member -NotePropertyName agent_id -NotePropertyValue $reply.agent_id
    $script:Config | Add-Member -NotePropertyName credential -NotePropertyValue (Protect-Secret $reply.credential)
    Write-Atomic (Join-Path $StateDir 'agent.json') (ConvertTo-Json $script:Config)
    Write-Host "Enrolled as $($reply.agent_id). The agent is PENDING approval."
    Write-Host "In the dashboard, approve it only if the fingerprint matches:`n`n    $(Format-Fingerprint $fp)`n"
    exit 0
}

if ($Install) {
    $script = $MyInvocation.MyCommand.Path
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" -Run -StateDir `"$StateDir`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'BLACKGUARD Agent' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'BLACKGUARD Agent'
    Write-Host "Installed and started scheduled task 'BLACKGUARD Agent' (runs at startup as SYSTEM, restarts on failure)."
    exit 0
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName 'BLACKGUARD Agent' -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Scheduled task removed. State (including buffered events) remains in $StateDir."
    exit 0
}

if ($Status) {
    Import-Config
    $view = try { Invoke-Api 'GET' '/api/v1/agent/status' $null } catch { @{ error = $_.Exception.Message } }
    [pscustomobject]@{
        agent_id = $script:Config.agent_id; server = $script:Config.server; fingerprint = (Format-Fingerprint $script:Fingerprint)
        spool_files = @(Get-ChildItem (Join-Path $StateDir 'spool') -Filter *.json).Count; spool_events = (Get-SpoolDepth); dropped_total = $script:Meta.dropped_total
        security_cursor = (Get-Cursor 'Security'); server_view = $view
    } | ConvertTo-Json -Depth 4
    exit 0
}

# -Run (default)
Import-Config
try { Get-WinEvent -ListLog Security | Out-Null } catch { throw 'Cannot read the Security log. Run as SYSTEM (scheduled task) or as an administrator / member of Event Log Readers.' }
Write-Log 'INFO' "BLACKGUARD Windows agent $AgentVersion started (agent $($script:Config.agent_id)). Read-only."
$script:SourceError = $null
$nextHeartbeat = [DateTime]::MinValue
while ($true) {
    try {
        $count = (Read-Log 'Security' $SecurityIds) + (Read-Log 'System' $SystemIds)
        $script:Meta.collected_total += $count
        $script:SourceError = $null
    } catch { $script:SourceError = $_.Exception.Message; Write-Log 'ERROR' "Collection failed: $($_.Exception.Message)" }
    if ([DateTime]::UtcNow -ge $nextHeartbeat) { Send-Heartbeat; $nextHeartbeat = [DateTime]::UtcNow.AddSeconds(30) }
    Send-Spool
    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
}
