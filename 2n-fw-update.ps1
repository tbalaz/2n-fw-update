<#
.SYNOPSIS
  Update the firmware of one or many 2N IP intercoms (with or without camera).

.DESCRIPTION
  For every device: read model + running version (GET /api/system/info), upload the firmware file
  (PUT /api/firmware, multipart field blob-fw), check what the device says about the image (version,
  downgrade flag), apply it (/api/firmware/apply), wait for the restart and confirm the running version.
  Devices are handled in parallel (-Parallel, default 4). A device that refuses the file (wrong model,
  corrupt image) fails at the upload step and is left untouched; the others carry on. Configuration is
  kept (normal 2N upgrade). The camera makes no difference: the image is per model family, not per camera.

  Runs on stock Windows PowerShell 5.1 and on PowerShell 7; nothing to install.
  Device side: Services > HTTP API > System API must be enabled and the account needs System "Control"
  access. Authentication is detected per device: Digest (or none) works as is; Basic is refused unless
  -AllowBasic is given, because it sends the password itself.
  Login: -Credential, or env TWON_USER / TWON_PASS, otherwise the script asks. One account per run.
  API reference: 2N HTTP API manual 5.2.1-5.2.3 (wiki.2n.com/hip/hapi/latest/en, api/firmware, apply, reject).
  HTTPS is used by default and the certificate is NOT checked (2N ships a self-signed one) unless
  -VerifyCertificate is given.
  Exit code 0 = every device runs the new version.

.EXAMPLE
  .\2n-fw-update.ps1 C:\fw\verso.bin 192.168.1.20 -DryRun
  Read-only: shows model and running version, uploads nothing.
.EXAMPLE
  .\2n-fw-update.ps1 C:\fw\verso.bin 192.168.1.20,192.168.1.21
.EXAMPLE
  .\2n-fw-update.ps1 C:\fw\verso.bin -DeviceFile doors.txt -Yes
  doors.txt: one IP or name per line (optional :port), # comments allowed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$FirmwarePath,
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)][string[]]$Device,
    [string]$DeviceFile,
    [pscredential]$Credential,
    [switch]$Http,               # plain HTTP instead of HTTPS
    [switch]$VerifyCertificate,  # check the device TLS certificate
    [switch]$AllowBasic,         # permit Basic login (password readable on the wire unless TLS is verified)
    [switch]$AllowDowngrade,
    [switch]$Force,              # apply even when the device already runs this version
    [int]$Parallel = 4,
    [int]$TimeoutSec = 600,      # how long to wait for the restart
    [switch]$DryRun,             # only read model and version
    [switch]$Yes                 # do not ask before updating
)
$ErrorActionPreference = 'Stop'

# ---- one device; runs in its own background job -------------------------------------------------
$worker = {
    param($Dev, $O)
    $ErrorActionPreference = 'Stop'
    $r = [ordered]@{ Device = $Dev; Model = '?'; Before = '?'; After = '?'; Result = '' }
    $hints = @{
        1  = 'function not supported by this model/licence'
        7  = 'device demands HTTPS - drop -Http'
        8  = 'authentication method not accepted'
        9  = 'login required - check user / password'
        10 = 'account lacks System API Control access'
        12 = 'device rejected the file - wrong model or corrupt image'
        19 = 'image is older than the minimum version this device allows'
    }
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    if ($PSVersionTable.PSEdition -ne 'Core') {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::Expect100Continue = $false
    }
    if (-not $O.Http -and -not $O.Verify) {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        } else {
            Add-Type -TypeDefinition 'using System.Net.Security; public static class TwoNTrust { public static RemoteCertificateValidationCallback Callback = delegate { return true; }; }'
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [TwoNTrust]::Callback
        }
    }
    $client = New-Object System.Net.Http.HttpClient $handler
    $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan
    $base = $(if ($O.Http) { 'http' } else { 'https' }) + "://$Dev"
    $net = $O.Cred.GetNetworkCredential()
    $ctx = @{ Scheme = ''; P = @{}; Nc = 0 }   # last auth challenge from the device

    function Get-Hash($Text, $Alg) {
        $h = if ($Alg -like 'SHA-256*') { [System.Security.Cryptography.SHA256]::Create() } else { [System.Security.Cryptography.MD5]::Create() }
        -join ($h.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') })
    }
    function Get-AuthHeader($Method, $Uri) {
        if ($ctx.Scheme -eq 'Basic') {
            return 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($net.UserName + ':' + $net.Password))
        }
        if ($ctx.Scheme -ne 'Digest') { return $null }
        $p = $ctx.P; $alg = if ($p.algorithm) { $p.algorithm } else { 'MD5' }
        $ha1 = Get-Hash ($net.UserName + ':' + $p.realm + ':' + $net.Password) $alg
        $ha2 = Get-Hash ($Method + ':' + $Uri) $alg
        $v = 'Digest username="{0}", realm="{1}", nonce="{2}", uri="{3}", algorithm={4}' -f $net.UserName, $p.realm, $p.nonce, $Uri, $alg
        if ($p.qop) {
            $ctx.Nc++; $nc = '{0:x8}' -f $ctx.Nc; $cn = [guid]::NewGuid().ToString('N').Substring(0, 16)
            $resp = Get-Hash ($ha1 + ':' + $p.nonce + ':' + $nc + ':' + $cn + ':auth:' + $ha2) $alg
            $v += ', qop=auth, nc={0}, cnonce="{1}"' -f $nc, $cn
        } else {
            $resp = Get-Hash ($ha1 + ':' + $p.nonce + ':' + $ha2) $alg
        }
        if ($p.opaque) { $v += ', opaque="{0}"' -f $p.opaque }
        return $v + ', response="{0}"' -f $resp
    }
    function Read-Challenge($Response) {
        $c = @($Response.Headers.WwwAuthenticate)
        $pick = $c | Where-Object { $_.Scheme -eq 'Digest' } | Select-Object -First 1
        if (-not $pick) {
            $pick = $c | Where-Object { $_.Scheme -eq 'Basic' } | Select-Object -First 1
            # Basic sends the password itself. Never answer it unasked: on an unverified connection anyone
            # on the path could request Basic instead of Digest and read the password.
            if ($pick -and -not $O.AllowBasic) {
                throw 'device asks for Basic login, which sends the password readable on the wire - set the device HTTP API to Digest, or pass -AllowBasic (best together with -VerifyCertificate)'
            }
        }
        if (-not $pick) { return $false }
        $ctx.Scheme = $pick.Scheme; $ctx.P = @{}; $ctx.Nc = 0
        foreach ($m in [regex]::Matches([string]$pick.Parameter, '(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))')) {
            $ctx.P[$m.Groups[1].Value.ToLower()] = $m.Groups[2].Value + $m.Groups[3].Value
        }
        return $true
    }
    function Invoke-Api($Method, $Path, $Content, $Timeout = 20) {
        $uri = "/api/$Path"
        for ($try = 0; $try -lt 2; $try++) {
            $req = New-Object System.Net.Http.HttpRequestMessage (New-Object System.Net.Http.HttpMethod $Method), ($base + $uri)
            $auth = Get-AuthHeader $Method $uri
            if ($auth) { [void]$req.Headers.TryAddWithoutValidation('Authorization', $auth) }
            if ($Content) { $req.Content = $Content }
            $cts = New-Object System.Threading.CancellationTokenSource ([TimeSpan]::FromSeconds($Timeout))
            $resp = $client.SendAsync($req, $cts.Token).GetAwaiter().GetResult()
            $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $code = [int]$resp.StatusCode
            # first call, or the nonce went stale (restart): take the new challenge and repeat once.
            # Never repeated for the upload, so the firmware goes over the wire once.
            if ($code -eq 401 -and $try -eq 0 -and -not $Content -and (Read-Challenge $resp)) { continue }
            if ($code -eq 401) { throw 'login refused (HTTP 401) - check user / password' }
            try { $j = $text | ConvertFrom-Json } catch { throw "HTTP $code with a non-JSON reply from $uri - is the HTTP API enabled?" }
            if (-not $j.success) {
                $hint = $hints[[int]$j.error.code]
                throw ("{0}: error {1} {2}" -f $uri, $j.error.code, $j.error.description) + $(if ($hint) { " ($hint)" })
            }
            return $j.result
        }
    }
    function Test-SameVersion($A, $B) { $A -and $B -and ($A -eq $B -or $A.StartsWith($B) -or $B.StartsWith($A)) }

    try {
        $info = Invoke-Api GET 'system/info'
        $r.Model = [string]$info.variant; $r.Before = [string]$info.swVersion
        "[$Dev] $($r.Model), running $($r.Before)"
        # system/info answers without login, so check login + System Control here, before the big upload:
        # reject of an id that cannot exist is harmless and must answer error 12/14 when the account is fine.
        # It also picks up the auth challenge (digest nonce), so the firmware is sent only once.
        try { [void](Invoke-Api GET 'firmware/reject?fileId=00000000') }
        catch { if ($_.Exception.Message -notmatch ': error (12|14) ') { throw } }
        if ($O.DryRun) { $r.After = $r.Before; $r.Result = 'DRY-RUN'; return [pscustomobject]$r }

        "[$Dev] uploading ..."
        $mp = New-Object System.Net.Http.MultipartFormDataContent
        $bc = New-Object System.Net.Http.ByteArrayContent (, [System.IO.File]::ReadAllBytes($O.Firmware))
        $bc.Headers.ContentType = 'application/octet-stream'
        # quoted names and an unquoted boundary: what browsers and curl send, safest for embedded web servers
        $mp.Add($bc, '"blob-fw"', '"' + [System.IO.Path]::GetFileName($O.Firmware) + '"')
        $b = $mp.Headers.ContentType.Parameters | Where-Object { $_.Name -eq 'boundary' }
        $b.Value = $b.Value.Trim('"')
        try { $up = Invoke-Api PUT 'firmware' $mp 900 }
        catch {
            for ($e = $_.Exception; $e; $e = $e.InnerException) {
                if ($e -is [System.OperationCanceledException]) {
                    throw 'upload got no reply - an earlier unapplied image may still be pending on the device (it is dropped after 5 minutes); wait and rerun'
                }
            }
            throw
        }
        $new = [string]$up.version
        # parameter case as documented by 2N: apply takes fileid, reject takes fileId
        $id = [uri]::EscapeDataString([string]$up.fileId)
        $qApply = if ($id) { "?fileid=$id" } else { '' }
        $qReject = if ($id) { "?fileId=$id" } else { '' }
        "[$Dev] image accepted: $new" + $(if ($up.downgrade) { ' (DOWNGRADE)' })

        $skip = $null
        if ($up.downgrade -and -not $O.AllowDowngrade) { $skip = 'SKIPPED: downgrade (use -AllowDowngrade)' }
        elseif ((Test-SameVersion $r.Before $new) -and -not $O.Force) { $skip = 'OK: already on this version' }
        if ($skip) {
            try { [void](Invoke-Api GET "firmware/reject$qReject") } catch { }   # device drops an unapplied image after 5 min anyway
            $r.After = $r.Before; $r.Result = $skip; return [pscustomobject]$r
        }

        [void](Invoke-Api GET "firmware/apply$qApply")
        "[$Dev] applied, waiting for restart ..."
        $deadline = (Get-Date).AddSeconds($O.TimeoutSec); $seenDown = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            try { $r.After = [string](Invoke-Api GET 'system/info' $null 5).swVersion } catch { $seenDown = $true; continue }
            if (Test-SameVersion $r.After $new) { $r.Result = 'OK: updated'; return [pscustomobject]$r }
            if ($seenDown) { $r.Result = "FAILED: back up on $($r.After), expected $new"; return [pscustomobject]$r }
        }
        $r.Result = "FAILED: no $new within $($O.TimeoutSec)s" + $(if (-not $seenDown) { ' (device never restarted)' })
    } catch {
        $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
        $r.Result = 'FAILED: ' + $e.Message
    }
    [pscustomobject]$r
}

# ---- main ------------------------------------------------------------------------------------------
$devices = @($Device | Where-Object { $_ } | ForEach-Object { $_ -split ',' })
if ($DeviceFile) { $devices += Get-Content -LiteralPath $DeviceFile | ForEach-Object { ($_ -split '#')[0].Trim() } }
$devices = @($devices | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
if (-not $devices) { throw 'No devices given: pass IPs/names or -DeviceFile.' }
if (-not (Test-Path -LiteralPath $FirmwarePath -PathType Leaf)) { throw "Firmware file not found: $FirmwarePath" }
$fw = (Resolve-Path -LiteralPath $FirmwarePath).ProviderPath

if (-not $Credential) {
    if ($env:TWON_USER -and $env:TWON_PASS) {
        $Credential = New-Object pscredential $env:TWON_USER, (ConvertTo-SecureString $env:TWON_PASS -AsPlainText -Force)
    } else {
        $Credential = Get-Credential -Message '2N device login (System API account)' -UserName $env:TWON_USER
    }
}

Write-Host ("firmware: {0} ({1:N1} MB)" -f $fw, ((Get-Item -LiteralPath $fw).Length / 1MB))
Write-Host ("devices ({0}): {1}" -f $devices.Count, ($devices -join ', '))
if (-not ($DryRun -or $Yes)) {
    if ((Read-Host 'Each device restarts during the update (about 1-3 min offline). Proceed? [y/N]') -notmatch '^\s*y') { exit 2 }
}

$opt = @{ Firmware = $fw; Cred = $Credential; Http = [bool]$Http; Verify = [bool]$VerifyCertificate
          AllowBasic = [bool]$AllowBasic
          AllowDowngrade = [bool]$AllowDowngrade; Force = [bool]$Force; TimeoutSec = $TimeoutSec; DryRun = [bool]$DryRun }
$queue = New-Object System.Collections.Queue (, $devices)
$jobs = @(); $results = @{}
while ($queue.Count -or $jobs.Count) {
    while ($queue.Count -and $jobs.Count -lt [Math]::Max(1, $Parallel)) {
        $d = $queue.Dequeue()
        $jobs += Start-Job -Name $d -ScriptBlock $worker -ArgumentList $d, $opt
    }
    foreach ($j in @($jobs)) {
        $done = $j.State -notin 'NotStarted', 'Running'
        Receive-Job $j -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_ -is [string]) { Write-Host $_ } else { $results[$j.Name] = $_ }
        }
        if ($done) {
            if (-not $results.ContainsKey($j.Name)) {
                $why = if ($j.ChildJobs[0].JobStateInfo.Reason) { $j.ChildJobs[0].JobStateInfo.Reason.Message } else { 'worker ended without a result' }
                $results[$j.Name] = [pscustomobject]@{ Device = $j.Name; Model = '?'; Before = '?'; After = '?'; Result = "FAILED: $why" }
            }
            Remove-Job $j -Force
            $jobs = @($jobs | Where-Object { $_.Id -ne $j.Id })
        }
    }
    Start-Sleep -Milliseconds 300
}

$table = $devices | ForEach-Object { $results[$_] } | Select-Object Device, Model, Before, After, Result
$table | Format-Table -AutoSize -Wrap | Out-String | Write-Host
if ($table | Where-Object { $_.Result -match '^(FAILED|SKIPPED)' }) { exit 1 }
exit 0
