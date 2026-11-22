<#
.SYNOPSIS
  Checks every external source URL in the Sentinel X datasets.

.DESCRIPTION
  Extracts all "url" values from data/*.json and requests each one (GET, generic
  user agent, 25 s timeout). Prints status code per URL and exits non-zero if any
  URL fails. Some sites block automated clients (HTTP 403) — those are reported
  separately so they can be checked manually in a browser.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tools\check-links.ps1
#>
param(
  [string]$DataDir = (Join-Path $PSScriptRoot '..\data'),
  # The CVE snapshot also contains every reference NVD lists for each CVE (third-party links
  # we copy but do not cite). They are skipped unless this switch is given.
  [switch]$IncludeNvdReferences
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelX-LinkCheck/1.0'

$urls = Get-ChildItem -Path $DataDir -Filter *.json | ForEach-Object {
  $json = Get-Content -Raw -Encoding UTF8 $_.FullName
  if ($_.Name -eq 'cve-snapshot.json' -and -not $IncludeNvdReferences) {
    $snap = $json | ConvertFrom-Json
    foreach ($s in $snap.sources.PSObject.Properties.Value) { $s.url }
  } else {
    [regex]::Matches($json, '"url"\s*:\s*"(https?://[^"]+)"') | ForEach-Object { $_.Groups[1].Value }
  }
} | Sort-Object -Unique

# curl.exe (bundled with Windows 10 1803+) is used because Invoke-WebRequest in
# Windows PowerShell 5.1 can stall for over a minute per request on some machines,
# which made earlier runs time out. curl also follows 308 redirects.
$useCurl = [bool](Get-Command curl.exe -ErrorAction SilentlyContinue)
$results = foreach ($u in $urls) {
  $status = $null; $note = ''
  if ($useCurl) {
    $code = & curl.exe -s -o NUL -L --max-redirs 5 -m 25 -A $ua -w '%{http_code}' $u
    $status = [int]($code | Select-Object -Last 1)
    if ($status -eq 429) {
      # Rate limited (rfc-editor.org does this for bursts): wait and retry once.
      Start-Sleep -Seconds 15
      $code = & curl.exe -s -o NUL -L --max-redirs 5 -m 25 -A $ua -w '%{http_code}' $u
      $status = [int]($code | Select-Object -Last 1)
      $note = 'retried after 429'
    }
    if ($status -eq 0) { $note = "curl exit $LASTEXITCODE" }
  } else {
    try {
      $r = Invoke-WebRequest -Uri $u -UseBasicParsing -UserAgent $ua -TimeoutSec 25 -MaximumRedirection 5
      $status = [int]$r.StatusCode
    } catch {
      if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
      else { $status = 0; $note = $_.Exception.Message }
    }
  }
  [pscustomobject]@{ Status = $status; Url = $u; Note = $note }
}

$results | Sort-Object Status, Url | Format-Table -AutoSize -Wrap
# 403 (bot protection) and 429 (rate limiting) mean "could not check automatically", not "broken".
$ok = @($results | Where-Object { $_.Status -ge 200 -and $_.Status -lt 400 }).Count
$blocked = @($results | Where-Object { $_.Status -eq 403 -or $_.Status -eq 429 }).Count
$failed = @($results | Where-Object { $_.Status -eq 0 -or ($_.Status -ge 400 -and $_.Status -ne 403 -and $_.Status -ne 429) }).Count
Write-Host ("{0} URLs: {1} OK, {2} not checkable automatically (403 bot block / 429 rate limit; verify manually), {3} failed" -f $results.Count, $ok, $blocked, $failed)
if ($failed -gt 0) { exit 1 }
