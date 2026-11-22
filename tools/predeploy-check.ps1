<#
.SYNOPSIS
  Pre-deployment checks for Sentinel X. Exits 1 if any check fails.

.DESCRIPTION
  Runs on Windows PowerShell 5.1 and PowerShell 7 (CI). No network access.
    1. Every data/*.json file parses.
    2. Text files have no UTF-8 BOM (a BOM breaks JSON.parse on some hosts).
    3. No secret-looking strings (cloud keys, tokens, private keys) in tracked text files.
    4. Every relative ES module import (static and dynamic) resolves to a file.
    5. Every local href/src in index.html and tests/index.html exists.
    6. All four CSP sources enforce Trusted Types and script-src 'self'.
    7. The Netlify function entry point and its imports exist.
    8. No file larger than 5 MB.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tools\predeploy-check.ps1
#>
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$failures = New-Object System.Collections.Generic.List[string]
function Fail([string]$msg) { $failures.Add($msg) | Out-Null; Write-Host "  FAIL $msg" -ForegroundColor Red }
function Rel([string]$p) { $p.Substring($root.Length + 1).Replace('\', '/') }
$skipDirs = '[\\/](node_modules|\.git|\.netlify|rules-ci|test-results)[\\/]'   # works with Windows and Linux paths
$textExt = '.js', '.mjs', '.json', '.css', '.html', '.md', '.yml', '.yaml', '.toml', '.ps1', '.svg', '.txt'
$files = Get-ChildItem -Path $root -Recurse -File -Force | Where-Object { $_.FullName -notmatch $skipDirs }
$text = $files | Where-Object { $textExt -contains $_.Extension.ToLowerInvariant() }
$utf8 = New-Object System.Text.UTF8Encoding $false

Write-Host '1. JSON datasets parse'
foreach ($f in Get-ChildItem (Join-Path $root 'data') -Filter *.json) {
  try { [IO.File]::ReadAllText($f.FullName, $utf8) | ConvertFrom-Json | Out-Null } catch { Fail "$(Rel $f.FullName): invalid JSON ($($_.Exception.Message))" }
}

Write-Host '2. No UTF-8 BOM'
foreach ($f in $text) {
  $b = [IO.File]::ReadAllBytes($f.FullName)
  if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { Fail "$(Rel $f.FullName): has a UTF-8 BOM" }
}

Write-Host '3. No secret-looking strings'
$secretPatterns = @(
  'AKIA[0-9A-Z]{16}', 'ghp_[A-Za-z0-9]{30,}', 'github_pat_[A-Za-z0-9_]{20,}', 'sk-[A-Za-z0-9]{32,}',
  'xox[abprs]-[A-Za-z0-9-]{10,}', '-----BEGIN [A-Z ]*PRIVATE KEY-----', 'AIza[0-9A-Za-z_-]{35}',
  '(?i)(api[_-]?key|secret|token)\s*[:=]\s*[''"][A-Za-z0-9_\-]{24,}[''"]'
)
foreach ($f in $text) {
  if ((Rel $f.FullName) -eq 'tools/predeploy-check.ps1') { continue }
  $c = [IO.File]::ReadAllText($f.FullName, $utf8)
  foreach ($p in $secretPatterns) { if ($c -match $p) { Fail "$(Rel $f.FullName): matches secret pattern $p" } }
}

Write-Host '4. Relative module imports resolve'
$importRe = '(?:import\s[^;]*?from\s*|import\s*\(\s*|export\s[^;]*?from\s*)[''"](\.{1,2}/[^''"]+)[''"]'
foreach ($f in $files | Where-Object { '.js', '.mjs' -contains $_.Extension }) {
  $c = [IO.File]::ReadAllText($f.FullName, $utf8)
  foreach ($m in [regex]::Matches($c, $importRe)) {
    $spec = $m.Groups[1].Value -replace '\?.*$', ''
    $target = [IO.Path]::GetFullPath((Join-Path $f.DirectoryName $spec))
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { Fail "$(Rel $f.FullName): import '$spec' not found" }
  }
}

Write-Host '5. Local href/src in HTML exist'
foreach ($page in 'index.html', 'tests/index.html') {
  $full = Join-Path $root $page
  $c = [IO.File]::ReadAllText($full, $utf8)
  foreach ($m in [regex]::Matches($c, '(?:href|src)="([^"#:]+)"')) {
    $target = [IO.Path]::GetFullPath((Join-Path (Split-Path $full) $m.Groups[1].Value))
    if (-not (Test-Path -LiteralPath $target)) { Fail "${page}: '$($m.Groups[1].Value)' not found" }
  }
}

Write-Host '6. CSP sources agree on the essentials'
foreach ($src in 'index.html', 'netlify.toml', 'serve.ps1', 'serve.json') {
  $c = [IO.File]::ReadAllText((Join-Path $root $src), $utf8)
  foreach ($need in "script-src 'self'", "object-src 'none'", "require-trusted-types-for 'script'", "trusted-types 'none'") {
    if (-not $c.Contains($need)) { Fail "${src}: CSP is missing ""$need""" }
  }
  if ($c -match "unsafe-inline|unsafe-eval") { Fail "${src}: CSP allows unsafe-inline or unsafe-eval" }
}

Write-Host '7. Netlify function present'
$toml = [IO.File]::ReadAllText((Join-Path $root 'netlify.toml'), $utf8)
if ($toml -notmatch 'directory\s*=\s*"netlify/functions"') { Fail 'netlify.toml: functions directory is not netlify/functions' }
if (-not (Test-Path (Join-Path $root 'netlify/functions/ioc.mjs'))) { Fail 'netlify/functions/ioc.mjs missing' }

Write-Host '8. No oversized files'
foreach ($f in $files) { if ($f.Length -gt 5MB) { Fail "$(Rel $f.FullName): $([math]::Round($f.Length / 1MB, 1)) MB" } }

if ($failures.Count) { Write-Host "`n$($failures.Count) check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host "`nAll pre-deploy checks passed ($($files.Count) files)." -ForegroundColor Green
exit 0
