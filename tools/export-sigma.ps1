<#
.SYNOPSIS
  Exports the Sigma rules in data/detection-rules.json to individual .yml files.

.DESCRIPTION
  The web app stores each rule's YAML as an array of lines inside JSON. This
  script writes one <slug>.yml per rule (UTF-8, no BOM, LF line endings) so the
  rules can be validated with the official tooling (`sigma check`) and imported
  into other systems. Works in Windows PowerShell 5.1 and PowerShell 7.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tools\export-sigma.ps1
  pwsh ./tools/export-sigma.ps1 -OutDir rules-ci
#>
param([string]$OutDir = (Join-Path $PSScriptRoot '..\rules'))

$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot '..\data\detection-rules.json'
$data = Get-Content -Raw -Encoding UTF8 $src | ConvertFrom-Json
New-Item -ItemType Directory -Force $OutDir | Out-Null
$enc = New-Object Text.UTF8Encoding($false)
$n = 0
foreach ($r in $data.rules) {
  if ($r.slug -notmatch '^[a-z0-9-]{2,60}$') { throw "Unsafe rule slug: $($r.slug)" }
  $path = Join-Path (Resolve-Path $OutDir).Path "$($r.slug).yml"
  [IO.File]::WriteAllText($path, (($r.yaml -join "`n") + "`n"), $enc)
  $n++
}
Write-Host "Exported $n Sigma rules to $((Resolve-Path $OutDir).Path)"
