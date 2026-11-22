<#
.SYNOPSIS
  Zero-dependency local development server for Sentinel X (Windows PowerShell 5.1+).

.DESCRIPTION
  ES modules cannot load from file://, so the site must be served over HTTP.
  This script serves the project folder on http://localhost:<Port>/ using .NET's
  HttpListener, bound to localhost only, with path-traversal protection and the
  same security headers that netlify.toml sends in production.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\serve.ps1
  powershell -ExecutionPolicy Bypass -File .\serve.ps1 -Port 5500
#>
param([int]$Port = 8080)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path $PSScriptRoot).Path.TrimEnd('\') + '\'

$mime = @{
  '.html' = 'text/html; charset=utf-8'; '.css' = 'text/css; charset=utf-8'
  '.js'   = 'text/javascript; charset=utf-8'; '.mjs' = 'text/javascript; charset=utf-8'
  '.json' = 'application/json; charset=utf-8'; '.svg' = 'image/svg+xml'
  '.png'  = 'image/png'; '.jpg' = 'image/jpeg'; '.webp' = 'image/webp'
  '.ico'  = 'image/x-icon'; '.woff2' = 'font/woff2'; '.md' = 'text/plain; charset=utf-8'
  '.txt'  = 'text/plain; charset=utf-8'
}

$securityHeaders = @{
  'Content-Security-Policy' = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'"
  'X-Content-Type-Options'  = 'nosniff'
  'Referrer-Policy'         = 'strict-origin-when-cross-origin'
  'Permissions-Policy'      = 'camera=(), microphone=(), geolocation=(), payment=()'
  'X-Frame-Options'         = 'DENY'
  'Cache-Control'           = 'no-store'
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "Sentinel X dev server: http://localhost:$Port/  (Ctrl+C to stop)"

try {
  while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $req = $ctx.Request; $res = $ctx.Response
    try {
      foreach ($k in $securityHeaders.Keys) { $res.Headers[$k] = $securityHeaders[$k] }

      if ($req.HttpMethod -ne 'GET' -and $req.HttpMethod -ne 'HEAD') {
        $res.StatusCode = 405; continue
      }

      $rel = [Uri]::UnescapeDataString($req.Url.AbsolutePath).TrimStart('/')
      if ($rel -eq '' -or $rel.EndsWith('/')) { $rel = $rel + 'index.html' }
      $full = [System.IO.Path]::GetFullPath((Join-Path $root $rel))

      # Path traversal guard: the resolved path must stay inside the project root.
      if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $full -PathType Leaf)) {
        $res.StatusCode = 404
        $body = [Text.Encoding]::UTF8.GetBytes('404 Not Found')
        $res.ContentType = 'text/plain; charset=utf-8'
        $res.OutputStream.Write($body, 0, $body.Length)
      } else {
        $ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
        $res.ContentType = if ($mime.ContainsKey($ext)) { $mime[$ext] } else { 'application/octet-stream' }
        $bytes = [System.IO.File]::ReadAllBytes($full)
        $res.ContentLength64 = $bytes.Length
        if ($req.HttpMethod -eq 'GET') { $res.OutputStream.Write($bytes, 0, $bytes.Length) }
      }
      Write-Host ("{0} {1} {2}" -f $res.StatusCode, $req.HttpMethod, $req.Url.AbsolutePath)
    } catch {
      # The client may have disconnected (e.g. page reload mid-request); never let that stop the server.
      try { $res.StatusCode = 500 } catch {}
      Write-Warning $_.Exception.Message
    } finally {
      try { $res.OutputStream.Close() } catch { Write-Warning "Client disconnected before the response completed: $($req.Url.AbsolutePath)" }
    }
  }
} finally {
  $listener.Stop()
}
