<#
.SYNOPSIS
  Spot-checks that key phrases behind documented claims still appear in the cited sources.

.DESCRIPTION
  A working link is not proof that a summary is accurate, and some sites redirect
  removed pages to an index ("soft 404"). For each source this script fetches the
  page text and confirms the phrases our facts rely on are present.

  Pages that render their text with JavaScript (Microsoft MSRC blog, justice.gov,
  gao.gov) cannot be checked this way and are listed under $manual — verify those
  in a browser. Results of the last manual check are recorded in docs/testing.md.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tools\check-claims.ps1
#>
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelX-LinkCheck/1.0'

$checks = [ordered]@{
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a' = @('most deployed ransomware variant', 'RDP', 'phishing')
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a' = @('helpdesk staff', 'healthcare sector has been the most commonly victimized')
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a' = @('push bombing', 'SIM', 'helpdesk', 'DragonForce')
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a' = @('pre-positioning', 'ntdsutil', 'Volume Shadow', 'wmic', 'netsh')
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a' = @('May 27', 'LEMURLOOT', 'SQL injection')
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-280a' = @('TrickBot', 'QakBot', 'phishing')
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a' = @('bypass password requirements', 'multifactor authentication', 'LockBit 3.0')
  'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a' = @('avsvmcloud', 'SolarWinds Orion')
  'https://www.cisa.gov/news-events/alerts/2016/10/14/heightened-ddos-threat-posed-mirai-and-other-botnets' = @('default', 'Mirai')
  'https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware' = @('EternalBlue', 'PsExec', 'WMI', 'MBR')
  'https://www.cisa.gov/news-events/alerts/2023/03/30/supply-chain-attack-against-3cxdesktopapp' = @('3CXDesktopApp', 'supply chain')
  'https://www.cisa.gov/news-events/news/attack-colonial-pipeline-what-weve-learned-what-weve-done-over-past-two-years' = @('May 7, 2021', 'eastern seaboard', 'stopransomware.gov', 'Joint Ransomware Task Force')
  'https://www.cisa.gov/news-events/directives/ed-21-04-mitigate-windows-print-spooler-service-vulnerability' = @('SYSTEM privileges', 'multiple threat actors', 'Domain Controllers')
  'https://www.dfs.ny.gov/reports_and_publications/press_releases/pr202010141' = @('IT department', 'double your bitcoin', '118,000')
  'https://github.blog/2018-03-01-ddos-incident-report/' = @('1.35Tbps', 'memcached')
  'https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/' = @('session cookie', 'MFA', 'business email compromise')
  'https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor' = @('DNS', 'avsvmcloud')
  'https://samy.pl/myspace/' = @('million', '20 hours')
  'https://www.nationalcrimeagency.gov.uk/news/nca-leads-international-investigation-targeting-worlds-most-harmful-ransomware-group' = @('taken control', 'Operation Cronos')
  'https://www.europol.europa.eu/media-press/newsroom/news/world%E2%80%99s-most-dangerous-malware-emotet-disrupted-through-global-action' = @('EMOTET', 'Eurojust')
}
$manual = @(
  'https://www.microsoft.com/en-us/msrc/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard  (password spray, legacy non-production test tenant, small percentage, senior leadership)',
  'https://www.justice.gov/archives/opa/pr/qakbot-malware-disrupted-international-cyber-takedown  (multinational, 700,000, August 29, 2023)',
  'https://www.gao.gov/products/gao-18-559  (at least 145.5 million individuals; published Aug 30, 2018)'
)

$fail = 0
foreach ($u in $checks.Keys) {
  try {
    $html = (Invoke-WebRequest -Uri $u -UseBasicParsing -UserAgent $ua -TimeoutSec 40).Content
    $text = [System.Net.WebUtility]::HtmlDecode(($html -replace '<[^>]+>', ' ')) -replace '[‐-―]', '-' -replace '\s+', ' '
    $missing = @($checks[$u] | Where-Object { $text.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -lt 0 })
    if ($missing.Count) { $fail++; "MISSING  $u :: $($missing -join ' | ')" } else { "ok       $u" }
  } catch { $fail++; "ERROR    $u :: $($_.Exception.Message)" }
}
''
'Verify manually in a browser (JavaScript-rendered or bot-protected):'
$manual | ForEach-Object { "  - $_" }
if ($fail) { exit 1 }
