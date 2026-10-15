<#
Deploy the latest pushed code to the running instance (git pull, rebuild, restart). Data volumes are kept.
#>
$ErrorActionPreference = "Stop"
$state = Join-Path $PSScriptRoot ".state.json"
if (-not (Test-Path $state)) { throw "No deployment found. Run provision.ps1 first." }
$s = Get-Content $state -Raw | ConvertFrom-Json
ssh -o StrictHostKeyChecking=accept-new -i $s.keyPath "ubuntu@$($s.ip)" "cd /opt/blastradius && sudo git pull --ff-only && cd deploy && sudo docker compose -f docker-compose.prod.yml up -d --build && sudo docker compose -f docker-compose.prod.yml ps"
$u = "https://$($s.host)"
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-WebRequest "$u/api/health" -UseBasicParsing -TimeoutSec 8).StatusCode -eq 200) { break } } catch { Start-Sleep 4 } }
node (Join-Path $PSScriptRoot "..\..\tools\probe.mjs") $u

