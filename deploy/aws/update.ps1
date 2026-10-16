<#
Deploy the latest pushed code to the running instance (git pull, rebuild, restart). Data volumes are kept.
  ./update.ps1            # code only
  ./update.ps1 -Reseed    # also rebuild the curated graphs from the committed snapshot (use after the snapshot or schema changed;
                          # this resets curated-tenant memory and anything a rescan added)
#>
param([switch]$Reseed)
$ErrorActionPreference = "Stop"
$state = Join-Path $PSScriptRoot ".state.json"
if (-not (Test-Path $state)) { throw "No deployment found. Run provision.ps1 first." }
$s = Get-Content $state -Raw | ConvertFrom-Json
$cmd = "cd /opt/blastradius && sudo git pull --ff-only && cd deploy && sudo docker compose -f docker-compose.prod.yml up -d --build"
if ($Reseed) { $cmd += " && sudo docker compose -f docker-compose.prod.yml --profile seed run --rm --build seed" }
$cmd += " && sudo docker compose -f docker-compose.prod.yml ps"
ssh -o StrictHostKeyChecking=accept-new -i $s.keyPath "ubuntu@$($s.ip)" $cmd
$u = "https://$($s.host)"
for ($i = 0; $i -lt 30; $i++) { try { if ((Invoke-WebRequest "$u/api/health" -UseBasicParsing -TimeoutSec 8).StatusCode -eq 200) { break } } catch { Start-Sleep 4 } }
node (Join-Path $PSScriptRoot "..\..\tools\probe.mjs") $u
