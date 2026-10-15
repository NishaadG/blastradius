<#
Deploy the latest pushed code to the running instance (git pull, rebuild, restart). Data volumes are kept.
#>
$ErrorActionPreference = "Stop"
$state = Join-Path $PSScriptRoot ".state.json"
if (-not (Test-Path $state)) { throw "No deployment found. Run provision.ps1 first." }
$s = Get-Content $state -Raw | ConvertFrom-Json
ssh -o StrictHostKeyChecking=accept-new -i $s.keyPath "ubuntu@$($s.ip)" "cd /opt/blastradius && sudo git pull --ff-only && cd deploy && sudo docker compose -f docker-compose.prod.yml up -d --build && sudo docker compose -f docker-compose.prod.yml ps"
node (Join-Path $PSScriptRoot "..\..\tools\probe.mjs") "https://$($s.host)"
