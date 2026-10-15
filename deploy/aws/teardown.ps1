<#
Remove everything provision.ps1 created (instance, Elastic IP, security group, key pair). Stops all charges.
#>
$ErrorActionPreference = "Continue"
$state = Join-Path $PSScriptRoot ".state.json"
if (-not (Test-Path $state)) { Write-Host "Nothing to tear down (no .state.json)."; return }
$s = Get-Content $state -Raw | ConvertFrom-Json
$env:AWS_DEFAULT_REGION = $s.region

if ($s.instance) {
  Write-Host "Terminating instance $($s.instance)..."
  aws ec2 terminate-instances --instance-ids $s.instance | Out-Null
  aws ec2 wait instance-terminated --instance-ids $s.instance
}
if ($s.alloc) { Write-Host "Releasing Elastic IP..."; aws ec2 release-address --allocation-id $s.alloc | Out-Null }
if ($s.sg) {
  Write-Host "Deleting security group..."
  for ($i = 0; $i -lt 6; $i++) { aws ec2 delete-security-group --group-id $s.sg 2>$null; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep 10 }
}
if ($s.key) { Write-Host "Deleting key pair..."; aws ec2 delete-key-pair --key-name $s.key | Out-Null; if ($s.keyPath) { Remove-Item $s.keyPath -Force -ErrorAction SilentlyContinue } }
Remove-Item $state -Force
Write-Host "Done. Nothing from this deployment remains in your AWS account."
