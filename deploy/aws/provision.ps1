<#
Provision Blastradius on one small EC2 instance (Ubuntu 24.04, Docker, Caddy HTTPS on <ip>.sslip.io).
Needs: AWS CLI logged in (`aws login`), and the repository pushed to GitHub (the instance clones it).
Creates: key pair, security group (80/443 open, 22 only from your IP), Elastic IP, 1 EC2 instance, encrypted 20 GB disk.
Writes deploy/aws/.state.json so teardown.ps1 can remove everything.

  ./provision.ps1                       # ap-south-1, t3.small
  ./provision.ps1 -Region us-east-1 -InstanceType t3.medium
  $env:GEMINI_API_KEY = "..."           # optional, passed to the server
#>
param(
  [string]$Region = "ap-south-1",
  [string]$InstanceType = "t3.small",
  [string]$Name = "blastradius",
  [string]$RepoUrl = "https://github.com/NishaadG/blastradius.git"
)
$ErrorActionPreference = "Stop"
$env:AWS_DEFAULT_REGION = $Region
$state = Join-Path $PSScriptRoot ".state.json"
if (Test-Path $state) { throw "A deployment already exists ($state). Run teardown.ps1 first, or use update.ps1." }

function Aws { $out = & aws @args; if ($LASTEXITCODE -ne 0) { throw "aws $($args -join ' ') failed" }; $out }
function Json($obj, $name) { $p = Join-Path $env:TEMP $name; ($obj | ConvertTo-Json -Depth 10) | Set-Content -Encoding ascii $p; "file://$($p -replace '\\','/')" }

Write-Host "Checking AWS credentials..."
$who = Aws sts get-caller-identity --query Arn --output text
Write-Host "  signed in as $who (region $Region)"

$ami = Aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text
$vpc = Aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query "Vpcs[0].VpcId" --output text
if (-not $vpc -or $vpc -eq "None") { throw "No default VPC in $Region. Create one or choose another region." }
$myIp = (Invoke-RestMethod https://checkip.amazonaws.com).Trim()

$created = @{ region = $Region; name = $Name }
try {
  $keyPath = Join-Path $HOME ".ssh\$Name-$Region.pem"
  New-Item -ItemType Directory -Force (Split-Path $keyPath) | Out-Null
  Aws ec2 create-key-pair --key-name $Name --query KeyMaterial --output text | Out-File -Encoding ascii $keyPath
  icacls $keyPath /inheritance:r /grant:r "$($env:USERNAME):R" | Out-Null
  $created.key = $Name; $created.keyPath = $keyPath

  $sg = Aws ec2 create-security-group --group-name $Name --description "Blastradius web" --vpc-id $vpc --query GroupId --output text
  $created.sg = $sg
  $perms = @(
    @{ IpProtocol = "tcp"; FromPort = 80;  ToPort = 80;  IpRanges = @(@{ CidrIp = "0.0.0.0/0"; Description = "http (redirects to https)" }) },
    @{ IpProtocol = "tcp"; FromPort = 443; ToPort = 443; IpRanges = @(@{ CidrIp = "0.0.0.0/0"; Description = "https" }) },
    @{ IpProtocol = "tcp"; FromPort = 22;  ToPort = 22;  IpRanges = @(@{ CidrIp = "$myIp/32"; Description = "ssh from deployer only" }) }
  )
  Aws ec2 authorize-security-group-ingress --group-id $sg --ip-permissions (Json $perms "br-perms.json") | Out-Null

  $alloc = Aws ec2 allocate-address --domain vpc --query AllocationId --output text
  $created.alloc = $alloc
  $ip = Aws ec2 describe-addresses --allocation-ids $alloc --query "Addresses[0].PublicIp" --output text
  $hostName = ($ip -replace '\.', '-') + ".sslip.io"

  $chars = (48..57) + (65..90) + (97..122) | ForEach-Object { [char]$_ }
  $pw = -join (1..40 | ForEach-Object { $chars | Get-Random })
  $gemini = ""
  if ($env:GEMINI_API_KEY) { $gemini = $env:GEMINI_API_KEY }
  $ud = (Get-Content (Join-Path $PSScriptRoot "user-data.sh.tpl") -Raw) `
        -replace '@@REPO@@', $RepoUrl -replace '@@HOST@@', $hostName -replace '@@PASSWORD@@', $pw -replace '@@GEMINI@@', $gemini
  $udPath = Join-Path $env:TEMP "br-userdata.sh"
  [IO.File]::WriteAllText($udPath, ($ud -replace "`r`n", "`n"))

  $bdm = @(@{ DeviceName = "/dev/sda1"; Ebs = @{ VolumeSize = 20; VolumeType = "gp3"; Encrypted = $true; DeleteOnTermination = $true } })
  $tags = @(@{ ResourceType = "instance"; Tags = @(@{ Key = "Name"; Value = $Name }, @{ Key = "Project"; Value = "blastradius" }) })
  $inst = Aws ec2 run-instances --image-id $ami --instance-type $InstanceType --key-name $Name --security-group-ids $sg `
      --user-data "file://$($udPath -replace '\\','/')" --metadata-options "HttpTokens=required,HttpEndpoint=enabled,HttpPutResponseHopLimit=1" `
      --block-device-mappings (Json $bdm "br-bdm.json") --tag-specifications (Json $tags "br-tags.json") `
      --query "Instances[0].InstanceId" --output text
  $created.instance = $inst
  Write-Host "Launched $inst, waiting for it to run..."
  Aws ec2 wait instance-running --instance-ids $inst
  Aws ec2 associate-address --instance-id $inst --allocation-id $alloc | Out-Null

  $created.ip = $ip; $created.host = $hostName
  $created | ConvertTo-Json | Set-Content -Encoding ascii $state
  Write-Host ""
  Write-Host "Deployed. It takes ~8-12 minutes to build and start."
  Write-Host "  URL:      https://$hostName"
  Write-Host "  Watch:    ssh -i `"$keyPath`" ubuntu@$ip `"sudo tail -f /var/log/cloud-init-output.log`""
  Write-Host "  Verify:   node tools/probe.mjs https://$hostName"
  Write-Host "  Tear down: ./deploy/aws/teardown.ps1"
} catch {
  Write-Warning "Provisioning failed: $_"
  Write-Warning "Cleaning up what was created so far..."
  $created | ConvertTo-Json | Set-Content -Encoding ascii $state
  & (Join-Path $PSScriptRoot "teardown.ps1")
  throw
}
