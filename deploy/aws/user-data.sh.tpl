#!/bin/bash
# Runs once at first boot (cloud-init). Installs Docker, fetches the public repo, seeds the graphs from the committed
# snapshot (no internet data needed), and starts the HTTPS stack. Log: /var/log/cloud-init-output.log
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# swap: the Next.js image build is memory hungry on a 2 GB box
fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

apt-get update -y
apt-get install -y ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

git clone --depth 1 @@REPO@@ /opt/blastradius
cd /opt/blastradius/deploy
umask 077
cat > .env <<'EOF'
SITE_ADDRESS=@@HOST@@
FALKOR_PASSWORD=@@PASSWORD@@
GEMINI_API_KEY=@@GEMINI@@
GITHUB_TOKEN=
EOF
umask 022

docker compose -f docker-compose.prod.yml up -d --build falkordb
docker compose -f docker-compose.prod.yml --profile seed run --rm --build seed
docker compose -f docker-compose.prod.yml up -d --build
echo "BLASTRADIUS-DEPLOY-COMPLETE"
