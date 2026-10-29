#!/bin/bash
set -euo pipefail
[[ $EUID == 0 && $# == 1 && $1 =~ ^10\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Use sudo bash deploy/install-ad-collector.sh IP_PRIVADO_AUTORIZADO'; exit 1; }
project="$(cd -- "$(dirname -- "$0")/.." && pwd)"
apt-get update -qq
apt-get install -y python3-venv ca-certificates
getent passwd sechub-ad >/dev/null || useradd --system --user-group --home-dir /var/lib/sechub-ad --create-home --shell /usr/sbin/nologin sechub-ad
install -d -o root -g root -m 0755 /usr/local/lib/sechub-ad
if [[ ! -x /usr/local/lib/sechub-ad/venv/bin/python ]]; then python3 -m venv /usr/local/lib/sechub-ad/venv; fi
/usr/local/lib/sechub-ad/venv/bin/pip install --disable-pip-version-check 'pywinrm==0.5.0'
install -o root -g root -m 0644 "$project/worker/"{ad_collector.py,ad-events.ps1} /usr/local/lib/sechub-ad/
install -d -o root -g sechub-ad -m 0750 /etc/sechub-ad
install -d -o sechub-ad -g sechub-ad -m 0700 /var/lib/sechub-ad
if [[ ! -f /etc/sechub-ad/credentials.json ]]; then
  printf '{\n  "enabled": false,\n  "endpoint": "http://%s:5985/wsman",\n  "username": "",\n  "password": ""\n}\n' "$1" > /etc/sechub-ad/credentials.json
  chown root:sechub-ad /etc/sechub-ad/credentials.json
  chmod 0640 /etc/sechub-ad/credentials.json
fi
/opt/node24/bin/node "$project/deploy/register-ad-collector.mjs" "$1"
install -o root -g root -m 0644 "$project/deploy/sechub-ad.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sechub-ad
systemctl restart sechub-ad
echo 'Instalado. Preencha /etc/sechub-ad/credentials.json e altere enabled para true.'
echo 'A configuração é relida automaticamente. Consulte docs/ACTIVE-DIRECTORY.md.'
