#!/bin/bash
set -euo pipefail
if [[ $EUID != 0 ]]; then echo 'Execute com sudo bash deploy/install-zap.sh'; exit 1; fi
project="$(cd -- "$(dirname -- "$0")/.." && pwd)"
[[ -f /etc/sechub.env && -x /opt/node24/bin/node ]] || { echo 'Instalação existente do SecHUB não encontrada.'; exit 1; }
getent passwd sechub >/dev/null
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io iptables
systemctl enable --now docker
docker network inspect sechub-zap >/dev/null 2>&1 || docker network create --driver bridge --opt com.docker.network.bridge.name=sechubzap0 sechub-zap
docker pull ghcr.io/zaproxy/zaproxy:stable
image="$(docker image inspect ghcr.io/zaproxy/zaproxy:stable --format '{{index .RepoDigests 0}}')"
[[ $image =~ ^ghcr.io/zaproxy/zaproxy@sha256:[a-f0-9]{64}$ ]] || { echo 'Digest inválido'; exit 1; }
/opt/node24/bin/node "$project/deploy/check-zap-plans.mjs" "$image"
install -d -o root -g sechub -m 0770 /var/spool/sechub-zap
install -d -o root -g root -m 0701 /var/lib/sechub-zap-worker
install -d -o root -g root -m 0755 /usr/local/lib/sechub-zap/{worker,lib,deploy}
install -d -o root -g root -m 0755 /etc/sechub-zap
install -o root -g root -m 0644 "$project/worker/zap-worker.mjs" /usr/local/lib/sechub-zap/worker/
install -o root -g root -m 0644 "$project/lib/zap.mjs" "$project/lib/zap-scope.mjs" "$project/lib/security.mjs" /usr/local/lib/sechub-zap/lib/
install -o root -g root -m 0755 "$project/deploy/zap-firewall.sh" /usr/local/lib/sechub-zap/deploy/
if [[ ! -e /etc/sechub-zap/policy.json ]]; then
  printf '{"image":"%s","allowedRoots":["casaeterra.com"],"activeEnabled":true}\n' "$image" > /etc/sechub-zap/policy.json
  chmod 0644 /etc/sechub-zap/policy.json
else
  echo 'Política existente preservada; confira o digest e os domínios em /etc/sechub-zap/policy.json.'
fi
install -o root -g root -m 0644 "$project/deploy/sechub-zap-worker.service" /etc/systemd/system/
install -d -m 0755 /etc/systemd/system/sechub.service.d
printf '[Service]\nReadWritePaths=/var/spool/sechub-zap\n' > /etc/systemd/system/sechub.service.d/zap.conf
# Preserve every SAML setting and secret; change only the worker spool setting.
cp -p /etc/sechub.env /etc/sechub.env.before-zap
sed -i '/^ZAP_SPOOL_DIR=/d' /etc/sechub.env
printf '\nZAP_SPOOL_DIR=/var/spool/sechub-zap\n' >> /etc/sechub.env
systemctl daemon-reload
systemctl enable --now sechub-zap-worker
systemctl restart sechub-zap-worker
systemctl restart sechub
systemctl is-active sechub sechub-zap-worker
echo 'Integração instalada. Nenhum scan foi disparado. Política: casaeterra.com e seus subdomínios; teste ativo exige URLs e autorização por trabalho.'
