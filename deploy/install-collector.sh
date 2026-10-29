#!/bin/bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Execute com sudo bash deploy/install-collector.sh'; exit 1; }
project="$(cd -- "$(dirname -- "$0")/.." && pwd)"
[[ -x /opt/node24/bin/node && -f /etc/sechub.env ]] || { echo 'SecHUB não encontrado.'; exit 1; }
getent passwd sechub-collector >/dev/null || useradd --system --user-group --home-dir /var/lib/sechub-collector --create-home --shell /usr/sbin/nologin sechub-collector
install -d -o root -g root -m 0755 /usr/local/lib/sechub-collector/{lib,worker}
install -o root -g root -m 0644 "$project/worker/collector.mjs" /usr/local/lib/sechub-collector/worker/
install -o root -g root -m 0644 "$project/lib/"{scanner,security,internal-scope,aws-collector}.mjs /usr/local/lib/sechub-collector/lib/
install -d -o sechub-collector -g sechub-collector -m 0700 /var/lib/sechub-collector /var/lib/sechub-collector/.aws
install -d -o root -g sechub-collector -m 0750 /etc/sechub-collector
if [[ ! -f /etc/sechub-collector/policy.json ]]; then
  cat > /etc/sechub-collector/policy.json <<'POLICY'
{
  "internal": {"suffixes":["casaeterra.com"],"cidrs":["10.4.0.0/24"],"dnsServers":["10.4.0.6"],"blockedCidrs":[]},
  "aws": {"sourceProfiles":["sechub-source"],"roleArns":[],"regions":["us-east-1","sa-east-1"],"cliPath":"/opt/aws-cli/v2/current/bin/aws"}
}
POLICY
  chown root:sechub-collector /etc/sechub-collector/policy.json
  chmod 0640 /etc/sechub-collector/policy.json
fi
/opt/node24/bin/node "$project/deploy/register-local-collector.mjs"
install -o root -g root -m 0644 "$project/deploy/sechub-collector.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sechub-collector
systemctl restart sechub-collector
systemctl is-active sechub-collector
echo 'Coletor instalado. Nenhum host é escaneado e nenhuma conta AWS é ativada automaticamente.'
echo 'AWS: configure a Role, o perfil de origem e a allowlist antes de coletar. Veja docs/COLETORES-AWS.md.'
