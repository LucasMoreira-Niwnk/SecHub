#!/bin/bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Execute com sudo.'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl unzip ca-certificates
case "$(uname -m)" in x86_64) architecture=x86_64;; aarch64) architecture=aarch64;; *) echo 'Arquitetura não suportada'; exit 1;; esac
task_dir="$(mktemp -d /tmp/sechub-awscli.XXXXXXXX)"
[[ $task_dir == /tmp/sechub-awscli.* ]] || exit 1
trap 'rm -rf -- "$task_dir"' EXIT
curl --fail --show-error --silent --proto '=https' --tlsv1.2 "https://awscli.amazonaws.com/awscli-exe-linux-${architecture}.zip" -o "$task_dir/awscliv2.zip"
unzip -q "$task_dir/awscliv2.zip" -d "$task_dir"
"$task_dir/aws/install" --install-dir /opt/aws-cli --bin-dir /usr/local/bin --update
/opt/aws-cli/v2/current/bin/aws --version
