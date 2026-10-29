# Rede interna e AWS — SecHUB 0.4

## Módulos e configuração inicial

As abas **Domínios internos**, **AWS** e **Coletores** usam um worker separado da aplicação e do ZAP público. O painel registra configurações, autentica administradores por SAML e envia trabalhos ao coletor; não abre conexões com alvos privados nem recebe credenciais AWS.

Escopo corporativo autorizado para esta instalação:

- Sufixo DNS: `casaeterra.com` (o domínio e nomes terminados em `.casaeterra.com`).
- CIDR: `10.4.0.0/24`.
- Resolvedor: `10.4.0.6`.
- AWS preparada para `us-east-1` e `sa-east-1`; nenhuma conta está ativada inicialmente.

Os hosts internos e as conexões AWS são cadastrados separadamente do inventário público. Todos os agendamentos começam pausados. A instalação não inicia scans, enumera CIDRs, ativa serviços AWS ou cria recursos na nuvem.

## Instalação do coletor corporativo

Pré-requisitos: Debian/Ubuntu, SecHUB atualizado em `/opt/sechub`, Node 24 em `/opt/node24/bin/node`, aplicação já iniciada uma vez para criar as novas tabelas e conta `sechub`. Faça backup consistente do SQLite e registre o commit anterior antes da atualização do aplicativo.

```bash
cd /opt/sechub
/opt/node24/bin/node --test tests/*.test.mjs
sudo bash deploy/install-collector.sh
sudo systemctl status sechub-collector --no-pager
```

O instalador cria o usuário sem login `sechub-collector`, instala código root-owned em `/usr/local/lib/sechub-collector` e registra a identidade do coletor no banco usando a conta da aplicação. O token é gerado localmente, nunca é impresso, e fica em `/etc/sechub-collector.env` com modo 0600. O painel armazena somente o hash do token. A configuração SAML existente não é modificada.

A política local fica em `/etc/sechub-collector/policy.json`, root-owned e legível somente pelo grupo do coletor. O instalador não sobrescreve a política ou o token em atualizações. A política é relida entre trabalhos; alterações de token/ambiente exigem reinício do serviço.

```json
{
  "internal": {
    "suffixes": ["casaeterra.com"],
    "cidrs": ["10.4.0.0/24"],
    "dnsServers": ["10.4.0.6"],
    "blockedCidrs": []
  },
  "aws": {
    "sourceProfiles": ["sechub-source"],
    "roleArns": [],
    "regions": ["us-east-1", "sa-east-1"],
    "cliPath": "/opt/aws-cli/v2/current/bin/aws"
  }
}
```

Para outro coletor/VPC, registre uma identidade na aba **Coletores** e copie o token mostrado uma única vez para o ambiente do serviço instalado naquela rede. Configure uma política própria, a origem HTTPS do painel e o Node 24. Não reutilize o mesmo token entre máquinas. A aplicação pode revogar um coletor pelo painel; o worker cancela a execução ao perder sua concessão.

## Monitoramento interno

Na aba **Domínios internos**, cadastre o hostname completo e escolha o coletor. **Verificar** enfileira uma execução. **Agendar** ativa a coleta recorrente de 24 horas; a API também aceita intervalos de 1–168 horas. O resultado de cada execução fica disponível no histórico, inclusive falhas e resultados parciais.

O worker consulta somente A/AAAA no DNS explícito. Não consulta TXT, SPF ou DMARC para avaliar hosts internos. Cada conexão HTTPS usa o endereço validado, com porta fixa 443, TLS 1.2+ e validação de certificado. Em cada redirecionamento, revalida DNS e escopo; não segue outro hostname ou protocolo. Certificados corporativos exigem uma CA confiável, configurável no ambiente por `NODE_EXTRA_CA_CERTS` apontando a um arquivo root-owned; não desligue a validação TLS.

Permite apenas endereços RFC1918 e IPv6 ULA dentro dos CIDRs locais. Respostas públicas, privadas fora do escopo, misturas público/privado e falhas transitórias do DNS bloqueiam a conexão. Bloqueia loopback, link-local, metadata (incluindo `fd00:ec2::/32`), IPs do próprio coletor, os servidores DNS e `blockedCidrs`. Adicione IPs de equipamentos de administração a `blockedCidrs` antes de cadastrá-los como alvos. Não há port scan, descoberta de rede ou ZAP interno nesta versão. O ZAP público continua bloqueando endereços privados.

## AWS: configurar IAM posteriormente

1. Na conta AWS, crie uma Role de leitura e anexe a política que o painel disponibiliza em **AWS → Baixar política IAM de leitura** (`deploy/aws-readonly-policy.json`). Ela permite somente as operações usadas pelo coletor; não concede escrita. A trust policy da Role deve aceitar somente a identidade de origem escolhida, com External ID se necessário.
2. Configure no coletor um perfil de origem `sechub-source`, usando IAM Identity Center/SSO, IAM Role ou `credential_process` que entregue credenciais temporárias. A identidade de origem precisa de `sts:AssumeRole` limitado ao ARN da Role de destino. Não use permissões amplas de administração.
3. Instale o AWS CLI v2 oficial quando for conectar a conta:

   ```bash
   cd /opt/sechub
   sudo bash deploy/install-aws-cli.sh
   ```

4. O serviço usa `HOME=/var/lib/sechub-collector`, `AWS_CONFIG_FILE=/var/lib/sechub-collector/.aws/config` e o cache SSO em `.aws/sso/cache`. Configure/autentique o perfil como o usuário do serviço, no terminal do operador:

   ```bash
   sudo -u sechub-collector env HOME=/var/lib/sechub-collector \
     /opt/aws-cli/v2/current/bin/aws configure sso --profile sechub-source
   sudo -u sechub-collector env HOME=/var/lib/sechub-collector \
     /opt/aws-cli/v2/current/bin/aws sso login --profile sechub-source --use-device-code
   ```

   SSO requer renovação quando a sessão expira; o painel informará a falha. Para coleta contínua, prefira identidade de workload/Role apropriada ao ambiente. O agente não precisa conhecer senhas nem tokens de login do operador.

5. Autorize o ARN exato em `aws.roleArns` da política local. A tela **Coletores** mostrará o escopo anunciado no próximo contato. A política local é um limite adicional às permissões IAM, não as substitui.
6. Na aba **AWS**, use **Configurar conta**: nome, Account ID de 12 dígitos, Role ARN, perfil, External ID opcional e regiões. O nome/alias da conta não substitui o Account ID numérico. A conexão pode ser salva antecipadamente; a coleta fica bloqueada enquanto a Role não estiver autorizada no coletor. Só depois use **Coletar** ou ative a agenda.

Para cada trabalho, o worker solicita uma sessão STS de 15 minutos, verifica `GetCallerIdentity` e rejeita conta diferente antes de acessar serviços. Consulta Security Hub com filtros de conta, região e achados ativos; isso evita misturar regiões agregadas do Security Hub. Consulta GuardDuty e Inspector na região explícita, zonas Route 53 uma única vez por conta e endpoints Route 53 Resolver por região. O inventário não importa TXT/segredos DNS ou inicia scans dos nomes encontrados.

A paginação do AWS CLI é limitada a 200 itens por operação, página de 50 itens, com no máximo 1.000 achados e 1.000 recursos por relatório. Limites são informados. Erros de permissão e serviços não habilitados aparecem por fonte/região; não viram um resultado vazio considerado saudável. Nenhum Security Hub, GuardDuty ou Inspector é habilitado automaticamente. Os serviços AWS têm suas próprias regras de cobrança.

Credenciais temporárias são mantidas somente na memória do worker e no ambiente do processo AWS CLI, nunca em argumentos, resultados, banco do painel ou logs. Endpoints AWS personalizados herdados são desativados. Não há formulário de access key/secret key no site. Os achados de cada serviço são identificados pela origem; pode haver duplicação semântica entre Security Hub, GuardDuty e Inspector. A integração não calcula certificação ou percentual de conformidade.

## Fila, autenticação e limites

O coletor inicia conexões HTTPS com o painel, sem porta de entrada própria. Os endpoints `/api/collector/*` aceitam somente o bearer token do coletor, separado das sessões SAML/CSRF dos administradores. Cada trabalho tem concessão aleatória, vinculada ao coletor, com validade de 90 segundos e heartbeat a cada 15 segundos. O prazo máximo é 10 minutos. Resultado atrasado, de outro coletor ou reapresentado é rejeitado. Falha de comunicação aborta o trabalho; o painel registra interrupção ao expirar a concessão, sem repetir automaticamente uma execução possivelmente ainda em andamento.

Um trabalho por coletor; até 20 pendentes, com intervalo mínimo de um minuto por ativo. O botão **Cancelar** cancela imediatamente a fila e solicita abortar uma execução ativa no próximo heartbeat. Trabalhos pendentes persistem após reinício. O servidor não redefine como interrompidos jobs ativos com concessão ainda válida durante uma reinicialização curta.

O painel armazena resultados normalizados. O resumo carrega contagens e cobertura; achados e inventário completos são consultados por execução. Erros de conexão, TLS ou permissão não comprovam vulnerabilidade. Revise os achados antes de tomar ações.

## Diagnóstico e rollback

Confira `systemctl status sechub sechub-collector`, `journalctl -u sechub-collector`, conectividade ao DNS/painel, CA, política local e sessão SSO. Logs registram IDs/estados, sem o token, respostas AWS brutas ou credenciais. Mantenha `/etc/sechub-collector.env` restrito e não exponha `/var/lib/sechub-collector` pelo Nginx.

Para desativar, pause as agendas e revogue o coletor pelo painel; depois pare/desabilite `sechub-collector`. Para rollback do código, pare o aplicativo, volte ao commit anterior e inicie novamente. As migrações são aditivas e preservam o histórico público/ZAP. Guarde o backup; não apague o banco nem credenciais de outros serviços.

## Validação e referências

Os testes cobrem CIDRs, metadata, DNS misto, hostname/sufixo, escopo público preservado, filas, leases, cancelamento, revogação, CSRF, leitura de resultados, conta/região AWS, paginação e falhas por fonte. DNS e AWS são simulados; autenticação em uma conta real só pode ser validada depois do bootstrap IAM.

- [AWS CLI — paginação Security Hub](https://docs.aws.amazon.com/cli/latest/reference/securityhub/get-findings.html)
- [AWS CLI — GuardDuty](https://docs.aws.amazon.com/cli/latest/reference/guardduty/list-detectors.html)
- [AWS CLI — zonas Route 53](https://docs.aws.amazon.com/cli/latest/reference/route53/list-hosted-zones.html)
- [AWS CLI v2 — instalação oficial](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
