# Casa & Terra · SecHUB

Primeira versão funcional do monitoramento de domínios empresariais. Node.js 24+, SQLite local e interface em português. Autenticação SAML com @node-saml/node-saml; instale as dependências com npm ci.

## Iniciar

```powershell
npm ci
Copy-Item .env.example .env
# Para prévia estritamente local, altere DEV_MODE=true no .env.
node --env-file-if-exists=.env server.mjs
```

Abra http://127.0.0.1:3000. O domínio inicial é casaeterra.com. Todos os agendamentos começam pausados; nenhuma verificação é iniciada durante a instalação. O modo local permite operar o sistema sem SSO somente em loopback, identifica essa condição na interface e não deve ser usado no servidor.

Para abrir diretamente a prévia local no PowerShell: `./run-local.ps1`. Na validação inicial de 09/10/2026, o domínio casaeterra.com foi verificado uma vez e seu agendamento diário foi ativado. A checagem HTTPS retornou `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, inclusive usando as CAs do Windows; isso exige investigar a cadeia apresentada ao coletor, sem desabilitar TLS. O coletor registrou DMARC `p=none` e ausência de SPF no hostname consultado, sujeitos à validação pelo responsável de email.

## Implementado

- Cadastro de até 100 domínios públicos; busca; intervalos de 1 a 168 horas.
- Execução manual e agendada de baseline DNS e HTTPS, histórico persistente e exportação JSON.
- DNS A/AAAA, MX, NS, TXT, SPF e DMARC. Avaliações de email são por hostname; confirmar política herdada e função de envio antes de tratar um achado como problema.
- Certificado TLS, expiração, protocolo negociado (mínimo TLS 1.2), status HTTP, headers HSTS/CSP/nosniff, proteção contra enquadramento e cookies Secure.
- Evidência e orientação por observação. Não armazena valores de cookies, assertions SAML ou respostas HTML dos alvos.
- Google Workspace via aplicação SAML: assinaturas da resposta e assertion, audiência, emissor, Recipient, validade, correlação InResponseTo, vínculo ao navegador e lista explícita de emails.
- Sessões opacas de 8h, hash do identificador no banco, proteção CSRF, validação de Host, headers de segurança e auditoria das alterações.
- Exportação de plano ZAP baseline passivo por domínio. Não executa Docker ou ZAP automaticamente.

## Habilitar Google Workspace por SAML

A integração é feita no **Google Admin Console**, em Apps > Apps da Web e para dispositivos móveis > Adicionar app > Adicionar app SAML personalizado.

É possível subir o site antes de criar a aplicação SAML. Deixe SAML_ENTRY_POINT, SAML_IDP_ISSUER e SAML_IDP_CERT_PATH vazios e DEV_MODE=false: a página de login e os metadados são acessíveis; o painel e a API protegida continuam bloqueados. Não configure GOOGLE_CLIENT_ID ou GOOGLE_CLIENT_SECRET: OAuth/OIDC foi substituído por SAML nesta versão.

Para https://sechub.casaeterra.com:

| Campo no Google | Valor |
| --- | --- |
| ACS URL | https://sechub.casaeterra.com/auth/saml/acs |
| Entity ID do SP | https://sechub.casaeterra.com/auth/saml/metadata |
| Resposta assinada | Habilitada (obrigatório) |
| Formato Name ID | EMAIL |
| Name ID | Informações básicas > Email principal |
| Start URL | Deixar vazio |

Depois copie a URL de SSO e o Entity ID **do Google**, baixe o certificado público e configure SAML_ENTRY_POINT, SAML_IDP_ISSUER e SAML_IDP_CERT_PATH no servidor. O Entity ID do Google é diferente do Entity ID do SecHUB. O certificado deve estar em PEM, legível pela conta sechub; sua chave privada nunca é necessária.

Autorize a aplicação para o grupo/OU escolhido e configure ALLOWED_EMAILS com os administradores. Reinicie o serviço e teste começando pelo botão de login no SecHUB. Apenas login iniciado pelo SP é aceito; o botão Testar login SAML no Admin Console e o lançamento direto pelo IdP não são suportados. Logout encerra a sessão local, sem encerrar a conta Google.

As sessões anteriores de OAuth são invalidadas na migração. O certificado é validado na inicialização e deve ser renovado antes de vencer. O teste real com o Workspace depende da aplicação criada pelo administrador.

Consulte [o roteiro Ubuntu e SAML](docs/SAML-UBUNTU.md) para comandos e configuração do serviço.

## Operação e limites

O processo deve permanecer em execução para cumprir a agenda. Instale como serviço no ambiente definitivo; a cada 30s o coletor verifica trabalhos vencidos. Após reinício, jobs em execução são marcados como interrompidos; agendas vencidas são retomadas. Limites: duas verificações simultâneas, um minuto entre execuções manuais do mesmo domínio, timeout HTTPS de 10s por salto e no máximo dois redirecionamentos no mesmo hostname. A resposta final HTTPS é avaliada, sem crawl no baseline nativo.

Endereços privados/reservados são bloqueados antes da conexão HTTPS; a conexão usa o IP público validado para evitar troca de resolução entre validação e acesso. Redirecionamentos para outro hostname não são seguidos. Não cadastra subdomínios automaticamente nem considera um domínio pai autorização para todos os subdomínios. DNS usa o resolvedor do sistema; não usa DNS público de terceiros configurado pela aplicação.

Falhas do coletor e ausência de headers são observações para investigação. O painel não calcula porcentagem de conformidade, não garante ausência de vulnerabilidades, não enumera todas as versões TLS e não faz validação completa de SPF/DMARC/DNSSEC. Sem notificações externas, integração SIEM, gestão de falsos positivos ou deduplicação entre execuções nesta versão. O painel mostra até 100 execuções recentes; o SQLite conserva o histórico completo.

## SQL injection e abuso de autenticação

Ainda **não implementados como testes executáveis**. O plano ZAP exportado contém crawl limitado e análise passiva; até um crawler GET pode acionar endpoints de uma aplicação mal projetada. Revise caminhos e exclusões antes de executá-lo.

Próxima fase: worker ZAP isolado com política ativa de SQL injection, parâmetros e caminhos explícitos, ambiente autorizado e limites de taxa/tempo; importação normalizada dos achados e revisão de falsos positivos. Para autenticação, configurar conta de teste e fluxos de login, MFA, sessão, enumeração e rate limiting. Não usar contas reais nem automatizar tentativas em massa. Testes ativos devem ser configurados por aplicação e janela operacional, preferencialmente em homologação.

Exemplo de execução do plano passivo com Docker já instalado, após revisar o arquivo baixado:

```powershell
docker run --rm -v "${PWD}:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap.sh -cmd -autorun /zap/wrk/zap-casaeterra.com.yaml
```

## Expansão AWS e DNS interno

Não há integração AWS ou coletor privado ativo. Contrato proposto:

- Coletores separados por zona de confiança (internet, rede corporativa, VPC), registro de identidade e envio autenticado das evidências.
- Inventário com `collector_id`, zona, resolvedores e escopo; permitir IPs privados apenas no worker interno e dentro dos CIDRs autorizados, preservando bloqueio de metadata e serviços de administração.
- AWS via IAM Role/STS de leitura, sem chaves estáticas: Security Hub CSPM (AWS FSBP/CIS), GuardDuty, Inspector e Route 53/Resolver. Configurar contas/regiões explícitas.
- API de ingestão autenticada, esquema versionado, fila durável, RBAC por equipe, alertas, retenção e trilha de auditoria em armazenamento externo antes de operação em escala.

## Implantação

SQLite em `data/sechub.sqlite`; proteja diretório, backups e `.env` com ACL restrita à conta do serviço. O banco armazena inventário, emails e evidências, sem criptografia própria em repouso; utilize volume criptografado no ambiente definitivo. Não exponha a pasta do projeto por servidor estático. Configure proxy reverso HTTPS sem cache, preserve Host/Origin e encaminhe à porta loopback. Não há trust automático em X-Forwarded-*.

Este MVP pressupõe uma única instância e administradores confiáveis. Antes da produção: configurar e validar SSO/TLS, serviço persistente, backups/retention, controles de acesso da infraestrutura e observabilidade. Não é uma implantação de produção concluída.

## Validar

```powershell
node --test tests/*.test.mjs
```

Testes locais cobrem rejeição de IPs privados, validação de respostas e assertions SAML assinadas, CSRF, acesso bloqueado sem SSO, Host, cadastro, duplicação, agenda, persistência e exportação. Não executam scans no domínio empresarial.

## Referências

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Google Workspace: aplicação SAML personalizada](https://knowledge.workspace.google.com/admin/apps/set-up-your-own-custom-saml-app)
- [AWS Security Hub CSPM: standards](https://docs.aws.amazon.com/securityhub/latest/userguide/standards-reference.html)

Paleta extraída dos estilos do [site oficial Casa & Terra](https://casaeterra.com/): azul-marinho `#0d2137`, vermelho `#e53935` e branco. A marca tipográfica do painel é uma composição local, não o arquivo oficial do logotipo.
