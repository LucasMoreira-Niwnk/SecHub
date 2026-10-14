# Casa & Terra · SecHUB

Primeira versão funcional do monitoramento de domínios empresariais. Node.js 24+, SQLite local e interface em português. Sem dependências npm externas.

## Iniciar

```powershell
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
- Evidência e orientação por observação. Não armazena valores de cookies, tokens OAuth ou respostas HTML dos alvos.
- Google Workspace via OpenID Connect: código de autorização, PKCE, state vinculado ao navegador, nonce, assinatura RS256 com JWKS Google, emissor, audience, validade, email verificado, `hd` e lista explícita de usuários.
- Sessões opacas de 8h, hash do identificador no banco, proteção CSRF, validação de Host, headers de segurança e auditoria das alterações.
- Exportação de plano ZAP baseline passivo por domínio. Não executa Docker ou ZAP automaticamente.

## Habilitar Google Workspace

1. No projeto Google Cloud da empresa, configure a tela de consentimento para uso interno da organização.
2. Crie um cliente OAuth do tipo Aplicativo da Web.
3. Cadastre exatamente `https://SEU-HOST/auth/callback` como URI de redirecionamento. Para desenvolvimento local, use `http://127.0.0.1:3000/auth/callback`.
4. Preencha `.env` no servidor: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `WORKSPACE_DOMAIN=casaeterra.com`, `ALLOWED_EMAILS=administrador@casaeterra.com`. Não coloque segredos no repositório ou no frontend.
5. Defina `DEV_MODE=false`, `APP_URL` com a origem HTTPS definitiva e `HOST=127.0.0.1` atrás de proxy reverso.
6. Reinicie o serviço e valide o login com um administrador da lista e a rejeição de uma conta não autorizada.

Todos os emails em ALLOWED_EMAILS têm permissão de administrador neste MVP. O login real depende das credenciais e não foi validado com a organização. A aplicação só solicita `openid email profile`, sem acesso a Gmail ou Drive. A autenticação do painel não autentica o scanner nas aplicações alvo.

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

Testes locais cobrem rejeição de IPs privados, validação de identidade/assinatura Google, CSRF, acesso bloqueado sem SSO, Host, cadastro, duplicação, agenda, persistência e exportação. Não executam scans no domínio empresarial.

## Referências

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [AWS Security Hub CSPM: standards](https://docs.aws.amazon.com/securityhub/latest/userguide/standards-reference.html)

Paleta extraída dos estilos do [site oficial Casa & Terra](https://casaeterra.com/): azul-marinho `#0d2137`, vermelho `#e53935` e branco. A marca tipográfica do painel é uma composição local, não o arquivo oficial do logotipo.
