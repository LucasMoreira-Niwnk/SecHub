# Integração ZAP (0.3)

## Operação

Na aba **ZAP**, escolha um host exato ou use o botão ZAP no inventário. O baseline visita páginas por até um minuto e faz análise passiva, com profundidade 2 e sem envio de formulários. Crawlers GET podem acionar efeitos em aplicações mal projetadas. Não segue outros hosts. É executado manualmente; a agenda DNS/HTTPS existente não dispara ZAP.

Use **Buscar alvo** para filtrar o seletor de hosts e **Configurar scan** para abrir o formulário do host escolhido. O seletor ocupa o mesmo espaço independentemente do tamanho do inventário. No histórico, clique em uma execução concluída para abrir somente os achados daquele scan, com tipo e data de conclusão; **Voltar ao histórico** preserva a busca. A mesma navegação está disponível no histórico DNS/HTTPS. A aba geral **Achados** continua reunindo os últimos resultados por host e modo.

O modo **SQL injection** usa somente a regra 40018, intensidade Low, um thread e intervalo de 500 ms entre requisições. Não usa spider: envia GET às 1–5 URLs informadas, testa apenas seus parâmetros de consulta e restringe o contexto aos caminhos e nomes de parâmetros indicados. Exemplo em homologação: `/busca?q=exemplo`. URLs de logout/exclusão/pagamento e parâmetros com nomes de credenciais são rejeitados. Não é uma validação completa de SQL injection. Todos os demais scanners ativos ficam desligados. Não implementa abuso de autenticação nem scans autenticados.

Para o modo ativo, informe início e fim de uma janela de até quatro horas e confirme a autorização. O worker verifica a janela novamente ao iniciar e encerra no seu fim. Horários do formulário usam o fuso do navegador, persistidos como UTC. Um trabalho futuro não bloqueia baseline de outro host. A autorização por hostname não implica autorização de serviços de terceiros encontrados em links.

Fila máxima: 20 trabalhos, uma execução ZAP por vez e intervalo mínimo de um minuto por host. Cada contêiner usa no máximo 1 CPU, 2 GiB de memória e 256 processos. Limite externo: 12 minutos; plano: 10 minutos; scan ativo: 5 minutos, 2 minutos por regra. É possível cancelar trabalhos na fila ou em execução. Filas persistem no SQLite. Reinício do painel não redispara um job já entregue. Reinício do worker encerra contêineres antigos e registra interrupção; entregas não iniciadas em 60 segundos expiram. Worker ausente aparece como indisponível no painel.

Os achados do último baseline nativo e do último ZAP de **cada modo** aparecem em Achados por host, mesmo após sair das últimas 100 entradas do histórico. Resultados ZAP começam com revisão pendente: confirme ou marque falso positivo, com justificativa. A revisão é auditada e vinculada à execução, sem suprimir automaticamente achados futuros. Falsos positivos não entram no indicador de prioridade alta. Ausência de alertas não comprova segurança. Não são armazenados HTML das respostas, payloads, cookies ou valores de parâmetros dos alertas; URLs iniciais do trabalho permanecem no histórico, portanto não inclua dados confidenciais.

## Arquitetura e escopo

O painel continua na conta `sechub`, sem grupo Docker ou sudo. Publica JSON na fila `/var/spool/sechub-zap`; o worker valida independentemente identificador, escopo, janela e DNS. O worker de controle usa root somente para administrar Docker e firewall, com código instalado e protegido em `/usr/local/lib/sechub-zap`. O ZAP roda como UID 1000, sem capabilities, sem privilégio adicional, filesystem somente leitura e sem volumes do aplicativo/banco/configuração.

Imagem oficial fixada por digest em `/etc/sechub-zap/policy.json`. A política inicial permite `casaeterra.com` e subdomínios exatos selecionados no inventário. `activeEnabled` controla a disponibilidade de testes ativos; cada trabalho ativo exige autorização própria. Outros domínios exigem atualização administrativa de `allowedRoots`, seguida de reinício do worker. O cadastro no painel não altera essa política.

Rede Docker dedicada `sechub-zap`, bridge `sechubzap0`. O host é resolvido antes de cada execução: qualquer endereço privado/reservado ou mistura público/privado bloqueia o trabalho. Esta versão exige IPv4 público; o IPv4 escolhido é fixado no hosts do contêiner. DNS externo fica bloqueado. A chain `SECHUB_ZAP` em `DOCKER-USER` permite somente TCP 443 ao IP escolhido, bloqueando o restante; INPUT bloqueia o acesso do contêiner ao próprio servidor. A política default da rede é bloquear, restaurada após cada trabalho. Não há portas ZAP publicadas. Docker reiniciado interrompe o worker e requer confirmação de que ambos os serviços voltaram; use `systemctl restart sechub-zap-worker` se necessário.

O plano exportado é JSON válido como YAML 1.2. Executá-lo externamente não reproduz o isolamento de rede oferecido pelo worker.

## Instalação em Debian 12 / Ubuntu

Requer o SecHUB existente em `/opt/sechub`, Node 24 em `/opt/node24/bin/node`, serviço `sechub`, conta `sechub` e ambiente `/etc/sechub.env`. Instala Docker e iptables pelo repositório do sistema. A instalação não altera Nginx, certificado ou as configurações SAML.

Antes de trocar a versão, faça backup consistente do SQLite com a aplicação parada (ou pela API online de backup do SQLite), e registre o commit anterior. Não copie só o `.sqlite` de um banco em WAL enquanto está escrevendo.

```bash
cd /opt/sechub
# Atualize o checkout para o commit da integração, com a árvore limpa.
/opt/node24/bin/node --test tests/*.test.mjs
sudo bash deploy/install-zap.sh
sudo systemctl status sechub sechub-zap-worker --no-pager
sudo journalctl -u sechub-zap-worker -n 40 --no-pager
curl --resolve sechub.casaeterra.com:443:127.0.0.1 https://sechub.casaeterra.com/health
```

O instalador preserva a política existente e todas as configurações SAML. Cria `/etc/sechub.env.before-zap`, adiciona apenas `ZAP_SPOOL_DIR` e uma permissão systemd de escrita para o spool. Não altera o modo de login nem dispara scans. Não atualiza automaticamente um digest já configurado. Revise a política e atualize a imagem de forma controlada em manutenções futuras.

## Diagnóstico e rollback

Confira serviços, `/var/spool/sechub-zap/status.json`, espaço em disco, `docker image inspect`, `iptables -S SECHUB_ZAP` e `iptables -S INPUT`. Logs do worker registram apenas IDs e estados, sem respostas HTTP. O banco e as credenciais SAML continuam em seus diretórios restritos. Não exponha o spool pelo Nginx.

Para desativar: cancele trabalhos pendentes pelo painel, pare/desabilite `sechub-zap-worker`, remova `ZAP_SPOOL_DIR` de `/etc/sechub.env` e reinicie `sechub`. Para voltar o código, pare `sechub`, volte ao commit anterior e inicie novamente. As migrações são aditivas; não é necessário restaurar ou apagar o banco. Preserve o backup e o histórico de auditoria. Não remova Docker, redes ou regras compartilhadas por outros serviços.

## Validação do runtime

Validado em Debian 12 com ZAP 2.17.0 e Java 17, imagem `ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6`. A heap é limitada pelo argumento `zap.sh -Xmx1200m`; essa imagem não aplica `JAVA_OPTS` para esse fim. O contêiner recebe hostname local e diretórios de preferências temporários, e o plano permanece legível mesmo sob UMask 0027 do systemd.

`deploy/check-zap-plans.mjs` valida os dois planos sem rede. `deploy/smoke-zap.mjs` executa ambos contra uma aplicação HTTPS descartável em uma rede Docker interna, sem acesso externo: confirma detecção da falha SQLi simulada, importação do relatório e ausência de POST ou caminhos não autorizados. Exige root e o digest da imagem como argumento. O alvo e a rede de teste são removidos ao terminar. Não usa sistemas empresariais como alvo.

O contexto ZAP compara caminhos sem query string. No modo ativo, o contexto contém caminhos exatos; a lista inicial de URLs determina os parâmetros testados. Crawling, parâmetros adicionais, corpos, headers e cookies ficam desabilitados. O teste real do runtime cobre esse contrato, além dos testes Node.

## Referências

- [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Scanner ativo e definição de política](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/)
- [Vetores de entrada](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascanconfig/)
- [Docker e DOCKER-USER](https://docs.docker.com/engine/network/firewall-iptables/)
