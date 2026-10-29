# Eventos de autenticação do Active Directory

O coletor Linux consulta somente o log Security de um controlador explicitamente autorizado, usando WinRM/NTLM e criptografia de mensagens obrigatória. Não modifica contas, grupos, GPOs ou o log. Cada controlador adicional precisa de um registro e processo próprios; esta instalação registra um controlador. Logs dos DCs cobrem autenticação Kerberos/NTLM e logons processados no próprio DC. Para acompanhar todos os logons interativos de estações e servidores, também é necessário coletar esses equipamentos ou centralizar seus eventos com Windows Event Forwarding.

## Configuração da conta no servidor SecHub

Arquivo: **`/etc/sechub-ad/credentials.json`**. Edite com `sudoedit /etc/sechub-ad/credentials.json`, sem enviar senha pelo chat. O arquivo pertence a root:sechub-ad, modo 0640, diretório 0750. O site e o processo principal não leem esse arquivo. O usuário do serviço não pode modificá-lo. O instalador preserva arquivos existentes.

```json
{
  "enabled": true,
  "endpoint": "http://DC_IP_AUTORIZADO:5985/wsman",
  "username": "DOMINIO\\svc_sechub",
  "password": "PREENCHER_LOCALMENTE"
}
```

Use o nome NetBIOS real do domínio ou UPN da conta. Escape barras invertidas e aspas conforme JSON. O endpoint precisa corresponder ao controlador registrado; HTTP aceita somente endereço privado e porta 5985. HTTPS aceita somente 5986, valida certificado e é preferível quando disponível para autenticar também a identidade do servidor; não existe opção para ignorar certificados. NTLM exige `message_encryption=always`, inclusive em HTTP: nunca usa Basic, CredSSP ou mensagens em texto aberto. Não habilite AllowUnencrypted no Windows.

O serviço relê o arquivo a cada minuto, sem reinício. `enabled=false` pausa a consulta. Após erro de credencial, o coletor **não repete o login** até o arquivo ser alterado, evitando bloquear a conta por tentativas automáticas. A senha não é enviada ao SecHub, registrada em logs, colocada em argumentos de processo ou incluída no Git. Não use Domain Admin.

O sudo temporário usado durante a implantação é removido depois da validação. Para editar posteriormente, utilize uma conta com sudo autorizado pela administração; não habilite sudo irrestrito permanentemente para manter o coletor.

## Permissões no Windows

A conta precisa de leitura do log **Security** (delegação para Event Log Readers, com ACL do canal validada) e autorização para abrir a sessão WinRS/WinRM e executar o PowerShell usado por `pywinrm.run_ps`. Event Log Readers sozinho não concede uma sessão WinRM. O endpoint padrão pode exigir Administrators: delegue explicitamente o acesso WinRM/WinRS para a conta de serviço, com ajuda do administrador Windows, em vez de promovê-la a administradora do domínio. A ACL de uma configuração de PowerShell Remoting isoladamente pode não autorizar WinRS; valide a ACL do serviço WinRM e suas políticas. A conta não precisa de permissão para limpar logs nem de Manage auditing and security log.

As delegações exatas dependem da versão do Windows, GPOs e ACLs existentes. Com as credenciais ainda em branco, não é possível aplicar nem testar essas permissões no DC. Confirme que o firewall permite WinRM somente a partir do servidor SecHub. O instalador Linux não altera firewall, listener, NTLM ou auditoria no Windows.

Verifique em GPO (Advanced Audit Policy): Account Logon / Credential Validation, Kerberos Authentication Service e Service Ticket Operations; Logon/Logoff / Logon e Special Logon; Account Management / User Account Management e Security Group Management; Policy Change / Audit Policy Change. Habilite sucesso/falha conforme a categoria e a política da organização. Sem auditoria habilitada, a ausência de eventos não comprova ausência de atividade.

Eventos coletados: 4624, 4625, 4672, 4728, 4732, 4740, 4756, 4768, 4769, 4771, 4776, 1102 e 4719. Campos são extraídos pelo nome do XML, sem depender do idioma da mensagem. Mensagens brutas, tokens e tickets não são armazenados.

## Regras e revisão

Na aba Active Directory, ajuste os limiares, fuso, horário útil e listas de contas. Por padrão: dez falhas por conta ou cinco contas diferentes na mesma origem em dez minutos; sucesso após falhas; bloqueios; adição a grupos com SIDs privilegiados; alteração de auditoria e limpeza de logs. Login fora do horário começa desativado. Login interativo de conta de serviço e monitoramento de contas privilegiadas só são aplicados às listas cadastradas. A lista de ignoradas suprime alertas, preservando eventos. Use `dominio\usuario` para precisão; nome simples também é aceito e vale para qualquer domínio.

Nova origem exige ao menos sete dias de histórico e vinte autenticações anteriores; não há alerta de novidade durante a instalação. Logon types 2, 7, 10 e 11 são usados para horário; contas de máquina são excluídas dessas regras. Kerberos/NTLM não são tratados como logon interativo. As correlações usam o horário dos eventos e podem incluir múltiplos registros para uma tentativa; ajuste o limiar à sua rede. Não há classificação automática como invasão, bloqueio de conta ou teste ativo de senha. Revise alertas como confirmados ou falsos positivos, com justificativa auditada.

## Limites e operação

Consulta inicial: últimos quinze minutos; depois cursor persistido, lotes ascendentes de até 500 eventos, consulta a cada minuto (cinco segundos se houver backlog). Cursor só avança depois da confirmação do servidor. Reentregas são deduplicadas por fonte, RecordId, EventId e horário. Limpeza/reinício detectado ou lacuna de retenção aparecem como LOG_RESET/LOG_GAP; um reset usa novamente a janela inicial. Não é um arquivo de auditoria completo nem substitui um SIEM: se a retenção do DC expirar antes da leitura, eventos podem ser perdidos. Sincronize NTP no DC e no SecHub.

Retenção: eventos por trinta dias e no máximo 200 mil registros; alertas por noventa dias e no máximo vinte mil. O painel mostra os cem eventos e alertas mais recentes. A evidência do alerta guarda até vinte registros e sobrevive à expiração do evento original. Essas informações contêm nomes de usuários e origens, acessíveis apenas aos administradores autorizados pelo SAML existente.

Instalação, após atualizar/iniciar o servidor para criar as tabelas:

```bash
sudo bash /opt/sechub/deploy/install-ad-collector.sh IP_PRIVADO_AUTORIZADO
systemctl status sechub-ad
sudo journalctl -u sechub-ad -n 30 --no-pager
```

`credentials_pending`: conta não preenchida ou coleta pausada; `AUTH_FAILED`: corrigir conta/senha e salvar arquivo; `ACCESS_DENIED`: delegar leitura/WinRM; `WINRM_UNAVAILABLE`: verificar rede/listener; `EVENT_QUERY_FAILED`: política/compatibilidade de consulta. Serviço online significa que o coletor comunica com SecHub; última coleta bem-sucedida indica leitura do Windows. Sem credenciais válidas, não se declara a coleta real validada.

Fontes: [Microsoft — WinRM e segurança](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security), [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent), [pywinrm — criptografia de mensagens](https://github.com/diyan/pywinrm).

## Dashboard da visão geral

A visão geral agrega todos os eventos retidos no período, sem o limite de cem registros da lista de eventos recentes. Filtre hoje, sete, quinze ou trinta dias, ou informe um intervalo personalizado dentro dos últimos trinta dias. Os dias usam America/Sao_Paulo, com início à meia-noite e término exclusivo à meia-noite do dia seguinte. Usuários são o filtro inicial; máquinas (contas terminadas em $) e todas as contas estão disponíveis. Contas de sistema conhecidas e anônimas não entram no filtro de usuários.

Os rankings de sucesso/falha contam eventos, não sessões únicas: logons, TGTs, tickets de serviço e validações NTLM podem produzir múltiplos registros de uma sessão. O dashboard mostra a distribuição por Event ID e o número de eventos 4624 separadamente. Alertas são filtrados pelo período, incluindo todos os tipos de conta, e divididos por comportamento e revisão. Retenção e interrupções da coleta podem deixar dias sem dados.

Os cartões de domínios, rede interna e AWS representam inventário/configuração atuais; as contagens de execuções desses módulos e do ZAP respeitam o período. Estado dos workers e última leitura são atuais. Os agregados só estão acessíveis pela sessão autenticada existente, em /api/dashboard e /api/overview.
