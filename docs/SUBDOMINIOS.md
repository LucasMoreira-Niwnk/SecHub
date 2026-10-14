# Domínios, subdomínios e status de varredura

Ao cadastrar um domínio, a opção **Descobrir subdomínios em certificados públicos (crt.sh)** vem marcada. Ela inicia uma pesquisa assíncrona; é possível desmarcá-la. Domínios já cadastrados têm o botão **Descobrir subdomínios**. A consulta envia o nome do domínio ao serviço público crt.sh.

O resultado fica agrupado em **Domínios**, com o domínio principal e os subdomínios abaixo dele. Nomes cadastrados manualmente também são agrupados automaticamente pelo ancestral mais próximo. Um nome como `notexample.com` não é filho de `example.com`.

## Status por host

- **DNS público:** A/AAAA retornou apenas endereços públicos.
- **Privado / reservado:** foi encontrado ao menos um endereço fora do escopo público. O scanner continua bloqueando a conexão HTTPS a esse endereço.
- **Sem DNS A/AAAA:** não foi encontrado endereço atual; pode ser um nome histórico.
- **DNS inconclusivo:** timeout ou falha do resolvedor.
- **Não verificado / Na fila / Em execução / Concluída / Com observações / Inconclusiva / Falhou / Interrompida:** estado ou resultado da verificação daquele host, sem confundir falta de evidência com ausência de problemas.

A tabela mostra o último estado de varredura, código HTTP quando disponível, quantidade de observações da última execução concluída e agendamento individual. O último resultado por host é preservado na resposta da API mesmo quando sai das últimas 100 execuções do histórico.

## Executar as verificações

**Verificar** avalia só o host daquela linha. **Verificar todos** coloca o domínio e os subdomínios já registrados sob ele na fila persistente, com no máximo duas execuções simultâneas. Trabalhos duplicados ou executados no último minuto são ignorados. A fila aguarda disponibilidade do coletor; jobs pendentes sobrevivem ao reinício. Jobs que estavam executando são marcados como interrompidos.

A descoberta não inicia varreduras HTTPS nem ativa agendas automaticamente. Cada subdomínio novo começa com o agendamento pausado. Use **Agendar** na linha dos hosts que deseja verificar periodicamente. Ativar a agenda do domínio principal não ativa a agenda dos subdomínios.

## Limites da descoberta

Certificados públicos não enumeram necessariamente todos os subdomínios. Nomes cobertos somente por wildcard, DNS interno e nomes sem certificados públicos podem não aparecer. Entradas históricas podem não resolver mais. Não há força bruta de DNS, tentativa de transferência de zona, descoberta recursiva ilimitada nem integração com provedor DNS nesta versão.

Cada pesquisa considera até 100 nomes exatos, com quatro consultas de host em paralelo. Intervalo mínimo entre pesquisas do mesmo domínio: 10 minutos. Inventário máximo: 500 ativos, somando domínios e subdomínios. A fonte tem timeout de 20 segundos e resposta limitada a 4 MiB. Falha da fonte é exibida como falha, sem apagar o inventário existente nem apresentar um resultado vazio como sucesso. Se o resultado atingir o limite, isso é informado no painel.

## Atualização do servidor Ubuntu

Há migração automática e idempotente do SQLite para adicionar vínculo pai/filho, estado DNS e filas. Faça backup antes de atualizar. O caminho abaixo pressupõe DATA_DIR=/var/lib/sechub.

```bash
sudo install -d -m 700 /var/backups/sechub
sudo sqlite3 /var/lib/sechub/sechub.sqlite ".backup '/var/backups/sechub/sechub-$(date +%F-%H%M%S).sqlite'"
cd /opt/sechub
sudo systemctl stop sechub
git pull --ff-only origin feat/google-workspace-saml
sudo systemctl start sechub
sudo systemctl status sechub --no-pager
```

Não há nova dependência npm nesta alteração. Atualize a página com Ctrl+F5. Para domínios existentes, clique em **Descobrir subdomínios**; depois confira os nomes encontrados e execute **Verificar todos**, ou verifique hosts individualmente.

## Validação

Os testes usam respostas CT e DNS simuladas, sem scans em domínios empresariais. Cobrem validação de nomes e escopo, wildcard, deduplicação, indisponibilidade, limite de resposta, DNS privado/misto, hierarquia, persistência, limite de concorrência da fila e API com CSRF.

Fonte de pesquisa: [crt.sh / Sectigo](https://crt.sh/).
