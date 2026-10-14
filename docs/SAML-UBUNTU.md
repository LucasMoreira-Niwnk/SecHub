# Ubuntu 24.04: subir o site antes de criar o SAML

Este roteiro substitui a etapa OAuth das instruções anteriores. A aplicação agora usa SAML e possui dependências npm. Mantenha Node 24, DNS, Nginx e HTTPS conforme a instalação anterior.

## 1. Instalar dependências

Na revisão do repositório que contém esta atualização:

```bash
cd /opt/sechub
/opt/node24/bin/node /opt/node24/lib/node_modules/npm/bin/npm-cli.js ci
sudo chmod -R u=rwX,go=rX /opt/sechub/node_modules
sudo -u sechub /opt/node24/bin/node --test tests/*.test.mjs
```

O npm já acompanha o tarball oficial Node instalado em /opt/node24. Não execute npm como a conta do serviço; use o usuário administrativo proprietário do checkout. Mantenha o banco fora do diretório do código.

## 2. Subir em modo SAML pendente

```bash
sudo nano /etc/sechub.env
```

Conteúdo (troque o email):

```dotenv
NODE_ENV=production
PORT=3000
HOST=127.0.0.1
APP_URL=https://sechub.casaeterra.com
DEV_MODE=false
WORKSPACE_DOMAIN=casaeterra.com
ALLOWED_EMAILS=SEU_EMAIL@casaeterra.com
DATA_DIR=/var/lib/sechub
SAML_SP_ENTITY_ID=https://sechub.casaeterra.com/auth/saml/metadata
SAML_ENTRY_POINT=
SAML_IDP_ISSUER=
SAML_IDP_CERT_PATH=
```

O serviço systemd continua usando EnvironmentFile=/etc/sechub.env e ExecStart=/opt/node24/bin/node /opt/sechub/server.mjs. Não é necessário criar .env dentro do repositório. As variáveis GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET não são utilizadas.

```bash
sudo systemctl restart sechub
sudo systemctl status sechub --no-pager
curl --fail https://sechub.casaeterra.com/health
curl --fail https://sechub.casaeterra.com/auth/saml/metadata
curl -s -o /dev/null -w '%{http_code}\n' https://sechub.casaeterra.com/api/overview
```

Resultados: health retorna ok; metadados retornam XML; API retorna 401. O botão de login informa SAML pendente, sem dar acesso ao painel.

## 3. Ajustar o Nginx para o POST SAML

```bash
sudo nano /etc/nginx/sites-available/sechub
```

Nos blocos que encaminham para a aplicação, utilize:

```nginx
client_max_body_size 256k;
access_log off;

location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Connection "";
    proxy_cache off;
    proxy_connect_timeout 5s;
    proxy_read_timeout 30s;
}
```

Preserve as configurações TLS criadas pelo Certbot. Nginx encaminha o formulário POST sem reescrever o caminho ACS. Não registre corpos de requisição ou assertions SAML em logs.

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 4. Criar a aplicação no Google Admin Console

Como administrador: Apps > Apps da Web e para dispositivos móveis > Adicionar app > Adicionar app SAML personalizado. Nome: SecHUB Casa e Terra.

Na tela do provedor de identidade, copie URL de SSO e Entity ID do Google e baixe o certificado X.509 público.

Na tela do provedor de serviço:

| Campo | Valor |
| --- | --- |
| ACS URL | https://sechub.casaeterra.com/auth/saml/acs |
| Entity ID | https://sechub.casaeterra.com/auth/saml/metadata |
| Start URL | vazio |
| Resposta assinada | marcar |
| Name ID format | EMAIL |
| Name ID | Informações básicas > Email principal |

Não são necessários mapeamentos adicionais para esta versão. Habilite acesso à aplicação apenas para o grupo/OU desejado. ALLOWED_EMAILS também deve autorizar cada administrador.

## 5. Instalar o certificado público do Google

Cole o PEM baixado, incluindo BEGIN CERTIFICATE e END CERTIFICATE:

```bash
sudo install -d -m 750 -o root -g sechub /etc/sechub
sudo nano /etc/sechub/google-idp.pem
sudo chown root:sechub /etc/sechub/google-idp.pem
sudo chmod 640 /etc/sechub/google-idp.pem
```

Esse arquivo contém somente o certificado público do IdP. Nunca copie a chave fictícia em tests/fixtures para a produção. A integração não pede a chave privada do Google.

## 6. Ativar a integração

```bash
sudo nano /etc/sechub.env
```

Preencha os três campos com os valores reais do Admin Console:

```dotenv
SAML_ENTRY_POINT=URL_SSO_DO_GOOGLE
SAML_IDP_ISSUER=ENTITY_ID_DO_GOOGLE
SAML_IDP_CERT_PATH=/etc/sechub/google-idp.pem
```

Não confunda SAML_IDP_ISSUER (Google) com SAML_SP_ENTITY_ID (SecHUB).

```bash
sudo systemctl restart sechub
sudo journalctl -u sechub -n 50 --no-pager
```

Abra https://sechub.casaeterra.com e inicie o login pelo botão do SecHUB. Verifique a entrada de um administrador permitido e a rejeição de uma conta fora da lista. A aplicação exige resposta e assertion assinadas, correlação com solicitação iniciada no mesmo navegador e NameID no formato EMAIL.

Login iniciado diretamente pelo IdP, pelo launcher Google ou pelo botão de teste do Admin Console não é aceito nesta implementação. Não desabilite InResponseTo para contornar essa restrição. Logout encerra apenas a sessão SecHUB. Relógio do servidor deve estar sincronizado; tolerância de 60s, janela de login de 10 minutos.

## Referências

- https://knowledge.workspace.google.com/admin/apps/set-up-your-own-custom-saml-app
- https://github.com/node-saml/node-saml
