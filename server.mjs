import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { openStore } from './lib/store.mjs';
import { normalizeDomain, parseInterval } from './lib/security.mjs';
import { token, hash } from './lib/auth.mjs';
import { createSaml, samlDiagnostic } from './lib/saml.mjs';
import { createMonitor } from './lib/monitor.mjs';
import { createDiscovery } from './lib/discovery.mjs';
import { inventory,decodeScan,relinkHierarchy,withinDomain,MAX_ASSETS } from './lib/inventory.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const host = process.env.HOST || '127.0.0.1';
const port = Number(process.env.PORT || 3000);
const appURL = new URL(process.env.APP_URL || `http://127.0.0.1:${port}`);
const dev = process.env.DEV_MODE === 'true';
const domain = normalizeDomain(process.env.WORKSPACE_DOMAIN || 'casaeterra.com');
const allowed = (process.env.ALLOWED_EMAILS || '').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean);
if (dev && (!['127.0.0.1','localhost','::1'].includes(host) || !['127.0.0.1','localhost','[::1]'].includes(appURL.hostname))) throw new Error('Modo local exige HOST e APP_URL de loopback.');
if (!dev && appURL.protocol!=='https:' && !['127.0.0.1','localhost'].includes(appURL.hostname)) throw new Error('SSO em servidor exige APP_URL HTTPS.');
const secure = appURL.protocol === 'https:';
const {db,audit} = openStore(resolve(process.env.DATA_DIR || resolve(root,'data')));
const saml=createSaml({db,appURL,domain,allowed});
const configured=saml.configured;
db.prepare('INSERT OR IGNORE INTO domains(id,hostname,created_at) VALUES(?,?,?)').run('initial-domain',domain,new Date().toISOString());
relinkHierarchy(db);
const monitor=createMonitor({db,audit,canRun:()=>dev||configured});
const discovery=createDiscovery({db,audit});
const running=monitor.running;
const json = (res,status,data) => { res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'}); res.end(JSON.stringify(data)); };
const redirect = (res,path,cookie) => {res.writeHead(302,{Location:path,...(cookie?{'Set-Cookie':cookie}:{})});res.end();};
const cookie = (name,value,age) => `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${secure?'; Secure':''}`;
const cookies = req => Object.fromEntries((req.headers.cookie||'').split(';').map(s=>s.trim().split('=')));
const session = req => {
  if(dev) return {email:'local@'+domain,csrf:localCSRF,local:true};
  const sid = cookies(req).sechub_session;
  if(!sid) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE id=? AND expires>?').get(hash(sid),Date.now());
  return row && allowed.includes(row.email) ? row : null;
};
const localCSRF = token();
async function body(req,form=false) {
  let size=0, chunks=[];
  for await (const chunk of req) {size+=chunk.length;if(size>(form?262144:16384)) throw new Error('Requisição muito grande.');chunks.push(chunk);}
  if(form) {
    if(!req.headers['content-type']?.startsWith('application/x-www-form-urlencoded')) throw new Error('Requisição SAML deve usar formulário.');
    const params=new URLSearchParams(Buffer.concat(chunks).toString());
    for(const key of ['SAMLResponse','RelayState']) if(params.getAll(key).length!==1) throw new Error('Requisição SAML inválida.');
    return Object.fromEntries(params);
  }
  try {return JSON.parse(Buffer.concat(chunks).toString()||'{}');} catch {throw new Error('JSON inválido.');}
}
function getOverview() {
  const domains = inventory(db);
  const scans = db.prepare('SELECT scans.*,domains.hostname FROM scans JOIN domains ON domains.id=scans.domain_id ORDER BY started_at DESC LIMIT 100').all().map(decodeScan);
  return {domains,scans,audit:db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 50').all(),running:[...running],
    queued:db.prepare("SELECT domain_id FROM scans WHERE status='queued'").all().map(s=>s.domain_id),
    discoveries:db.prepare('SELECT * FROM discoveries ORDER BY rowid DESC LIMIT 100').all().map(decodeScan)};
}

const server = http.createServer(async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if(secure) res.setHeader('Strict-Transport-Security','max-age=31536000');
  try {
    if(req.headers.host!==appURL.host) return json(res,400,{error:'Host não permitido. Use '+appURL.origin});
    const url = new URL(req.url,appURL);
    if(req.method==='GET' && url.pathname==='/health') return json(res,200,{status:'ok'});
    if(req.method==='GET' && url.pathname==='/api/session') return json(res,200,{user:session(req),dev,configured,workspaceDomain:domain});
    if(req.method==='GET' && url.pathname==='/auth/saml/metadata') {
      res.writeHead(200,{'Content-Type':'application/samlmetadata+xml; charset=utf-8'});
      return res.end(saml.metadata());
    }
    if(req.method==='GET' && url.pathname==='/auth/saml/login') {
      if(dev) return redirect(res,'/');
      if(!configured) return json(res,503,{error:'SAML pendente. Configure a aplicação no Google Admin Console e os dados do IdP no servidor.'});
      try {
        const flow=await saml.begin();
        return redirect(res,flow.url,'__Host-sechub_saml='+flow.relay+'; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=600');
      } catch {return json(res,429,{error:'Não foi possível iniciar o login SAML. Tente novamente em instantes.'});}
    }
    if(req.method==='POST' && url.pathname==='/auth/saml/acs') {
      if(!configured) return json(res,503,{error:'SAML ainda não configurado.'});
      try {
        const fields=await body(req,true);
        const email=await saml.complete(fields,cookies(req)['__Host-sechub_saml']);
        const sid=token();
        db.prepare('INSERT INTO sessions(id,email,csrf,expires) VALUES(?,?,?,?)').run(hash(sid),email,token(),Date.now()+8*3600000);
        audit(email,'login','Google Workspace / SAML');
        res.setHeader('Set-Cookie',[cookie('sechub_session',sid,8*3600),'__Host-sechub_saml=; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=0']);
        return redirect(res,'/');
      } catch(error) {
        const diagnostic=samlDiagnostic(error);
        console.warn('SAML_LOGIN_REJECTED',diagnostic.code);
        audit('anonymous','saml.rejected',diagnostic.code);
        return json(res,403,{error:'Login SAML não autorizado.',...diagnostic});
      }
    }
    if(url.pathname.startsWith('/api/')) {
      const user = session(req);
      if(!user) return json(res,401,{error:'Faça login com a conta corporativa.'});
      if(req.method!=='GET' && (req.headers.origin!==appURL.origin || req.headers['x-csrf-token']!==user.csrf)) return json(res,403,{error:'Origem ou token de proteção inválido.'});
      if(req.method==='GET' && url.pathname==='/api/overview') return json(res,200,getOverview());
      if(req.method==='GET' && url.pathname==='/api/export') {
        res.setHeader('Content-Disposition','attachment; filename="sechub-report.json"');
        return json(res,200,{exportedAt:new Date().toISOString(),...getOverview()});
      }
      if(req.method==='POST' && url.pathname==='/api/logout') {
        if(!dev && cookies(req).sechub_session) db.prepare('DELETE FROM sessions WHERE id=?').run(hash(cookies(req).sechub_session));
        res.setHeader('Set-Cookie',cookie('sechub_session','',0));
        return json(res,200,{ok:true});
      }
      if(req.method==='POST' && url.pathname==='/api/domains') {
        const data=await body(req);
        const hostname=normalizeDomain(data.hostname);
        const interval=parseInterval(data.intervalHours??24);
        if(db.prepare('SELECT id FROM domains WHERE hostname=?').get(hostname)) return json(res,409,{error:'Domínio já cadastrado.'});
        if(db.prepare('SELECT count(*) AS n FROM domains').get().n>=MAX_ASSETS) return json(res,400,{error:'Limite de 500 ativos nesta versão.'});
        if(data.discoverSubdomains!==undefined && typeof data.discoverSubdomains!=='boolean') throw new Error('Requisição de descoberta inválida.');
        const id=randomUUID();
        db.prepare('INSERT INTO domains(id,hostname,interval_hours,created_at) VALUES(?,?,?,?)').run(id,hostname,interval,new Date().toISOString());
        relinkHierarchy(db);
        audit(user.email,'domain.created',hostname);
        const discoveryJob=data.discoverSubdomains===false?null:discovery.enqueue(db.prepare('SELECT * FROM domains WHERE id=?').get(id),user.email);
        return json(res,201,{ok:true,id,discovery:discoveryJob});
      }
      const match=url.pathname.match(/^\/api\/domains\/([^/]+)(?:\/(scan|scan-tree|discover|schedule|zap-plan))?$/);
      if(match) {
        const asset=db.prepare('SELECT * FROM domains WHERE id=?').get(match[1]);
        if(!asset) return json(res,404,{error:'Domínio não encontrado.'});
        if(req.method==='POST' && ['scan','scan-tree'].includes(match[2])) {
          const assets=match[2]==='scan-tree'?db.prepare('SELECT * FROM domains ORDER BY hostname').all().filter(d=>d.id===asset.id||withinDomain(d.hostname,asset.hostname)):[asset];
          const result=monitor.enqueue(assets,user.email);
          return json(res,result.queued.length?202:409,result.queued.length?result:{error:'Os ativos já estão na fila ou foram verificados no último minuto.',...result});
        }
        if(req.method==='POST' && match[2]==='discover') {
          const result=discovery.enqueue(asset,user.email);
          return json(res,result.cooldown?429:202,result.cooldown?{error:'Aguarde 10 minutos entre descobertas deste domínio.'}:result);
        }
        if(req.method==='POST' && match[2]==='schedule') {
          const data=await body(req);const interval=parseInterval(data.intervalHours??asset.interval_hours);
          if(typeof data.enabled!=='boolean') throw new Error('Agendamento inválido.');
          db.prepare('UPDATE domains SET enabled=?, interval_hours=?, next_run=? WHERE id=?').run(data.enabled?1:0,interval,data.enabled?new Date(Date.now()+interval*3600000).toISOString():null,asset.id);
          audit(user.email,'schedule.updated',`${asset.hostname}: ${data.enabled?'ativo':'pausado'} / ${interval}h`);
          return json(res,200,{ok:true});
        }
        if(req.method==='GET' && match[2]==='zap-plan') {
          const escaped=asset.hostname.replaceAll('.','\\.');
          const plan=`# Baseline passivo. Execute somente no domínio empresarial autorizado.\n# SQL injection e abuso de autenticação NÃO são testados por este plano.\nenv:\n  contexts:\n    - name: CasaTerra\n      urls: ["https://${asset.hostname}/"]\n      includePaths: ['https://${escaped}/.*']\n      excludePaths: ['https://${escaped}/.*(?:logout|signout|delete|remove).*']\n  parameters:\n    failOnError: true\njobs:\n  - type: passiveScan-config\n    parameters:\n      scanOnlyInScope: true\n  - type: spider\n    parameters:\n      context: CasaTerra\n      maxDuration: 1\n      maxDepth: 2\n  - type: passiveScan-wait\n    parameters:\n      maxDuration: 3\n  - type: report\n    parameters:\n      template: traditional-json\n      reportDir: /zap/wrk\n      reportFile: zap-report\n`;
          res.writeHead(200,{'Content-Type':'text/yaml; charset=utf-8','Content-Disposition':`attachment; filename="zap-${asset.hostname}.yaml"`});return res.end(plan);
        }
      }
      return json(res,404,{error:'Operação não encontrada.'});
    }
    if(req.method==='GET') {
      const files={'/':'index.html','/app.js':'app.js','/styles.css':'styles.css'};
      const name=files[url.pathname];
      if(name && existsSync(resolve(root,'public',name))) {
        res.writeHead(200,{'Content-Type':name.endsWith('.css')?'text/css; charset=utf-8':name.endsWith('.js')?'text/javascript; charset=utf-8':'text/html; charset=utf-8'});
        return res.end(readFileSync(resolve(root,'public',name)));
      }
    }
    json(res,404,{error:'Página não encontrada.'});
  } catch(e) {
    const message=String(e.message);
    const expected=/Domínio|Informe|Intervalo|JSON|Requisição|Agendamento/.test(message);
    json(res,expected?400:500,{error:expected?message:'Não foi possível concluir a operação. Confira a configuração e tente novamente.'});
  }
});
server.requestTimeout=15000;
server.headersTimeout=10000;
server.maxHeadersCount=50;
const scheduler=setInterval(()=>{
  if(!dev && !configured) return;
  for(const asset of db.prepare('SELECT * FROM domains WHERE enabled=1 AND (next_run IS NULL OR next_run<=?)').all(new Date().toISOString())) {
    monitor.enqueue([asset],'scheduler');
  }
  db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());
  db.prepare('DELETE FROM saml_flows WHERE expires<?').run(Date.now());
  db.prepare('DELETE FROM saml_requests WHERE expires<?').run(Date.now());
},30000);
monitor.pump();
if(dev||configured)void discovery.pump();
server.listen(port,host,()=>console.log(`SecHUB: ${appURL.origin} | ${dev?'MODO LOCAL, sem SSO':configured?'Google Workspace configurado':'SSO pendente: acesso protegido bloqueado'}`));
function shutdown() {monitor.stop();discovery.stop();clearInterval(scheduler);server.close(()=>{db.close();process.exit(0);});}
process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
