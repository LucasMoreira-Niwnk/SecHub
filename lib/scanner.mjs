import { Resolver } from 'node:dns/promises';
import https from 'node:https';
import { isPublicIP } from './security.mjs';

const resolver = new Resolver({ timeout: 2500, tries: 2 });
const query = async (method, host, dnsResolver=resolver) => {
  try { return { records: await dnsResolver[method](host), error: null }; }
  catch(e) { return { records: [], error: e.code || 'DNS_ERROR' }; }
};

export async function resolvePublic(host) {
  const answers = await Promise.all([query('resolve4',host), query('resolve6',host)]);
  const ips = answers.flatMap(a=>a.records);
  if (!ips.length) throw new Error('Nenhum endereço A/AAAA resolvido.');
  if (ips.some(ip=>!isPublicIP(ip))) throw new Error('Endereço privado ou reservado: use futuramente o coletor interno.');
  return ips;
}

export async function inspectHTTPS(host, path = '/', redirects = 0, options={}) {
  const ips = await (options.resolveHost||resolvePublic)(host);
  const started = Date.now();
  const response = await new Promise((resolve,reject)=>{
    const req = https.get({ hostname: host, port:443, path, servername:host,
      lookup: (_h,options,cb)=>options?.all ? cb(null,[{address:ips[0],family:ips[0].includes(':')?6:4}]) : cb(null,ips[0],ips[0].includes(':')?6:4),
      agent:false, rejectUnauthorized:true, minVersion:'TLSv1.2',signal:options.signal,
      headers:{'User-Agent':'CasaTerra-SecHUB/0.1 (security monitoring)','Accept':'text/html'},
    },res=>{
      const cert = res.socket.getPeerCertificate();
      const result = {status:res.statusCode,headers:res.headers, latencyMs:Date.now()-started,
        tls:res.socket.getProtocol(), certificate:{issuer:cert.issuer?.O,validTo:cert.valid_to,daysRemaining:Math.floor((Date.parse(cert.valid_to)-Date.now())/86400000)}};
      res.destroy(); resolve(result);
    });
    const timer = setTimeout(()=>req.destroy(new Error('HTTPS_TIMEOUT')),10000);
    req.once('close',()=>clearTimeout(timer));
    req.on('error',reject);
  });
  if ([301,302,303,307,308].includes(response.status) && response.headers.location) {
    const next = new URL(response.headers.location,`https://${host}${path}`);
    if(next.protocol!=='https:' || next.hostname!==host || (next.port && next.port!=='443') || next.username || next.password) {
      return {...response,redirectOutsideScope:true};
    }
    if(redirects>=2) throw new Error('Limite de redirecionamentos atingido.');
    return inspectHTTPS(host,next.pathname+next.search,redirects+1,options);
  }
  return response;
}

export async function scanDomain(host,options={}) {
  const started = new Date().toISOString();
  const findings = [];
  const add = (code,title,severity,evidence,remediation,reference) => findings.push({code,title,severity,evidence,remediation,reference});
  const emailChecks=options.emailChecks!==false;
  const ask=(method,name)=>query(method,name,options.resolver||resolver);
  const [a,aaaa,mx,ns,txt,dmarc] = await Promise.all([
    ask('resolve4',host),ask('resolve6',host),...(emailChecks?[ask('resolveMx',host),ask('resolveNs',host),ask('resolveTxt',host),ask('resolveTxt',`_dmarc.${host}`)]:Array.from({length:4},()=>({records:[],error:null})))
  ]);
  const dns = emailChecks?{a,aaaa,mx,ns,txt,dmarc}:{a,aaaa};
  if(!a.records.length && !aaaa.records.length) add('dns-resolution','DNS sem endereço resolvido','high',`${a.error}; ${aaaa.error}`,'Verifique zona DNS e disponibilidade do resolvedor.','Operacional / DNS');
  if(emailChecks){
  const spf = txt.records.map(x=>x.join('')).filter(x=>/^v=spf1\b/i.test(x));
  if(txt.error && !['ENODATA','ENOTFOUND'].includes(txt.error)) add('dns-txt-error','Consulta SPF inconclusiva','info',txt.error,'Reexecute após verificar o resolvedor DNS.','Operacional / DNS');
  else if(!spf.length) add('spf-missing','SPF não encontrado neste domínio','medium','Nenhum TXT v=spf1','Configure SPF para os serviços autorizados; confira se este hostname envia email.','Email / SPF');
  else if(spf.length>1 || spf.some(x=>/(?:^|\s)\+?all(?:\s|$)/i.test(x))) add('spf-policy','Política SPF inválida ou permissiva','medium',spf.join('; '),'Mantenha um único SPF e restrinja os remetentes.','Email / SPF');
  const dm = dmarc.records.map(x=>x.join('')).find(x=>/^v=DMARC1\s*;/i.test(x));
  if(dmarc.error && !['ENODATA','ENOTFOUND'].includes(dmarc.error)) add('dmarc-query','Consulta DMARC inconclusiva','info',dmarc.error,'Reexecute após verificar o resolvedor.','Operacional / DNS');
  else if(!dm || !/;\s*p=(quarantine|reject)(?:\s*;|\s*$)/i.test(dm)) add('dmarc-policy','DMARC sem política de aplicação neste domínio','medium',dm || 'Registro não encontrado','Valide remetentes e herança da política no domínio organizacional antes de aplicar quarantine/reject.','Email / DMARC');
  }
  let web = null;
  try {
    web = await inspectHTTPS(host,'/',0,options);
    if(web.redirectOutsideScope) add('redirect-scope','Redirecionamento fora do escopo','info',String(web.headers.location).slice(0,300),'Cadastre o hostname de destino separadamente para avaliá-lo.','Escopo');
    if(web.status>=400) add('http-status','Endpoint HTTPS retornou erro','high',`HTTP ${web.status}`,'Investigue disponibilidade, WAF e aplicação.','Operacional / disponibilidade');
    if(web.certificate.daysRemaining<30) add('tls-expiry','Certificado próximo do vencimento','high',`${web.certificate.daysRemaining} dias`,'Renove e verifique a automação do certificado.','OWASP WSTG-CRYP-01');
    const controls = [
      ['strict-transport-security','HSTS não encontrado','medium','Configure Strict-Transport-Security após validar HTTPS em todos os hosts.','OWASP WSTG-CONF-07'],
      ['content-security-policy','Content Security Policy não encontrada','low','Defina uma CSP compatível com a aplicação.','OWASP WSTG-CONF-12'],
      ['x-content-type-options','Proteção contra MIME sniffing ausente','low','Configure X-Content-Type-Options: nosniff.','OWASP WSTG-CONF-14']
    ];
    for(const [header,title,severity,fix,ref] of controls) if(!web.headers[header]) add(header,title,severity,`Header ${header} ausente na resposta avaliada`,fix,ref);
    if(!web.headers['x-frame-options'] && !/frame-ancestors/i.test(web.headers['content-security-policy']||'')) add('clickjacking','Proteção contra enquadramento não encontrada','low','Sem X-Frame-Options ou frame-ancestors','Configure CSP frame-ancestors conforme o uso da aplicação.','OWASP WSTG-CLNT-09');
    const cookies = web.headers['set-cookie'] || [];
    if(cookies.some(c=>! /;\s*secure(?:;|$)/i.test(c))) add('cookie-secure','Cookie sem atributo Secure','medium',`${cookies.length} cookie(s) examinados; valores omitidos`,'Configure Secure em cookies transmitidos por HTTPS.','OWASP WSTG-SESS-02');
    // Do not retain tokens, cookie values or arbitrary server headers in evidence.
    web = {status:web.status,latencyMs:web.latencyMs,tls:web.tls,certificate:web.certificate,redirectOutsideScope:!!web.redirectOutsideScope};
  } catch(e) {
    add('https-check','Verificação HTTPS inconclusiva','high',String(e.code||e.message).slice(0,250),'Verifique conectividade, DNS e cadeia TLS. Falha do coletor não comprova vulnerabilidade.','OWASP WSTG-CRYP-01 / Operacional');
  }
  return {started,finished:new Date().toISOString(),dns,web,findings,coverage:{baseline:'executado',sqlInjection:'não testado',authenticationAbuse:'não testado'}};
}
