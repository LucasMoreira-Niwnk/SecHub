import { normalizeDomain } from './security.mjs';

export const ZAP_TIMEOUT_MS=12*60*1000;
export const ZAP_EXCLUDE='(?i).*(?:logout|signout|delete|remove|unsubscribe|checkout|payment).*';
const escapeRegex=s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');

export function validateZapRequest(hostname,input={}) {
  hostname=normalizeDomain(hostname);
  const mode=input.mode??'baseline';
  if(!['baseline','sqli'].includes(mode))throw new Error('ZAP: modo inválido.');
  if(mode==='baseline')return {hostname,mode,targets:[`https://${hostname}/`]};
  if(input.authorized!==true)throw new Error('ZAP: confirme a autorização para o teste ativo.');
  if(!Array.isArray(input.targets)||!input.targets.length||input.targets.length>5)throw new Error('ZAP: informe de 1 a 5 URLs autorizadas.');
  const targets=[...new Set(input.targets.map(value=>{
    if(typeof value!=='string'||value.length>1024||/[\r\n\x00]/.test(value))throw new Error('ZAP: URL inválida.');
    const u=new URL(value,`https://${hostname}`);
    if(u.origin!==`https://${hostname}`||u.username||u.password||u.hash||!u.search||new RegExp(ZAP_EXCLUDE.replace('(?i)',''),'i').test(decodeURIComponent(u.pathname)))throw new Error('ZAP: use HTTPS no host exato, com parâmetros de consulta e caminho autorizado.');
    if([...u.searchParams.keys()].some(k=>!/^\w{1,64}$/.test(k)))throw new Error('ZAP: nome de parâmetro inválido.');
    if([...u.searchParams.keys()].some(k=>/token|pass|secret|session|auth|key/i.test(k)))throw new Error('ZAP: não inclua credenciais nas URLs.');
    return u.href;
  }))];
  const windowStart=Date.parse(input.windowStart),windowEnd=Date.parse(input.windowEnd);
  if(!Number.isFinite(windowStart)||!Number.isFinite(windowEnd)||windowEnd<=Date.now()||windowEnd-windowStart>4*3600000||windowEnd-windowStart<60000)throw new Error('ZAP: informe uma janela operacional válida de até 4 horas.');
  return {hostname,mode,targets,authorized:true,windowStart:new Date(windowStart).toISOString(),windowEnd:new Date(windowEnd).toISOString()};
}

// JSON is a YAML 1.2 document; no interpolation of untrusted YAML fragments.
export function zapPlan(request) {
  const r=validateZapRequest(request.hostname,request);
  const includePaths=r.mode==='baseline'?[`https://${escapeRegex(r.hostname)}/.*`]:r.targets.map(value=>{
    const u=new URL(value),keys=[...new Set(u.searchParams.keys())].map(escapeRegex).join('|');
    return `https://${escapeRegex(r.hostname)}${escapeRegex(u.pathname)}\\?(?:${keys})=[^&]*(?:&(?:${keys})=[^&]*)*`;
  });
  const jobs=[{type:'passiveScan-config',parameters:{scanOnlyInScope:true,maxAlertsPerRule:20}}];
  if(r.mode==='baseline')jobs.push({type:'spider',parameters:{context:'SecHub',maxDuration:1,maxDepth:2,maxChildren:10,threadCount:1,processForm:false,postForm:false,parseRobotsTxt:false,parseSitemapXml:false}});
  else {
    jobs.push({type:'requestor',requests:r.targets.map(url=>({url,method:'GET',responseCode:200}))});
    jobs.push({type:'activeScan-config',inputVectors:{urlQueryStringAndDataDrivenNodes:{enabled:true,addParam:false,odata:false},postData:{enabled:false},urlPath:false,httpHeaders:{enabled:false},cookieData:{enabled:false},scripts:false}});
    jobs.push({type:'activeScan',parameters:{context:'SecHub',maxRuleDurationInMins:2,maxScanDurationInMins:5,delayInMs:500,threadPerHost:1,addQueryParam:false,handleAntiCSRFTokens:false,maxAlertsPerRule:20},policyDefinition:{defaultStrength:'Low',defaultThreshold:'Off',rules:[{id:40018,strength:'Low',threshold:'Medium'}]}});
  }
  jobs.push({type:'passiveScan-wait',parameters:{maxDuration:2}});
  jobs.push({type:'report',parameters:{template:'traditional-json',reportDir:'/zap/wrk',reportFile:'report.json'}});
  return JSON.stringify({env:{contexts:[{name:'SecHub',urls:r.targets,includePaths,excludePaths:[ZAP_EXCLUDE]}],parameters:{failOnError:true,failOnWarning:true,maxDuration:600}},jobs},null,2);
}

const plain=(s,n=2000)=>String(s??'').replace(/<[^>]*>/g,' ').replace(/[\x00-\x08\x0b-\x1f]/g,'').slice(0,n);
export function normalizeZapReport(report,hostname,mode) {
  if(!Array.isArray(report.site))throw new Error('ZAP: relatório inválido.');
  const findings=[],seen=new Set();let alerts=0,matched=false;
  for(const site of report.site) {
    let u;try{u=new URL(site['@name']);}catch{continue;}
    if(u.hostname!==hostname)continue;
    matched=true;
    for(const a of site.alerts||[]) {
      alerts++;
      const id=String(a.pluginid??a.alertRef??'');
      if(!/^\d+(?:-\d+)?$/.test(id)||seen.has(id))continue;
      seen.add(id);
      findings.push({id:'zap-'+id,source:'zap',severity:({0:'info',1:'low',2:'medium',3:'high'})[a.riskcode]||'info',title:plain(a.name||a.alert,200),reference:`ZAP ${id} · CWE ${plain(a.cweid,10)} · confiança ${plain(a.confidence,10)}`,evidence:`${Math.min(Number(a.count)||a.instances?.length||1,100000)} ocorrência(s). Valores de parâmetros, cookies e respostas não são armazenados.`,remediation:plain(a.solution),review:'pending'});
      if(findings.length>=200)break;
    }
  }
  if(!matched)throw new Error('ZAP: nenhum resultado do host autorizado; análise inconclusiva.');
  return {engine:'zap',mode,finished:new Date().toISOString(),findings,alerts,limited:findings.length>=200,reviewRequired:true};
}
