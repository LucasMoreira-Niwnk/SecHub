import { randomUUID } from 'node:crypto';
import { token,hash } from './auth.mjs';
import { internalHostname,internalPolicy,approvedInternalHost,validateInternalAddresses } from './internal-scope.mjs';
import { awsConnection,validateAwsPolicy,AWS_SOURCES } from './aws-collector.mjs';
import { parseInterval } from './security.mjs';

const now=()=>new Date().toISOString();
const decoded=row=>row?{...row,result:row.result?JSON.parse(row.result):null}:null;
const brief=row=>{const value=decoded(row);if(value?.result){const {findings=[],assets=[],...rest}=value.result;value.result={...rest,findingCount:findings.length,assetCount:assets.length};}return value;};
const safe=(value,n=1500)=>String(value??'').replace(/[\x00-\x08\x0b-\x1f]/g,'').slice(0,n);
export function registerCollector(db,audit,input){
  if(typeof input.name!=='string'||!input.name.trim()||input.name.length>80||!['corporate','vpc'].includes(input.zone))throw new Error('Coleta: nome ou zona do coletor inválidos.');
  if(db.prepare('SELECT count(*) n FROM collectors WHERE enabled=1').get().n>=20)throw new Error('Coleta: limite de 20 coletores.');
  const id=randomUUID(),secret=token();
  db.prepare('INSERT INTO collectors(id,name,zone,token_hash,created_at) VALUES(?,?,?,?,?)').run(id,input.name.trim(),input.zone,hash(secret),now());
  audit(input.actor||'administrator','collector.created',id);return {id,token:secret};
}
export function sanitizeCapabilities(value={}){
  const internal=internalPolicy(value.internal||{}),aws=value.aws||{};
  const list=(v,re,max)=>{if(!Array.isArray(v)||v.length>max||v.some(s=>typeof s!=='string'||!re.test(s)))throw new Error('Coleta: capacidades inválidas.');return [...new Set(v)];};
  return {version:1,internal,aws:{roleArns:list(aws.roleArns||[],/^arn:aws:iam::\d{12}:role\/[\w+=,.@\/-]+$/,50),sourceProfiles:list(aws.sourceProfiles||[],/^\w[\w.-]{0,63}$/,20),regions:list(aws.regions||[],/^[a-z]{2}-[a-z]+-\d+$/,20)}};
}
function resultSchema(kind,value={}){
  const findings=Array.isArray(value.findings)?value.findings:[];
  if(findings.length>1000)throw new Error('Coleta: limite de achados excedido.');
  const result={started:safe(value.started,40),finished:safe(value.finished,40),limited:!!value.limited,
    findings:findings.map(f=>({id:safe(f.id||f.code,100),source:kind==='internal'?'internal':safe(f.source,30),title:safe(f.title,200),severity:['critical','high','medium','low','info'].includes(f.severity)?f.severity:'info',evidence:safe(f.evidence),remediation:safe(f.remediation),reference:safe(f.reference,300),resource:safe(f.resource,500),accountId:safe(f.accountId,12),region:safe(f.region,40)}))};
  if(kind==='internal'){
    result.dns=Object.fromEntries(['a','aaaa'].map(k=>[k,{records:(value.dns?.[k]?.records||[]).slice(0,50).map(s=>safe(s,60)),error:value.dns?.[k]?.error?safe(value.dns[k].error,80):null}]));
    result.web=value.web?{status:Number(value.web.status),tls:safe(value.web.tls,40),certificate:{issuer:safe(value.web.certificate?.issuer,200),validTo:safe(value.web.certificate?.validTo,80),daysRemaining:Number.isFinite(value.web.certificate?.daysRemaining)?value.web.certificate.daysRemaining:null},redirectOutsideScope:!!value.web.redirectOutsideScope}:null;
  }else{
    result.accountId=safe(value.accountId,12);
    result.sources=(value.sources||[]).slice(0,60).map(s=>({source:AWS_SOURCES.includes(s.source)?s.source:'unknown',region:safe(s.region,40),status:['ok','error','not_enabled'].includes(s.status)?s.status:'error',error:safe(s.error,80),count:Number(s.count)||0,limited:!!s.limited}));
    result.assets=(value.assets||[]).slice(0,1000).map(a=>({id:safe(a.id,200),type:safe(a.type,40),name:safe(a.name,253),private:!!a.private,region:safe(a.region,40),status:safe(a.status,60),direction:safe(a.direction,30)}));
  }
  if(value.error)result.error=safe(value.error,200);
  return result;
}

export function createCollections({db,audit,canRun=()=>true}){
  function collector(id,online=false){
    const row=db.prepare('SELECT * FROM collectors WHERE id=? AND enabled=1').get(id);
    if(!row)throw new Error('Coleta: coletor não encontrado ou revogado.');
    if(online&&!(Date.now()-Date.parse(row.last_seen||'')<90000))throw new Error('Coleta: coletor indisponível.');
    return {...row,capabilities:JSON.parse(row.capabilities)};
  }
  const latest=id=>brief(db.prepare('SELECT id,kind,status,created_at,started_at,finished_at,result,cancel_requested FROM collection_jobs WHERE target_id=? ORDER BY rowid DESC LIMIT 1').get(id));
  function overview(){
    return {collectors:db.prepare('SELECT id,name,zone,enabled,created_at,last_seen,capabilities FROM collectors ORDER BY created_at').all().map(c=>({...c,capabilities:JSON.parse(c.capabilities),online:!!c.enabled&&Date.now()-Date.parse(c.last_seen||0)<90000})),
      internalAssets:db.prepare('SELECT a.*,c.name collector_name FROM internal_assets a JOIN collectors c ON c.id=a.collector_id ORDER BY a.hostname').all().map(a=>({...a,latest:latest(a.id)})),
      awsConnections:db.prepare('SELECT a.*,c.name collector_name FROM aws_connections a JOIN collectors c ON c.id=a.collector_id ORDER BY a.name').all().map(a=>{const {externalId,...config}=JSON.parse(a.config);return {...a,config:undefined,settings:config,latest:latest(a.id)};}),
      collectionJobs:db.prepare('SELECT id,collector_id,kind,target_id,status,actor,created_at,started_at,finished_at,result,cancel_requested FROM collection_jobs ORDER BY rowid DESC LIMIT 100').all().map(brief)};
  }
  function createInternal(input,actor){
    const c=collector(input.collectorId),hostname=internalHostname(input.hostname),policy=internalPolicy(c.capabilities.internal);
    if(!approvedInternalHost(hostname,policy)||!policy.cidrs.length||!policy.dnsServers.length)throw new Error('Coleta: host fora do escopo anunciado pelo coletor.');
    if(db.prepare('SELECT id FROM internal_assets WHERE collector_id=? AND hostname=?').get(c.id,hostname))throw new Error('Coleta: host interno já cadastrado neste coletor.');
    if(db.prepare('SELECT count(*) n FROM internal_assets').get().n>=500)throw new Error('Coleta: limite de 500 hosts internos.');
    const id=randomUUID();db.prepare('INSERT INTO internal_assets(id,collector_id,hostname,created_at) VALUES(?,?,?,?)').run(id,c.id,hostname,now());audit(actor,'internal.created',id);return {id};
  }
  function createAws(input,actor){
    const c=collector(input.collectorId),config=awsConnection(input);
    if(typeof input.name!=='string'||!input.name.trim()||input.name.length>80)throw new Error('Coleta: nome da conexão AWS inválido.');
    if(db.prepare('SELECT count(*) n FROM aws_connections').get().n>=30)throw new Error('Coleta: limite de 30 conexões AWS.');
    // Saving a draft connection is allowed before the worker's IAM policy is ready.
    const id=randomUUID();db.prepare('INSERT INTO aws_connections(id,collector_id,name,account_id,config,created_at) VALUES(?,?,?,?,?,?)').run(id,c.id,input.name.trim(),config.accountId,JSON.stringify(config),now());audit(actor,'aws.connection.created',id);return {id};
  }
  function enqueue(kind,id,actor){
    const table=kind==='internal'?'internal_assets':'aws_connections',asset=db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(id);
    if(!asset)throw new Error('Coleta: ativo não encontrado.');
    const c=collector(asset.collector_id,true),config=kind==='internal'?{hostname:asset.hostname}:JSON.parse(asset.config);
    if(kind==='internal'){
      const policy=internalPolicy(c.capabilities.internal);if(!approvedInternalHost(config.hostname,policy)||!policy.cidrs.length)throw new Error('Coleta: host fora do escopo do coletor.');
    }else validateAwsPolicy(config,c.capabilities.aws);
    const pending=db.prepare("SELECT id FROM collection_jobs WHERE target_id=? AND status IN ('queued','running')").get(id);
    if(pending)return {id:pending.id,existing:true};
    const last=db.prepare('SELECT created_at FROM collection_jobs WHERE target_id=? ORDER BY rowid DESC LIMIT 1').get(id);
    if(last&&Date.now()-Date.parse(last.created_at)<60000)throw new Error('Coleta: aguarde um minuto entre execuções.');
    if(db.prepare("SELECT count(*) n FROM collection_jobs WHERE collector_id=? AND status IN ('queued','running')").get(c.id).n>=20)throw new Error('Coleta: fila do coletor cheia.');
    const job=randomUUID();db.prepare("INSERT INTO collection_jobs(id,collector_id,kind,target_id,actor,status,created_at,input) VALUES(?,?,?,?,?,'queued',?,?)").run(job,c.id,kind,id,actor,now(),JSON.stringify(config));
    db.prepare(`UPDATE ${table} SET next_run=? WHERE id=?`).run(new Date(Date.now()+asset.interval_hours*3600000).toISOString(),id);audit(actor,kind+'.queued',job);return {id:job};
  }
  function authenticate(secret){
    if(typeof secret!=='string'||secret.length<32||secret.length>200)return null;
    return db.prepare('SELECT * FROM collectors WHERE token_hash=? AND enabled=1').get(hash(secret))||null;
  }
  function claim(c,manifest){
    const capabilities=sanitizeCapabilities(manifest);
    db.prepare('UPDATE collectors SET last_seen=?,capabilities=? WHERE id=?').run(now(),JSON.stringify(capabilities),c.id);
    reap();if(!canRun()||db.prepare("SELECT id FROM collection_jobs WHERE collector_id=? AND status='running'").get(c.id))return {job:null};
    // SQLite serializes this synchronous claim; no await occurs before the update.
    const job=db.prepare("SELECT * FROM collection_jobs WHERE collector_id=? AND status='queued' ORDER BY rowid LIMIT 1").get(c.id);if(!job)return {job:null};
    const lease=token(),deadline=Date.now()+600000;
    db.prepare("UPDATE collection_jobs SET status='running',started_at=?,lease_hash=?,lease_until=?,deadline=? WHERE id=? AND status='queued'").run(now(),hash(lease),Date.now()+90000,deadline,job.id);
    return {job:{id:job.id,kind:job.kind,input:JSON.parse(job.input),lease,deadline,version:1}};
  }
  function owned(c,data){
    const job=db.prepare("SELECT * FROM collection_jobs WHERE id=? AND collector_id=? AND status='running' AND lease_hash=? AND lease_until>?").get(data.id,c.id,hash(String(data.lease||'')),Date.now());
    if(!job)throw new Error('Coleta: concessão expirada ou inválida.');return job;
  }
  function heartbeat(c,data){
    const job=owned(c,data);db.prepare('UPDATE collectors SET last_seen=? WHERE id=?').run(now(),c.id);
    db.prepare('UPDATE collection_jobs SET lease_until=? WHERE id=?').run(Math.min(Date.now()+90000,job.deadline),job.id);
    return {cancelled:!!job.cancel_requested||Date.now()>=job.deadline};
  }
  function complete(c,data){
    const job=owned(c,data);
    if(!['completed','partial','failed','cancelled'].includes(data.status))throw new Error('Coleta: estado de resultado inválido.');
    const result=resultSchema(job.kind,data.result);
    if(['completed','partial'].includes(data.status)){
      const input=JSON.parse(job.input);
      if(job.kind==='aws'&&result.accountId!==input.accountId)throw new Error('Coleta: conta do resultado não corresponde ao trabalho.');
      if(job.kind==='internal'){
        const addresses=[...(result.dns?.a?.records||[]),...(result.dns?.aaaa?.records||[])];
        if(addresses.length)validateInternalAddresses(addresses,internalPolicy(JSON.parse(c.capabilities).internal),[]);
      }
    }
    db.prepare('UPDATE collection_jobs SET status=?,finished_at=?,result=?,lease_hash=NULL WHERE id=?').run(job.cancel_requested?'cancelled':data.status,now(),JSON.stringify(result),job.id);
    audit('collector:'+c.id,job.kind+'.'+(job.cancel_requested?'cancelled':data.status),job.id);return {ok:true};
  }
  function schedule(kind,id,input,actor){
    const table=kind==='internal'?'internal_assets':'aws_connections';if(typeof input.enabled!=='boolean')throw new Error('Coleta: agendamento inválido.');
    const interval=parseInterval(input.intervalHours??24),asset=db.prepare(`SELECT * FROM ${table} WHERE id=?`).get(id);if(!asset)throw new Error('Coleta: ativo não encontrado.');
    if(input.enabled){const c=collector(asset.collector_id,true);if(kind==='aws')validateAwsPolicy(JSON.parse(asset.config),c.capabilities.aws);}
    db.prepare(`UPDATE ${table} SET enabled=?,interval_hours=?,next_run=? WHERE id=?`).run(input.enabled?1:0,interval,input.enabled?new Date(Date.now()+interval*3600000).toISOString():null,id);audit(actor,kind+'.schedule',id);return {ok:true};
  }
  function cancel(id,actor){
    const job=db.prepare("SELECT * FROM collection_jobs WHERE id=? AND status IN ('queued','running')").get(id);if(!job)throw new Error('Coleta: trabalho pendente não encontrado.');
    if(job.status==='queued')db.prepare("UPDATE collection_jobs SET status='cancelled',finished_at=? WHERE id=?").run(now(),id);
    else db.prepare('UPDATE collection_jobs SET cancel_requested=1 WHERE id=?').run(id);
    audit(actor,'collection.cancel',id);return {ok:true};
  }
  function reap(){db.prepare("UPDATE collection_jobs SET status=CASE WHEN cancel_requested=1 THEN 'cancelled' ELSE 'interrupted' END,finished_at=?,lease_hash=NULL,result=? WHERE status='running' AND lease_until<=?").run(now(),JSON.stringify({error:'Coletor indisponível ou prazo excedido.'}),Date.now());}
  function tick(){reap();if(!canRun())return;for(const [kind,table] of [['internal','internal_assets'],['aws','aws_connections']])for(const asset of db.prepare(`SELECT id FROM ${table} WHERE enabled=1 AND next_run<=?`).all(now())){try{enqueue(kind,asset.id,'scheduler');}catch{db.prepare(`UPDATE ${table} SET next_run=? WHERE id=?`).run(new Date(Date.now()+60000).toISOString(),asset.id);}}}
  return {overview,createInternal,createAws,enqueue,authenticate,claim,heartbeat,complete,schedule,cancel,tick,job(id){return decoded(db.prepare('SELECT id,collector_id,kind,target_id,status,actor,created_at,started_at,finished_at,result FROM collection_jobs WHERE id=?').get(id));},register:input=>registerCollector(db,audit,input),revoke(id,actor){db.prepare('UPDATE collectors SET enabled=0 WHERE id=?').run(id);audit(actor,'collector.revoked',id);return {ok:true};}};
}
