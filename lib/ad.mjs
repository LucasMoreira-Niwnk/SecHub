import {createHash,randomUUID} from 'node:crypto';
import {token,hash} from './auth.mjs';

export const AD_IDS=[4624,4625,4672,4728,4732,4740,4756,4768,4769,4771,4776,1102,4719];
const clean=(v,n=180)=>String(v??'').replace(/[\x00-\x1f\x7f]/g,'').slice(0,n);
const digest=v=>createHash('sha256').update(v).digest('hex');
const fail=message=>{throw new Error('AD: '+message);};
const defaults={failureThreshold:10,sprayThreshold:5,windowMinutes:10,offHours:false,startHour:7,endHour:20,timeZone:'America/Sao_Paulo',ignoredAccounts:[],privilegedAccounts:[],serviceAccounts:[]};
export function adRules(value={}){
  const out={...defaults,...value};
  for(const [key,min,max] of [['failureThreshold',3,100],['sprayThreshold',3,100],['windowMinutes',1,60],['startHour',0,23],['endHour',1,24]])if(!Number.isInteger(out[key])||out[key]<min||out[key]>max)fail('limites de detecção inválidos.');
  if(typeof out.offHours!=='boolean'||out.startHour>=out.endHour)fail('horário inválido.');
  try{new Intl.DateTimeFormat('en',{timeZone:out.timeZone}).format();}catch{fail('fuso horário inválido.');}
  const list=key=>{if(!Array.isArray(out[key])||out[key].length>100||out[key].some(v=>typeof v!=='string'||v.length>180))fail('lista de contas inválida.');return [...new Set(out[key].map(v=>clean(v).toLowerCase()).filter(Boolean))];};
  return {failureThreshold:out.failureThreshold,sprayThreshold:out.sprayThreshold,windowMinutes:out.windowMinutes,offHours:out.offHours,startHour:out.startHour,endHour:out.endHour,timeZone:out.timeZone,ignoredAccounts:list('ignoredAccounts'),privilegedAccounts:list('privilegedAccounts'),serviceAccounts:list('serviceAccounts')};
}
export function normalizeAdEvent(value){
  if(!value||typeof value!=='object'||!AD_IDS.includes(value.eventId)||!Number.isSafeInteger(value.recordId)||value.recordId<1)fail('evento inválido.');
  const time=Date.parse(value.time);
  if(!Number.isFinite(time)||time>Date.now()+300000||time<Date.now()-30*86400000)fail('evento fora da retenção de 30 dias.');
  const event={eventId:value.eventId,recordId:value.recordId,time:new Date(time).toISOString(),computer:clean(value.computer),user:clean(value.user).toLowerCase(),domain:clean(value.domain).toLowerCase(),actor:clean(value.actor).toLowerCase(),ip:clean(value.ip,64),workstation:clean(value.workstation),logonType:clean(value.logonType,8),status:clean(value.status,32).toLowerCase(),group:clean(value.group),groupSid:clean(value.groupSid),member:clean(value.member,300)};
  if(['-','::','0.0.0.0','127.0.0.1','::1'].includes(event.ip))event.ip='';
  event.ip=event.ip.replace(/^::ffff:/i,'');
  const ok=['','0','0x0','0x00000000'].includes(event.status);
  event.outcome=value.eventId===4625||value.eventId===4771||[4768,4769,4776].includes(value.eventId)&&!ok?'failure':value.eventId===4624||[4768,4769,4776].includes(value.eventId)&&ok?'success':'activity';
  return event;
}
export function registerAdSource(db,{name,controller}){
  if(!/^[a-z0-9][a-z0-9.-]{0,252}$/i.test(controller||'')||!String(name||'').trim()||name.length>80)fail('nome ou controlador inválido.');
  const id=randomUUID(),secret=token();
  db.prepare('INSERT INTO ad_sources(id,name,controller,token_hash,created_at) VALUES(?,?,?,?,?)').run(id,name.trim(),controller.toLowerCase(),hash(secret),new Date().toISOString());return {id,token:secret};
}
export function createAd({db,audit}){
  const rules=()=>adRules(JSON.parse(db.prepare("SELECT value FROM settings WHERE key='ad_rules'").get()?.value||'{}'));
  function overview(){return {sources:db.prepare('SELECT id,name,controller,enabled,last_seen,last_success,status,error,backlog,created_at FROM ad_sources').all().map(s=>({...s,online:!!s.enabled&&Date.now()-Date.parse(s.last_seen||0)<180000})),rules:rules(),events:db.prepare('SELECT * FROM ad_events ORDER BY time DESC LIMIT 100').all().map(e=>({...JSON.parse(e.data),id:e.id,sourceId:e.source_id})),alerts:db.prepare('SELECT id,source_id,rule,title,severity,account,origin,created_at,status,review_reason,reviewed_by FROM ad_alerts ORDER BY created_at DESC LIMIT 100').all(),counts:{events:db.prepare('SELECT count(*) n FROM ad_events').get().n,openAlerts:db.prepare("SELECT count(*) n FROM ad_alerts WHERE status='pending'").get().n},retentionDays:30};}
  function alert(source,event,rule,title,severity,account,origin,ids){
    const bucket=Math.floor(Date.parse(event.time)/600000),id=digest([source.id,rule,account,origin,bucket].join('|'));
    const evidence=ids.slice(-20).map(id=>{const row=db.prepare('SELECT data FROM ad_events WHERE id=?').get(id);return row?{id,...JSON.parse(row.data)}:null;}).filter(Boolean);
    db.prepare("INSERT OR IGNORE INTO ad_alerts(id,source_id,rule,title,severity,account,origin,created_at,status,evidence) VALUES(?,?,?,?,?,?,?,?,'pending',?)").run(id,source.id,rule,title,severity,account,origin,event.time,JSON.stringify(evidence));
  }
  function detect(source,e,id,r){
    const account=e.user?(e.domain?e.domain+'\\':'')+e.user:'';
    const listed=list=>list.includes(account)||list.includes(e.user);
    if(listed(r.ignoredAccounts))return;
    const origin=e.ip||e.workstation,window=new Date(Date.parse(e.time)-r.windowMinutes*60000).toISOString();
    const recent=(field,value,outcome)=>db.prepare(`SELECT id,account,origin FROM ad_events WHERE source_id=? AND ${field}=? AND outcome=? AND time>=? AND time<=? ORDER BY time`).all(source.id,value,outcome,window,e.time);
    // Use only concrete credential rejection codes for brute-force correlation.
    const credentialFailure=e.eventId===4625&&['0xc000006a','0xc000006d','0xc0000064'].includes(e.status)||e.eventId===4771&&['0x18','0x6'].includes(e.status)||e.eventId===4776&&['0xc000006a','0xc000006d','0xc0000064'].includes(e.status);
    if(credentialFailure&&account){
      const attempts=recent('account',account,'failure');if(attempts.length>=r.failureThreshold)alert(source,e,'repeated-failures','Falhas repetidas de autenticação','high',account,'',attempts.map(a=>a.id));
      if(origin){const attempts=recent('origin',origin,'failure');if(new Set(attempts.map(a=>a.account).filter(Boolean)).size>=r.sprayThreshold)alert(source,e,'password-spray','Falhas contra várias contas na mesma origem','high','',origin,attempts.map(a=>a.id));}
    }
    if(e.outcome==='success'&&account&&!e.user.endsWith('$')){
      const failures=recent('account',account,'failure');
      if(failures.length>=r.failureThreshold)alert(source,e,'success-after-failures','Autenticação aceita após falhas repetidas','high',account,origin,[...failures.map(a=>a.id),id]);
      if(e.eventId===4624){
        const hour=Number(new Intl.DateTimeFormat('en-GB',{timeZone:r.timeZone,hour:'2-digit',hourCycle:'h23'}).format(new Date(e.time)));
        if(r.offHours&&['2','7','10','11'].includes(e.logonType)&&(hour<r.startHour||hour>=r.endHour))alert(source,e,'off-hours','Login interativo fora do horário configurado','medium',account,origin,[id]);
        if(listed(r.serviceAccounts)&&['2','10','11'].includes(e.logonType))alert(source,e,'service-interactive','Conta de serviço usada em login interativo','high',account,origin,[id]);
        if(listed(r.privilegedAccounts))alert(source,e,'privileged-login','Autenticação de conta privilegiada monitorada','medium',account,origin,[id]);
        if(origin){
          const history=db.prepare("SELECT min(time) first,count(*) n FROM ad_events WHERE source_id=? AND account=? AND outcome='success' AND time<?").get(source.id,account,window);
          const known=db.prepare("SELECT id FROM ad_events WHERE source_id=? AND account=? AND origin=? AND outcome='success' AND time<? LIMIT 1").get(source.id,account,origin,e.time);
          if(history.n>=20&&Date.parse(e.time)-Date.parse(history.first)>=7*86400000&&!known)alert(source,e,'new-origin','Login de origem ainda não observada para a conta','medium',account,origin,[id]);
        }
      }
    }
    if(e.eventId===4740)alert(source,e,'account-lockout','Conta bloqueada pelo AD','medium',account,origin,[id]);
    if([4728,4732,4756].includes(e.eventId)&&/-(512|518|519|544|548|549|550|551|552)$/.test(e.groupSid))alert(source,e,'privileged-membership','Membro adicionado a grupo privilegiado','high',e.member,e.actor,[id]);
    if([1102,4719].includes(e.eventId))alert(source,e,'audit-change',e.eventId===1102?'Log de segurança apagado':'Política de auditoria alterada','high',e.actor,'',[id]);
  }
  function ingest(source,data){
    if(!Array.isArray(data.events)||data.events.length>500||!['ok','credentials_pending','error'].includes(data.status))fail('lote inválido.');
    const allowedErrors=['','CREDENTIALS_PENDING','CONFIG_INVALID','AUTH_FAILED','ACCESS_DENIED','WINRM_UNAVAILABLE','EVENT_QUERY_FAILED','INVALID_RESPONSE','LOG_RESET','LOG_GAP'];
    if(!allowedErrors.includes(data.error||'')||data.status!=='ok'&&data.events.length)fail('estado do lote inválido.');
    const events=data.events.map(normalizeAdEvent).sort((a,b)=>a.time.localeCompare(b.time)||a.recordId-b.recordId),r=rules();let inserted=0;
    db.exec('BEGIN IMMEDIATE');
    try{
      for(const e of events){
        const id=digest([source.id,e.recordId,e.eventId,e.time].join('|')),account=e.user?(e.domain?e.domain+'\\':'')+e.user:'',origin=e.ip||e.workstation;
        const result=db.prepare('INSERT OR IGNORE INTO ad_events(id,source_id,time,event_id,account,origin,outcome,data) VALUES(?,?,?,?,?,?,?,?)').run(id,source.id,e.time,e.eventId,account,origin,e.outcome,JSON.stringify(e));
        if(result.changes){inserted++;detect(source,e,id,r);}
      }
      const now=new Date().toISOString();db.prepare('UPDATE ad_sources SET last_seen=?,last_success=CASE WHEN ?=\'ok\' THEN ? ELSE last_success END,status=?,error=?,backlog=? WHERE id=?').run(now,data.status,now,data.status,data.error||'',data.backlog?1:0,source.id);
      db.exec('COMMIT');
    }catch(e){db.exec('ROLLBACK');throw e;}
    return {ok:true,inserted};
  }
  return {overview,ingest,authenticate(secret){if(typeof secret!=='string'||secret.length<32||secret.length>200)return null;return db.prepare('SELECT * FROM ad_sources WHERE token_hash=? AND enabled=1').get(hash(secret));},configure(input,actor){const value=adRules(input);db.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES('ad_rules',?)").run(JSON.stringify(value));audit(actor,'ad.rules.updated','Limiares e contas monitoradas');return {ok:true};},alert(id){const row=db.prepare('SELECT * FROM ad_alerts WHERE id=?').get(id);return row?{...row,evidence:JSON.parse(row.evidence)}:null;},review(id,input,actor){if(!['pending','confirmed','false-positive'].includes(input.status)||typeof input.reason!=='string'||!input.reason.trim()||input.reason.length>1000)fail('informe estado e justificativa de revisão.');if(!db.prepare('SELECT id FROM ad_alerts WHERE id=?').get(id))fail('alerta não encontrado.');db.prepare('UPDATE ad_alerts SET status=?,review_reason=?,reviewed_by=? WHERE id=?').run(input.status,clean(input.reason,1000),actor,id);audit(actor,'ad.alert.review',id);return {ok:true};},prune(){db.prepare('DELETE FROM ad_events WHERE time<?').run(new Date(Date.now()-30*86400000).toISOString());db.exec('DELETE FROM ad_events WHERE id IN (SELECT id FROM ad_events ORDER BY time DESC LIMIT -1 OFFSET 200000)');db.prepare('DELETE FROM ad_alerts WHERE created_at<?').run(new Date(Date.now()-90*86400000).toISOString());db.exec('DELETE FROM ad_alerts WHERE id IN (SELECT id FROM ad_alerts ORDER BY created_at DESC LIMIT -1 OFFSET 20000)');}};
}
