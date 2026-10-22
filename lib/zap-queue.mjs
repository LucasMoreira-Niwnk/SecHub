import { randomUUID } from 'node:crypto';
import { readFileSync,writeFileSync,renameSync,existsSync,unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { validateZapRequest,ZAP_TIMEOUT_MS } from './zap.mjs';

export function createZapQueue({db,audit,spool=process.env.ZAP_SPOOL_DIR,canRun=()=>true}) {
  let stopped=false;
  const enabled=!!spool;
  const list=()=>db.prepare('SELECT z.*,d.hostname FROM zap_scans z JOIN domains d ON d.id=z.domain_id ORDER BY z.rowid DESC LIMIT 100').all().map(z=>({...z,request:JSON.parse(z.request),result:z.result?JSON.parse(z.result):null}));
  function status(){
    if(!enabled)return {enabled:false,ready:false};
    try{const s=JSON.parse(readFileSync(join(spool,'status.json'),'utf8'));return {enabled:true,ready:s.ready===true&&Date.now()-Date.parse(s.at)<30000,version:s.version};}catch{return {enabled:true,ready:false};}
  }
  function enqueue(asset,input,actor){
    if(!status().ready)throw new Error('ZAP: worker indisponível.');
    const request=validateZapRequest(asset.hostname,input);
    if(db.prepare("SELECT id FROM zap_scans WHERE domain_id=? AND status IN ('queued','running')").get(asset.id))throw new Error('ZAP: este host já tem um trabalho pendente.');
    if(db.prepare("SELECT count(*) AS n FROM zap_scans WHERE status IN ('queued','running')").get().n>=20)throw new Error('ZAP: fila cheia (20 trabalhos).');
    const last=db.prepare('SELECT created_at FROM zap_scans WHERE domain_id=? ORDER BY rowid DESC LIMIT 1').get(asset.id);
    if(last&&Date.now()-Date.parse(last.created_at)<60000)throw new Error('ZAP: aguarde um minuto entre trabalhos.');
    const id=randomUUID();
    db.prepare("INSERT INTO zap_scans(id,domain_id,actor,mode,status,created_at,request) VALUES(?,?,?,?,'queued',?,?)").run(id,asset.id,actor,request.mode,new Date().toISOString(),JSON.stringify(request));
    audit(actor,'zap.queued',`${asset.hostname} / ${request.mode}`);pump();return {id};
  }
  function pump(){
    if(stopped||!enabled||!canRun())return;
    for(const row of db.prepare("SELECT * FROM zap_scans WHERE status='running'").all()) {
      const path=join(spool,row.id+'.result.json');
      if(existsSync(path)) {
        try {
          const raw=readFileSync(path,'utf8');if(raw.length>1024*1024)throw new Error('Relatório excede o limite.');
          const result=JSON.parse(raw);
          if(!['completed','failed','interrupted','cancelled'].includes(result.status))throw new Error('Resultado inválido.');
          db.prepare('UPDATE zap_scans SET status=?,finished_at=?,result=? WHERE id=?').run(result.status,new Date().toISOString(),JSON.stringify(result.result),row.id);
          audit(row.actor,'zap.'+result.status,row.id);unlinkSync(path);
        }catch{db.prepare("UPDATE zap_scans SET status='failed',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify({error:'Resultado do worker inválido.'}),row.id);}
      } else if(Date.now()-Date.parse(row.started_at)>ZAP_TIMEOUT_MS+120000) {
        db.prepare("UPDATE zap_scans SET status='interrupted',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify({error:'Worker não concluiu dentro do prazo.'}),row.id);
      }
    }
    if(!status().ready||db.prepare("SELECT id FROM zap_scans WHERE status='running'").get())return;
    const row=db.prepare("SELECT * FROM zap_scans WHERE status='queued' ORDER BY rowid").all().find(r=>r.mode!=='sqli'||Date.parse(JSON.parse(r.request).windowStart)<=Date.now());if(!row)return;
    const request=JSON.parse(row.request);
    if(request.mode==='sqli'&&Date.now()<Date.parse(request.windowStart))return;
    if(request.mode==='sqli'&&Date.now()>=Date.parse(request.windowEnd)){
      db.prepare("UPDATE zap_scans SET status='failed',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify({error:'Janela operacional encerrada.'}),row.id);return;
    }
    // Persist dispatch before publishing; after a crash, the worker owns the lease.
    db.prepare("UPDATE zap_scans SET status='running',started_at=? WHERE id=?").run(new Date().toISOString(),row.id);
    try {
      const tmp=join(spool,row.id+'.tmp');
      writeFileSync(tmp,JSON.stringify({id:row.id,...request,expiresAt:Date.now()+60000}),{mode:0o640,flag:'wx'});
      renameSync(tmp,join(spool,row.id+'.job.json'));
    } catch {
      db.prepare("UPDATE zap_scans SET status='failed',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify({error:'Não foi possível enviar ao worker.'}),row.id);
    }
  }
  const timer=setInterval(pump,2000);timer.unref();
  function review(id,{findingId,status:reviewStatus,reason},actor){
    if(!['pending','confirmed','false-positive'].includes(reviewStatus)||typeof reason!=='string'||reason.length>500)throw new Error('ZAP: revisão inválida.');
    if(reviewStatus==='false-positive'&&!reason.trim())throw new Error('ZAP: informe o motivo do falso positivo.');
    const row=db.prepare("SELECT * FROM zap_scans WHERE id=? AND status='completed'").get(id);
    if(!row)throw new Error('ZAP: resultado não encontrado.');
    const result=JSON.parse(row.result),finding=result.findings.find(f=>f.id===findingId);
    if(!finding)throw new Error('ZAP: achado não encontrado.');
    Object.assign(finding,{review:reviewStatus,reviewReason:reason,reviewedBy:actor,reviewedAt:new Date().toISOString()});
    db.prepare('UPDATE zap_scans SET result=? WHERE id=?').run(JSON.stringify(result),id);
    audit(actor,'zap.review',`${id} / ${findingId} / ${reviewStatus}`);return {ok:true};
  }
  function cancel(id,actor){
    const row=db.prepare("SELECT * FROM zap_scans WHERE id=? AND status IN ('queued','running')").get(id);
    if(!row)throw new Error('ZAP: trabalho pendente não encontrado.');
    if(row.status==='queued')db.prepare("UPDATE zap_scans SET status='cancelled',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify({error:'Cancelado pelo operador.'}),id);
    else writeFileSync(join(spool,id+'.cancel'),'cancel',{mode:0o640});
    audit(actor,'zap.cancel.requested',id);return {ok:true};
  }
  return {enqueue,list,status,pump,review,cancel,stop(){stopped=true;clearInterval(timer);}};
}
