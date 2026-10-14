import { Resolver } from 'node:dns/promises';
import { randomUUID } from 'node:crypto';
import { normalizeDomain,isPublicIP } from './security.mjs';
import { withinDomain,relinkHierarchy,MAX_ASSETS,MAX_SUBDOMAINS } from './inventory.mjs';

export function certificateNames(rows,parent) {
  if(!Array.isArray(rows)) throw new Error('INVALID_SOURCE_RESPONSE');
  const found=new Set();
  for(const row of rows) {
    if(typeof row?.name_value!=='string') continue;
    for(const raw of row.name_value.split(/[\r\n]+/)) {
      if(raw.includes('*')) continue;
      try {const name=normalizeDomain(raw);if(withinDomain(name,parent))found.add(name);} catch {}
    }
  }
  return [...found].sort();
}

export async function fetchCertificates(parent,fetcher=fetch) {
  const url=new URL('https://crt.sh/');
  url.searchParams.set('q','%.'+parent);url.searchParams.set('output','json');
  const response=await fetcher(url,{signal:AbortSignal.timeout(20000),redirect:'error',headers:{Accept:'application/json','User-Agent':'CasaTerra-SecHUB/0.3'}});
  if(!response.ok) throw new Error('SOURCE_HTTP_'+response.status);
  const reader=response.body.getReader();let size=0;const chunks=[];
  try {
    while(true) {
      const {value,done}=await reader.read();if(done)break;
      size+=value.length;if(size>4*1024*1024)throw new Error('SOURCE_RESPONSE_TOO_LARGE');chunks.push(Buffer.from(value));
    }
  } finally {await reader.cancel().catch(()=>{});}
  let rows;try{rows=JSON.parse(Buffer.concat(chunks).toString());}catch{throw new Error('INVALID_SOURCE_RESPONSE');}
  return certificateNames(rows,parent);
}

export async function probeDNS(host,resolver=new Resolver({timeout:2000,tries:2})) {
  const answers=await Promise.all(['resolve4','resolve6'].map(async method=>{
    try{return {records:await resolver[method](host),error:null};}catch(error){return {records:[],error:error.code||'DNS_ERROR'};}
  }));
  const addresses=[...new Set(answers.flatMap(a=>a.records))];
  const errors=answers.map(a=>a.error).filter(Boolean);
  const state=addresses.length?(addresses.every(isPublicIP)?'public':'private'):(errors.some(e=>!['ENODATA','ENOTFOUND'].includes(e))?'error':'unresolved');
  return {state,addresses,checkedAt:new Date().toISOString()};
}

export function createDiscovery({db,audit,fetchNames=fetchCertificates,probe=probeDNS}) {
  let active=false,stopped=false;
  function enqueue(asset,actor) {
    const pending=db.prepare("SELECT id FROM discoveries WHERE domain_id=? AND status IN ('queued','running')").get(asset.id);
    if(pending) return {id:pending.id,existing:true};
    const last=db.prepare('SELECT started_at FROM discoveries WHERE domain_id=? ORDER BY rowid DESC LIMIT 1').get(asset.id);
    if(last && Date.now()-Date.parse(last.started_at)<600000) return {cooldown:true};
    const id=randomUUID();
    db.prepare('INSERT INTO discoveries(id,domain_id,actor,status,started_at) VALUES(?,?,?,?,?)').run(id,asset.id,actor,'queued',new Date().toISOString());
    audit(actor,'discovery.queued',asset.hostname);void pump();return {id};
  }
  async function pump() {
    if(active||stopped)return;
    const job=db.prepare("SELECT discoveries.*,domains.hostname,domains.interval_hours FROM discoveries JOIN domains ON domains.id=discoveries.domain_id WHERE discoveries.status='queued' ORDER BY discoveries.rowid LIMIT 1").get();
    if(!job)return;
    active=true;
    db.prepare("UPDATE discoveries SET status='running' WHERE id=?").run(job.id);
    try {
      const names=await fetchNames(job.hostname);
      if(!Array.isArray(names))throw new Error('INVALID_SOURCE_RESPONSE');
      const valid=[...new Set(names.flatMap(name=>{try{const normalized=normalizeDomain(name);return withinDomain(normalized,job.hostname)?[normalized]:[];}catch{return [];}}))].sort();
      const scoped=valid.slice(0,MAX_SUBDOMAINS);
      let added=0,processed=0,capacitySkipped=0;
      for(let offset=0;offset<scoped.length;offset+=4) {
        if(stopped)return;
        const batch=await Promise.all(scoped.slice(offset,offset+4).map(async hostname=>({hostname,dns:await probe(hostname)})));
        if(stopped)return;
        for(const {hostname,dns} of batch) {
          const known=db.prepare('SELECT id FROM domains WHERE hostname=?').get(hostname);
          if(!known && db.prepare('SELECT count(*) AS n FROM domains').get().n>=MAX_ASSETS){capacitySkipped++;continue;}
          const id=known?.id||randomUUID();
          if(!known) {
            db.prepare('INSERT INTO domains(id,hostname,interval_hours,created_at,parent_id,source) VALUES(?,?,?,?,?,?)').run(id,hostname,job.interval_hours,new Date().toISOString(),job.domain_id,'crt.sh');
            added++;
          }
          db.prepare('UPDATE domains SET dns_state=?,addresses=?,dns_checked_at=? WHERE id=?').run(dns.state,JSON.stringify(dns.addresses),dns.checkedAt,id);
          processed++;
        }
      }
      relinkHierarchy(db);
      const result={source:'crt.sh',found:valid.length,processed,added,limited:valid.length>MAX_SUBDOMAINS||capacitySkipped>0,capacitySkipped};
      db.prepare("UPDATE discoveries SET status='completed',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify(result),job.id);
      audit(job.actor,'discovery.completed',`${job.hostname}: ${added} novos / ${processed} consultados`);
    } catch(error) {
      if(stopped)return;
      const code=/^SOURCE_HTTP_\d+$|^SOURCE_RESPONSE_TOO_LARGE$|^INVALID_SOURCE_RESPONSE$/.test(error.message)?error.message:'SOURCE_UNAVAILABLE';
      db.prepare("UPDATE discoveries SET status='failed',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify({error:code}),job.id);
      audit(job.actor,'discovery.failed',job.hostname+': '+code);
    } finally {active=false;if(!stopped)void pump();}
  }
  return {enqueue,pump,stop(){stopped=true;}};
}
