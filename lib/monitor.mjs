import { randomUUID } from 'node:crypto';
import { scanDomain } from './scanner.mjs';
import { isPublicIP } from './security.mjs';

export function createMonitor({db,audit,scan=scanDomain,canRun=()=>true}) {
  const running=new Set();let stopped=false;
  function enqueue(assets,actor) {
    const queued=[],skipped=[];
    db.exec('BEGIN');
    try {
      for(const asset of assets) {
        const busy=db.prepare("SELECT id FROM scans WHERE domain_id=? AND status IN ('queued','running')").get(asset.id);
        const recent=db.prepare('SELECT started_at FROM scans WHERE domain_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1').get(asset.id);
        if(busy || (recent&&Date.now()-Date.parse(recent.started_at)<60000)) {skipped.push({id:asset.id,reason:busy?'pending':'cooldown'});continue;}
        const id=randomUUID();
        db.prepare('INSERT INTO scans(id,domain_id,actor,status,started_at) VALUES(?,?,?,?,?)').run(id,asset.id,actor,'queued',new Date().toISOString());
        db.prepare('UPDATE domains SET next_run=? WHERE id=?').run(new Date(Date.now()+asset.interval_hours*3600000).toISOString(),asset.id);
        audit(actor,'scan.queued',asset.hostname);queued.push(id);
      }
      db.exec('COMMIT');
    } catch(error){db.exec('ROLLBACK');throw error;}
    pump();return {queued,skipped};
  }
  function pump() {
    if(stopped||!canRun())return;
    while(running.size<2) {
      const job=db.prepare("SELECT scans.*,domains.hostname FROM scans JOIN domains ON domains.id=scans.domain_id WHERE scans.status='queued' ORDER BY scans.rowid LIMIT 1").get();
      if(!job)break;
      running.add(job.domain_id);
      db.prepare("UPDATE scans SET status='running',started_at=? WHERE id=?").run(new Date().toISOString(),job.id);
      audit(job.actor,'scan.started',job.hostname);
      void (async()=>{
        try {
          const result=await scan(job.hostname);
          if(stopped)return;
          db.prepare("UPDATE scans SET status='completed',finished_at=?,result=? WHERE id=?").run(result.finished,JSON.stringify(result),job.id);
          const addresses=[...new Set([...(result.dns?.a?.records||[]),...(result.dns?.aaaa?.records||[])])];
          if(result.dns) {
            const errors=[result.dns.a?.error,result.dns.aaaa?.error].filter(Boolean);
            const dnsState=addresses.length?(addresses.every(isPublicIP)?'public':'private'):(errors.some(e=>!['ENODATA','ENOTFOUND'].includes(e))?'error':'unresolved');
            db.prepare('UPDATE domains SET dns_state=?,addresses=?,dns_checked_at=? WHERE id=?').run(dnsState,JSON.stringify(addresses),result.finished,job.domain_id);
          }
          audit(job.actor,'scan.completed',job.hostname);
        } catch(error) {
          if(stopped)return;
          db.prepare("UPDATE scans SET status='failed',finished_at=?,result=? WHERE id=?").run(new Date().toISOString(),JSON.stringify({error:String(error.message).slice(0,250)}),job.id);
          audit(job.actor,'scan.failed',job.hostname);
        } finally {running.delete(job.domain_id);if(!stopped)pump();}
      })();
    }
  }
  return {running,enqueue,pump,stop(){stopped=true;}};
}
