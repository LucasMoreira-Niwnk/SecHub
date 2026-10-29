import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openStore} from '../lib/store.mjs';
import {registerAdSource} from '../lib/ad.mjs';
import {dashboardRange,createDashboard} from '../lib/dashboard.mjs';
const now=new Date('2026-10-29T15:00:00Z');
test('dashboard: dias de Brasília, limites inclusivos, intervalo personalizado e parâmetros rejeitados',()=>{
  const one=dashboardRange(new URLSearchParams('days=1'),now);assert.equal(one.from,'2026-10-29T03:00:00.000Z');assert.equal(one.to,'2026-10-30T03:00:00.000Z');
  const seven=dashboardRange(new URLSearchParams('days=7'),now);assert.equal(seven.start,'2026-10-23');assert.equal(seven.buckets.length,7);
  assert.equal(dashboardRange(new URLSearchParams('days=1'),new Date('2026-10-29T01:00:00Z')).start,'2026-10-28');
  const custom=dashboardRange(new URLSearchParams('start=2026-10-20&end=2026-10-22&accounts=all'),now);assert.equal(custom.days,3);assert.equal(custom.to,'2026-10-23T03:00:00.000Z');
  for(const params of ['days=31','days=0','days=7x','accounts=invalid','start=2026-02-30&end=2026-03-01','start=2026-10-29','start=2026-10-29&end=2026-10-28','start=2026-10-01&end=2026-10-30','start=2026-09-29&end=2026-10-01'])assert.throws(()=>dashboardRange(new URLSearchParams(params),now),/Dashboard:/);
});
test('dashboard: agrega além dos últimos 100 eventos, separa contas e respeita fronteiras de datas',()=>{
  const dir=mkdtempSync(join(tmpdir(),'sechub-dashboard-')),store=openStore(dir),source=registerAdSource(store.db,{name:'DC fixture',controller:'10.20.0.6'});let seq=0;
  const add=(account,outcome,time='2026-10-29T12:00:00.000Z',eventId=outcome==='success'?4624:4625)=>{const user=account.split('\\').at(-1);store.db.prepare('INSERT INTO ad_events(id,source_id,time,event_id,account,origin,outcome,data) VALUES(?,?,?,?,?,?,?,?)').run(String(++seq),source.id,time,eventId,account,'10.20.0.30',outcome,JSON.stringify({user}));};
  try{
    for(let i=0;i<125;i++)add('corp\\alice','success');for(let i=0;i<12;i++)add('corp\\bob','failure');for(let i=0;i<200;i++)add('corp\\machine$','success');add('nt authority\\anonymous logon','success');
    add('corp\\alice','success','2026-10-29T02:59:59.999Z');add('corp\\alice','success','2026-10-30T03:00:00.000Z');add('corp\\alice','success','2026-10-29T03:00:00.000Z',4769);
    const dashboard=createDashboard(store.db),one=dashboard.build(new URLSearchParams('days=1'),now);
    assert.equal(one.ad.totals.successes,126);assert.equal(one.ad.totals.failures,12);assert.equal(one.ad.totals.accounts,2);assert.equal(one.ad.totals.logons,125);assert.equal(one.ad.topSuccess[0].account,'corp\\alice');assert.equal(one.ad.topFailures[0].account,'corp\\bob');assert.equal(one.ad.series[0].successes,126);assert.equal(one.ad.origins[0].accounts,1);
    assert.equal(dashboard.build(new URLSearchParams('days=1&accounts=machines'),now).ad.totals.successes,200);
    assert.equal(dashboard.build(new URLSearchParams('days=1&accounts=all'),now).ad.totals.successes,327);
    const seven=dashboard.build(new URLSearchParams('days=7'),now);assert.equal(seven.ad.totals.successes,127);assert.equal(seven.ad.series.at(-2).successes,1);assert.equal(seven.ad.series[0].successes,0);assert.equal(seven.ad.coverage.retainedEvents,seq);
    const empty=dashboard.build(new URLSearchParams('start=2026-10-20&end=2026-10-20'),now);assert.equal(empty.ad.totals.successes,0);assert.deepEqual(empty.ad.topSuccess,[]);assert.equal(empty.ad.series[0].failures,0);
    store.db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run('dashboard-fixture','example.test',now.toISOString());
    const insert=store.db.prepare("INSERT INTO scans(id,domain_id,status,started_at) VALUES(?,'dashboard-fixture','completed',?)");for(let i=0;i<121;i++)insert.run('scan-'+i,'2026-10-29T12:00:00.000Z');insert.run('old-scan','2026-10-28T12:00:00.000Z');
    store.db.prepare("INSERT INTO ad_alerts(id,source_id,rule,title,severity,account,origin,created_at,status,evidence) VALUES(?,?,'test','Test','high','corp\\alice','','2026-10-29T12:00:00.000Z','pending','[]')").run('alert',source.id);
    const activity=dashboard.build(new URLSearchParams('days=1'),now);assert.equal(activity.modules.public[0].count,121);assert.equal(activity.ad.alertStats.pending,1);assert.equal(activity.ad.alertsByRule[0].count,1);
  }finally{store.db.close();rmSync(dir,{recursive:true,force:true});}
});
