import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,rmSync,writeFileSync,readFileSync,existsSync,mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateZapRequest,zapPlan,normalizeZapReport } from '../lib/zap.mjs';
import { openStore } from '../lib/store.mjs';
import { createZapQueue } from '../lib/zap-queue.mjs';
import { resolveZapTarget } from '../lib/zap-scope.mjs';

const active=()=>({mode:'sqli',authorized:true,targets:['/search?q=sample'],windowStart:new Date(Date.now()-60000).toISOString(),windowEnd:new Date(Date.now()+3600000).toISOString()});
test('ZAP: política independente e DNS privado/misto bloqueados antes de criar contêiner',async()=>{
  const policy={allowedRoots:['example.com']},pub={family:4,address:'93.184.216.34'};
  assert.equal(await resolveZapTarget('app.example.com',policy,async()=>[pub]),pub.address);
  for(const records of [[],[{family:4,address:'127.0.0.1'}],[pub,{family:4,address:'10.4.0.70'}],[{family:4,address:'169.254.169.254'}],[{family:6,address:'2606:4700:4700::1111'}]])await assert.rejects(resolveZapTarget('app.example.com',policy,async()=>records));
  let called=false;await assert.rejects(resolveZapTarget('notexample.com',policy,async()=>{called=true;return [pub];}));assert.equal(called,false);
});
test('ZAP: modo ativo exige autorização, host exato, query explícita e janela limitada',()=>{
  const valid=validateZapRequest('app.example.com',active());assert.equal(valid.targets[0],'https://app.example.com/search?q=sample');
  for(const patch of [{authorized:false},{mode:'full'},{targets:['https://other.example.com/?q=1']},{targets:['http://app.example.com/?q=1']},{targets:['https://user:pw@app.example.com/?q=1']},{targets:['/logout?q=1']},{targets:['/search?token=secret']},{targets:['/search']},{windowEnd:new Date(Date.now()-1000).toISOString()},{windowEnd:new Date(Date.now()+5*3600000).toISOString()}])assert.throws(()=>validateZapRequest('app.example.com',{...active(),...patch}));
});
test('ZAP: baseline sem scan ativo; SQLi sem spider, apenas regra 40018, GET e query',()=>{
  const baseline=JSON.parse(zapPlan({hostname:'app.example.com',mode:'baseline'}));
  assert.ok(baseline.jobs.some(j=>j.type==='spider'));assert.ok(!baseline.jobs.some(j=>j.type==='activeScan'));
  const plan=JSON.parse(zapPlan({hostname:'app.example.com',...active()}));
  assert.ok(!plan.jobs.some(j=>j.type==='spider'));
  const scan=plan.jobs.find(j=>j.type==='activeScan');assert.equal(scan.policyDefinition.defaultThreshold,'Off');assert.deepEqual(scan.policyDefinition.rules.map(r=>r.id),[40018]);assert.equal(scan.parameters.threadPerHost,1);
  const config=plan.jobs.find(j=>j.type==='activeScan-config');assert.equal(config.inputVectors.postData.enabled,false);assert.equal(config.inputVectors.cookieData.enabled,false);
  const regex=new RegExp('^(?:'+plan.env.contexts[0].includePaths[0]+')$');
  // Context.isInContext strips query strings before matching the pattern.
  const inContext=url=>regex.test(url.split('?')[0]);
  assert.ok(inContext('https://app.example.com/search?q=test'));
  for(const url of ['https://other.example.com/search?q=1','https://app.example.com/search/other?q=1'])assert.ok(!inContext(url));
  assert.deepEqual(plan.jobs.find(j=>j.type==='requestor').requests.map(r=>r.url),['https://app.example.com/search?q=sample']);
  assert.equal(config.inputVectors.urlQueryStringAndDataDrivenNodes.addParam,false);
});
test('ZAP: normalização descarta payloads, HTML, parâmetros e hosts fora do escopo',()=>{
  const report={site:[{'@name':'https://other.example.com',alerts:[{pluginid:'999',name:'wrong'}]},{'@name':'https://app.example.com',alerts:[{pluginid:'40018',name:'SQL Injection',riskcode:'3',confidence:'2',cweid:'89',count:'2',solution:'<p>Use prepared statements</p>',instances:[{uri:'https://app.example.com/?token=SECRET',evidence:'SECRET',attack:'PAYLOAD'}]},{pluginid:'40018',name:'duplicate'}]}]};
  const result=normalizeZapReport(report,'app.example.com','sqli');
  assert.equal(result.findings.length,1);assert.equal(result.findings[0].severity,'high');assert.equal(result.findings[0].review,'pending');assert.doesNotMatch(JSON.stringify(result),/SECRET|PAYLOAD|<p>|wrong/);
  assert.throws(()=>normalizeZapReport({},'app.example.com','baseline'));
});
function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'sechub-zap-')),spool=join(dir,'spool');mkdirSync(spool);
  const {db,audit}=openStore(join(dir,'db'));
  const asset={id:'asset',hostname:'app.example.com'};
  db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run(asset.id,asset.hostname,new Date().toISOString());
  const ready=()=>writeFileSync(join(spool,'status.json'),JSON.stringify({ready:true,at:new Date().toISOString(),version:1}));
  ready();const queue=createZapQueue({db,audit,spool});
  return {db,audit,spool,queue,asset,ready,close(){queue.stop();db.close();rmSync(dir,{recursive:true,force:true});}};
}
test('ZAP: despacho persistido, duplicatas bloqueadas, resultado e revisão auditados',()=>{
  const f=fixture();try{
    const {id}=f.queue.enqueue(f.asset,{mode:'baseline'},'admin');
    assert.equal(f.queue.list()[0].status,'running');assert.ok(existsSync(join(f.spool,id+'.job.json')));
    assert.throws(()=>f.queue.enqueue(f.asset,{mode:'baseline'},'admin'),/pendente/);
    writeFileSync(join(f.spool,id+'.result.json'),JSON.stringify({status:'completed',result:{findings:[{id:'zap-40018',review:'pending'}]}}));
    f.queue.pump();assert.equal(f.queue.list()[0].status,'completed');
    assert.throws(()=>f.queue.review(id,{findingId:'zap-40018',status:'false-positive',reason:''},'admin'));
    f.queue.review(id,{findingId:'zap-40018',status:'false-positive',reason:'Validação manual em homologação.'},'admin');
    assert.equal(f.queue.list()[0].result.findings[0].review,'false-positive');
    assert.ok(f.db.prepare("SELECT id FROM audit WHERE action='zap.review'").get());
    const resumed=createZapQueue({db:f.db,audit:f.audit,spool:f.spool});assert.equal(resumed.list()[0].status,'completed');resumed.stop();
  }finally{f.close();}
});
test('ZAP: worker offline bloqueia novos jobs, execução sem retorno expira',()=>{
  const f=fixture();try{
    writeFileSync(join(f.spool,'status.json'),JSON.stringify({ready:true,at:'2000-01-01'}));
    assert.equal(f.queue.status().ready,false);assert.throws(()=>f.queue.enqueue(f.asset,{},'admin'),/indisponível/);
    f.ready();const {id}=f.queue.enqueue(f.asset,{},'admin');
    f.db.prepare('UPDATE zap_scans SET started_at=? WHERE id=?').run('2000-01-01',id);f.queue.pump();assert.equal(f.queue.list()[0].status,'interrupted');
  }finally{f.close();}
});
test('ZAP: janela futura preserva fila no reinício e não bloqueia baseline de outro host',()=>{
  const f=fixture();try{
    const future={...active(),windowStart:new Date(Date.now()+600000).toISOString()};
    const {id}=f.queue.enqueue(f.asset,future,'admin');assert.equal(f.queue.list()[0].status,'queued');assert.ok(!existsSync(join(f.spool,id+'.job.json')));
    f.db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run('other','other.example.com',new Date().toISOString());
    const second=f.queue.enqueue({id:'other',hostname:'other.example.com'},{},'admin');
    assert.ok(existsSync(join(f.spool,second.id+'.job.json')));
  }finally{f.close();}
});
test('ZAP: cancelamento de job futuro é persistido, e de job em execução é enviado ao worker',()=>{
  const f=fixture();try{
    const future={...active(),windowStart:new Date(Date.now()+600000).toISOString()};
    const {id}=f.queue.enqueue(f.asset,future,'admin');f.queue.cancel(id,'admin');assert.equal(f.queue.list()[0].status,'cancelled');
    f.db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run('other','other.example.com',new Date().toISOString());
    const running=f.queue.enqueue({id:'other',hostname:'other.example.com'},{},'admin');f.queue.cancel(running.id,'admin');assert.ok(existsSync(join(f.spool,running.id+'.cancel')));
  }finally{f.close();}
});
