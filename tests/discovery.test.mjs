import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { certificateNames,fetchCertificates,probeDNS,createDiscovery } from '../lib/discovery.mjs';
import { openStore } from '../lib/store.mjs';
import { inventory,relinkHierarchy } from '../lib/inventory.mjs';
import { createMonitor } from '../lib/monitor.mjs';

const eventually=async check=>{for(let i=0;i<200;i++){if(check())return;await new Promise(resolve=>setTimeout(resolve,5));}assert.fail('Trabalho não terminou.');};
function fixture() {
  const dir=mkdtempSync(join(tmpdir(),'sechub-discovery-'));
  const store=openStore(dir);
  const add=(id,hostname)=>store.db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run(id,hostname,new Date().toISOString());
  return {...store,add,close(){store.db.close();rmSync(dir,{recursive:true,force:true});}};
}

test('certificados: normaliza, deduplica, exclui wildcards e nomes fora do domínio',()=>{
  assert.deepEqual(certificateNames([{name_value:'EXAMPLE.COM\nAPI.EXAMPLE.COM\nwww.example.com\n*.example.com'},{name_value:'api.example.com.\nexample.com.evil.test\nx.notexample.com\na..example.com\nhttps://api.example.com\nvpn.dev.example.com'}],'example.com'),['api.example.com','vpn.dev.example.com','www.example.com']);
  assert.throws(()=>certificateNames({},'example.com'));
});

test('fonte CT: host fixo, timeout, erro HTTP, JSON inválido e limite de resposta',async()=>{
  const names=await fetchCertificates('example.com',async(url,options)=>{
    assert.equal(url.hostname,'crt.sh');assert.equal(url.searchParams.get('q'),'%.example.com');assert.equal(options.redirect,'error');assert.ok(options.signal);
    return new Response(JSON.stringify([{name_value:'api.example.com'}]));
  });
  assert.deepEqual(names,['api.example.com']);
  await assert.rejects(fetchCertificates('example.com',async()=>new Response('bad',{status:503})),/SOURCE_HTTP_503/);
  await assert.rejects(fetchCertificates('example.com',async()=>new Response('invalid json')),/INVALID_SOURCE_RESPONSE/);
  await assert.rejects(fetchCertificates('example.com',async()=>new Response('x'.repeat(4*1024*1024+1))),/SOURCE_RESPONSE_TOO_LARGE/);
});

test('DNS: distingue público, privado/misto, ausência e erro temporário sem acessar HTTPS',async()=>{
  const fail=code=>{const e=new Error();e.code=code;throw e;};
  for(const [v4,v6,state] of [[['8.8.8.8'],[],'public'],[['10.0.0.1'],[],'private'],[['8.8.8.8','192.168.1.1'],[],'private'],[[],[],'unresolved']]) {
    const result=await probeDNS('api.example.com',{resolve4:async()=>v4.length?v4:fail('ENODATA'),resolve6:async()=>v6.length?v6:fail('ENODATA')});
    assert.equal(result.state,state);
  }
  assert.equal((await probeDNS('api.example.com',{resolve4:async()=>fail('ETIMEOUT'),resolve6:async()=>fail('ENODATA')})).state,'error');
});

test('descoberta: persiste filhos com agenda pausada, mantém os existentes e limita o escopo',async()=>{
  const f=fixture();let discovery;
  try {
    f.add('root','example.com');f.add('known','api.example.com');
    f.db.prepare('UPDATE domains SET enabled=1 WHERE id=?').run('known');
    discovery=createDiscovery({...f,fetchNames:async()=>['api.example.com','www.example.com','api.example.com','bad.other.com','a..example.com'],probe:async()=>({state:'public',addresses:['8.8.8.8'],checkedAt:new Date().toISOString()})});
    const job=discovery.enqueue(f.db.prepare('SELECT * FROM domains WHERE id=?').get('root'),'tester');
    await eventually(()=>f.db.prepare('SELECT status FROM discoveries WHERE id=?').get(job.id).status==='completed');
    const all=inventory(f.db);
    assert.equal(all.length,3);assert.equal(all.find(d=>d.hostname==='www.example.com').parent_id,'root');
    assert.equal(all.find(d=>d.hostname==='www.example.com').enabled,0);assert.equal(all.find(d=>d.id==='known').enabled,1);
    assert.equal(all.find(d=>d.id==='known').source,'manual');
    assert.equal(all.find(d=>d.hostname==='www.example.com').dns_state,'public');
    const result=JSON.parse(f.db.prepare('SELECT result FROM discoveries WHERE id=?').get(job.id).result);
    assert.equal(result.added,1);assert.equal(result.found,2);
    assert.equal(discovery.enqueue(f.db.prepare('SELECT * FROM domains WHERE id=?').get('root'),'tester').cooldown,true);
  }finally{discovery?.stop();f.close();}
});

test('descoberta: indisponibilidade da fonte não apaga inventário nem vira resultado vazio',async()=>{
  const f=fixture();let discovery;
  try {
    f.add('root','example.com');f.add('known','api.example.com');
    discovery=createDiscovery({...f,fetchNames:async()=>{throw new Error('PRIVATE_UPSTREAM_ERROR');}});
    const job=discovery.enqueue(f.db.prepare('SELECT * FROM domains WHERE id=?').get('root'),'tester');
    await eventually(()=>f.db.prepare('SELECT status FROM discoveries WHERE id=?').get(job.id).status==='failed');
    assert.equal(inventory(f.db).length,2);
    assert.equal(JSON.parse(f.db.prepare('SELECT result FROM discoveries WHERE id=?').get(job.id).result).error,'SOURCE_UNAVAILABLE');
  }finally{discovery?.stop();f.close();}
});

test('hierarquia: usa ancestral mais próximo sem confundir sufixos; preserva resultado fora do histórico recente',()=>{
  const f=fixture();
  try {
    f.add('leaf','api.dev.example.com');f.add('other','notexample.com');f.add('root','example.com');f.add('middle','dev.example.com');
    relinkHierarchy(f.db);
    assert.equal(f.db.prepare('SELECT parent_id FROM domains WHERE id=?').get('leaf').parent_id,'middle');
    assert.equal(f.db.prepare('SELECT parent_id FROM domains WHERE id=?').get('middle').parent_id,'root');
    assert.equal(f.db.prepare('SELECT parent_id FROM domains WHERE id=?').get('other').parent_id,null);
    const add=f.db.prepare('INSERT INTO scans(id,domain_id,status,started_at,result) VALUES(?,?,?,?,?)');
    add.run('old','root','completed','2020-01-01',JSON.stringify({findings:[]}));
    for(let i=0;i<105;i++)add.run('new'+i,'other','completed','2021-01-01',JSON.stringify({findings:[]}));
    assert.equal(inventory(f.db).find(d=>d.id==='root').latest_completed_scan.id,'old');
  }finally{f.close();}
});

test('fila: no máximo duas varreduras simultâneas, sem duplicatas e com resultados por host',async()=>{
  const f=fixture();let monitor;const release=[];let active=0,max=0;
  try {
    for(let i=0;i<4;i++)f.add('host'+i,`host${i}.example.com`);
    monitor=createMonitor({...f,scan:async()=>{active++;max=Math.max(max,active);await new Promise(resolve=>release.push(resolve));active--;return {finished:new Date().toISOString(),dns:{a:{records:['8.8.8.8']},aaaa:{records:[]}},web:{status:200},findings:[]};}});
    const assets=f.db.prepare('SELECT * FROM domains').all();
    const first=monitor.enqueue(assets,'tester');assert.equal(first.queued.length,4);assert.equal(monitor.running.size,2);
    assert.equal(f.db.prepare("SELECT count(*) AS n FROM scans WHERE status='queued'").get().n,2);
    assert.equal(monitor.enqueue(assets,'tester').queued.length,0);
    release.splice(0).forEach(resolve=>resolve());
    await eventually(()=>release.length===2);
    release.splice(0).forEach(resolve=>resolve());
    await eventually(()=>f.db.prepare("SELECT count(*) AS n FROM scans WHERE status='completed'").get().n===4);
    assert.equal(max,2);assert.equal(inventory(f.db).every(d=>d.latest_completed_scan&&d.dns_state==='public'),true);
    assert.equal(monitor.enqueue(assets,'tester').skipped.length,4);
  }finally{monitor?.stop();release.forEach(resolve=>resolve());f.close();}
});

test('fila: trabalhos pendentes sobrevivem ao reinício do banco',()=>{
  const dir=mkdtempSync(join(tmpdir(),'sechub-queue-restart-'));
  let f=openStore(dir);
  f.db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run('root','example.com',new Date().toISOString());
  const monitor=createMonitor({...f,canRun:()=>false});
  monitor.enqueue(f.db.prepare('SELECT * FROM domains').all(),'tester');monitor.stop();f.db.close();
  f=openStore(dir);
  assert.equal(f.db.prepare('SELECT status FROM scans').get().status,'queued');
  f.db.close();rmSync(dir,{recursive:true,force:true});
});
