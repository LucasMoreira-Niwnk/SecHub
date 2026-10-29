import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync,writeFileSync,existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import http from 'node:http';

async function start(port,dev,spool=''){
  const dir=mkdtempSync(join(tmpdir(),'sechub-api-'));
  const proc=spawn(process.execPath,['server.mjs'],{env:{...process.env,PORT:String(port),HOST:'127.0.0.1',APP_URL:`http://127.0.0.1:${port}`,DEV_MODE:String(dev),DATA_DIR:dir,ZAP_SPOOL_DIR:spool,SAML_ENTRY_POINT:'',SAML_IDP_ISSUER:'',SAML_IDP_CERT_PATH:'',ALLOWED_EMAILS:''},stdio:['ignore','pipe','pipe']});
  await Promise.race([once(proc.stdout,'data'),once(proc,'exit').then(()=>{throw new Error('Servidor não iniciou.');}),new Promise((_,reject)=>{const t=setTimeout(()=>reject(new Error('Timeout')),10000);t.unref();})]);
  return {origin:`http://127.0.0.1:${port}`,stop:async()=>{proc.kill();await once(proc,'exit');rmSync(dir,{recursive:true,force:true});}};
}
test('produção: API bloqueada sem SAML, metadados públicos e Host validado',async()=>{
  const server=await start(3197,false);
  try{
    assert.equal((await fetch(server.origin+'/api/overview')).status,401);
    assert.equal((await fetch(server.origin+'/api/aws/iam-policy')).status,401);
    assert.equal((await fetch(server.origin+'/api/collector/claim',{method:'POST'})).status,401);
    assert.equal((await fetch(server.origin+'/auth/saml/login')).status,503);
    assert.equal((await fetch(server.origin+'/auth/saml/acs',{method:'POST'})).status,503);
    assert.equal((await fetch(server.origin+'/auth/google')).status,404);
    const metadata=await(await fetch(server.origin+'/auth/saml/metadata')).text();
    assert.match(metadata,/AssertionConsumerService/);
    assert.match(metadata,/auth\/saml\/acs/);
    const response=await fetch(server.origin+'/api/session');
    assert.equal((await response.json()).user,null);
    assert.match(response.headers.get('content-security-policy'),/frame-ancestors 'none'/);
    const badHostStatus = await new Promise((resolve,reject)=>{
      http.get(server.origin+'/health',{headers:{Host:'evil.example'}},res=>{res.resume();resolve(res.statusCode);}).on('error',reject);
    });
    assert.equal(badHostStatus,400);
  }finally{await server.stop();}
});
test('ZAP API: entrega ao worker simulado, importa por host e audita revisão com CSRF',async()=>{
  const spool=mkdtempSync(join(tmpdir(),'sechub-zap-api-'));
  writeFileSync(join(spool,'status.json'),JSON.stringify({ready:true,at:new Date().toISOString(),version:1}));
  const server=await start(3199,true,spool);
  try{
    const auth=await(await fetch(server.origin+'/api/session')).json();
    const headers={'Content-Type':'application/json',Origin:server.origin,'X-CSRF-Token':auth.user.csrf};
    const post=(path,data,custom=headers)=>fetch(server.origin+path,{method:'POST',headers:custom,body:JSON.stringify(data)});
    const queued=await post('/api/domains/initial-domain/zap',{mode:'baseline'});assert.equal(queued.status,202);
    const {id}=await queued.json();assert.ok(existsSync(join(spool,id+'.job.json')));
    writeFileSync(join(spool,id+'.result.json'),JSON.stringify({status:'completed',result:{engine:'zap',mode:'baseline',findings:[{id:'zap-10020',source:'zap',title:'Fixture alert',severity:'low',review:'pending'}]}}));
    let overview;
    for(let i=0;i<30;i++){
      overview=await(await fetch(server.origin+'/api/overview')).json();
      if(overview.zapScans[0].status==='completed')break;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.equal(overview.domains[0].latest_zap[0].result.findings[0].id,'zap-10020');
    assert.equal((await post(`/api/zap/${id}/review`,{findingId:'zap-10020',status:'confirmed',reason:''},{})).status,403);
    assert.equal((await post(`/api/zap/${id}/review`,{findingId:'zap-10020',status:'confirmed',reason:''})).status,200);
    const reviewed=await(await fetch(server.origin+'/api/overview')).json();
    assert.equal(reviewed.domains[0].latest_zap[0].result.findings[0].review,'confirmed');
    assert.ok(reviewed.audit.some(a=>a.action==='zap.review'));
  }finally{await server.stop();rmSync(spool,{recursive:true,force:true});}
});
test('modo local: CSRF, cadastro, duplicatas, agenda e exportação',async()=>{
  const server=await start(3198,true);
  try{
    const auth=await(await fetch(server.origin+'/api/session')).json();
    const post=(path,data,headers={})=>fetch(server.origin+path,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(data)});
    assert.equal((await post('/api/domains',{hostname:'example.com'})).status,403);
    const headers={Origin:server.origin,'X-CSRF-Token':auth.user.csrf};
    assert.equal((await post('/api/domains',{hostname:'example.com',discoverSubdomains:false},headers)).status,201);
    assert.equal((await post('/api/domains',{hostname:'example.com'},headers)).status,409);
    assert.equal((await post('/api/domains',{hostname:'http://example.com'},headers)).status,400);
    assert.equal((await post('/api/domains',{hostname:'api.example.com',discoverSubdomains:false},headers)).status,201);
    const overview=await(await fetch(server.origin+'/api/overview')).json();
    const domain=overview.domains.find(d=>d.hostname==='example.com');
    assert.equal(overview.domains.find(d=>d.hostname==='api.example.com').parent_id,domain.id);
    assert.equal(overview.discoveries.length,0);
    assert.equal((await post(`/api/domains/${domain.id}/discover`,{})).status,403);
    assert.equal((await post(`/api/domains/${domain.id}/scan-tree`,{})).status,403);
    assert.equal(domain.enabled,0);
    assert.equal((await post(`/api/domains/${domain.id}/schedule`,{enabled:true,intervalHours:6},headers)).status,200);
    const after=await(await fetch(server.origin+'/api/overview')).json();
    assert.equal(after.domains.find(d=>d.id===domain.id).enabled,1);
    assert.ok(after.audit.length>=2);
    const exported=await(await fetch(server.origin+'/api/export')).json();
    assert.equal(exported.domains.length,3);
    assert.equal(exported.scans.length,0);
    const plan=await(await fetch(server.origin+`/api/domains/${domain.id}/zap-plan`)).text();
    assert.match(plan,/passiveScan-wait/);assert.ok(!JSON.parse(plan).jobs.some(j=>j.type==='activeScan'));
    assert.equal((await post(`/api/domains/${domain.id}/zap`,{mode:'baseline'})).status,403);
    assert.equal((await post(`/api/domains/${domain.id}/zap`,{mode:'baseline'},headers)).status,400);
    assert.equal(after.zap.enabled,false);
  }finally{await server.stop();}
});
test('API de coleta: registro protegido, claim/lease isolado, resultado autenticado e IAM preparado',async()=>{
  const server=await start(3201,true);
  try{
    const auth=await(await fetch(server.origin+'/api/session')).json();
    const headers={'Content-Type':'application/json',Origin:server.origin,'X-CSRF-Token':auth.user.csrf};
    const post=(path,value,custom=headers)=>fetch(server.origin+path,{method:'POST',headers:custom,body:JSON.stringify(value)});
    assert.equal((await post('/api/collectors',{name:'Fixture',zone:'corporate'},{})).status,403);
    const registration=await(await post('/api/collectors',{name:'Fixture',zone:'corporate'})).json();
    const worker={'Content-Type':'application/json',Authorization:'Bearer '+registration.token};
    const capabilities={internal:{suffixes:['casaeterra.com'],cidrs:['10.4.0.0/24'],dnsServers:['10.4.0.6']},aws:{roleArns:[],sourceProfiles:['sechub-source'],regions:['us-east-1','sa-east-1']}};
    assert.equal((await post('/api/collector/claim',{capabilities},worker)).status,200);
    const added=await post('/api/internal/assets',{collectorId:registration.id,hostname:'app.casaeterra.com'});assert.equal(added.status,201);const {id}=await added.json();
    const enqueued=await post(`/api/internal/assets/${id}/scan`,{});assert.equal(enqueued.status,202);
    const {job}=await(await post('/api/collector/claim',{capabilities},worker)).json();
    assert.ok(job.lease);assert.equal(job.kind,'internal');
    const overview=await(await fetch(server.origin+'/api/overview')).json();assert.ok(!JSON.stringify(overview).includes(registration.token));assert.ok(!JSON.stringify(overview).includes(job.lease));
    assert.equal((await post('/api/collector/result',{id:job.id,lease:'wrong',status:'completed'},worker)).status,400);
    assert.equal((await post('/api/collector/result',{id:job.id,lease:job.lease,status:'completed',result:{dns:{a:{records:['10.4.0.20']},aaaa:{records:[]}},web:{status:200},findings:[{code:'fixture',severity:'info',title:'Internal fixture'}]}},worker)).status,200);
    const result=await(await fetch(server.origin+'/api/collection-jobs/'+job.id)).json();assert.equal(result.result.findings[0].title,'Internal fixture');assert.equal(result.lease_hash,undefined);
    const aws=await post('/api/aws/connections',{collectorId:registration.id,name:'AWS fixture',accountId:'123456789012',roleArn:'arn:aws:iam::123456789012:role/ReadOnly',sourceProfile:'sechub-source',regions:['us-east-1','sa-east-1']});assert.equal(aws.status,201);
    const connection=await aws.json();assert.equal((await post(`/api/aws/connections/${connection.id}/scan`,{})).status,400);
    const policy=await(await fetch(server.origin+'/api/aws/iam-policy')).json();assert.ok(policy.Statement[0].Action.every(a=>/:(?:List|Get)/.test(a)));
    assert.equal((await post('/api/collectors/'+registration.id+'/revoke',{})).status,200);
    assert.equal((await post('/api/collector/claim',{capabilities},worker)).status,401);
  }finally{await server.stop();}
});
