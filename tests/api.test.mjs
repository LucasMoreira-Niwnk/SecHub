import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import http from 'node:http';

async function start(port,dev){
  const dir=mkdtempSync(join(tmpdir(),'sechub-api-'));
  const proc=spawn(process.execPath,['server.mjs'],{env:{...process.env,PORT:String(port),HOST:'127.0.0.1',APP_URL:`http://127.0.0.1:${port}`,DEV_MODE:String(dev),DATA_DIR:dir,SAML_ENTRY_POINT:'',SAML_IDP_ISSUER:'',SAML_IDP_CERT_PATH:'',ALLOWED_EMAILS:''},stdio:['ignore','pipe','pipe']});
  await Promise.race([once(proc.stdout,'data'),once(proc,'exit').then(()=>{throw new Error('Servidor não iniciou.');}),new Promise((_,reject)=>{const t=setTimeout(()=>reject(new Error('Timeout')),10000);t.unref();})]);
  return {origin:`http://127.0.0.1:${port}`,stop:async()=>{proc.kill();await once(proc,'exit');rmSync(dir,{recursive:true,force:true});}};
}
test('produção: API bloqueada sem SAML, metadados públicos e Host validado',async()=>{
  const server=await start(3197,false);
  try{
    assert.equal((await fetch(server.origin+'/api/overview')).status,401);
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
    assert.match(plan,/passiveScan-wait/);assert.doesNotMatch(plan,/type: activeScan/);
  }finally{await server.stop();}
});
