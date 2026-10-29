import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openStore } from '../lib/store.mjs';
import { createCollections } from '../lib/collections.mjs';
import { privateCIDR,internalPolicy,validateInternalAddresses,createInternalResolver } from '../lib/internal-scope.mjs';
import { scanDomain } from '../lib/scanner.mjs';

const policy={suffixes:['casaeterra.com'],cidrs:['10.7.0.0/16'],dnsServers:['10.7.0.6'],blockedCidrs:['10.7.0.9/32']};
const capabilities={internal:policy,aws:{roleArns:['arn:aws:iam::123456789012:role/SecHubReadOnly'],sourceProfiles:['sechub-source'],regions:['us-east-1','sa-east-1']}};
test('escopo interno: CIDRs privados explícitos, bloqueio de público, metadata, coletor e DNS misto',()=>{
  for(const value of ['10.7.0.0/16','172.16.0.0/12','192.168.0.0/16','fd12::/16'])assert.equal(privateCIDR(value),value);
  for(const value of ['0.0.0.0/0','10.0.0.0/0','172.31.0.0/8','8.8.8.0/24','127.0.0.0/8','169.254.0.0/16','::/0'])assert.throws(()=>privateCIDR(value));
  assert.deepEqual(validateInternalAddresses(['10.7.0.20'],policy,[]),['10.7.0.20']);
  for(const addresses of [[],['10.8.0.20'],['10.7.0.9'],['10.7.0.6'],['127.0.0.1'],['169.254.169.254'],['10.7.0.20','8.8.8.8']])assert.throws(()=>validateInternalAddresses(addresses,policy,[]));
  assert.throws(()=>validateInternalAddresses(['10.7.0.20'],policy,['10.7.0.20']));
  assert.throws(()=>validateInternalAddresses(['fd00:ec2::254'],{cidrs:['fd00::/8'],blockedCidrs:[]},[]));
  assert.throws(()=>internalPolicy({cidrs:'10.7.0.0/16'}));
});
test('resolvedor interno: DNS explícito, hostname exato e sufixo delimitado, sem fallback público',async()=>{
  let servers;
  const resolver={setServers(v){servers=v;},async resolve4(){return ['10.7.0.20'];},async resolve6(){throw Object.assign(new Error(),{code:'ENODATA'});}};
  const scoped=createInternalResolver('app.casaeterra.com',policy,resolver);
  assert.deepEqual(servers,['10.7.0.6']);assert.deepEqual(await scoped.resolveHost('app.casaeterra.com'),['10.7.0.20']);
  await assert.rejects(scoped.resolveHost('other.casaeterra.com'));
  assert.throws(()=>createInternalResolver('notcasaeterra.com',policy,resolver));
  resolver.resolve6=async()=>{throw Object.assign(new Error(),{code:'ETIMEOUT'});};await assert.rejects(scoped.resolveHost('app.casaeterra.com'));
});
test('baseline interno não consulta TXT nem gera falsos achados SPF/DMARC',async()=>{
  const resolver={async resolve4(){return ['10.7.0.20'];},async resolve6(){return [];},async resolveTxt(){throw new Error('TXT não deve ser consultado');}};
  const result=await scanDomain('app.casaeterra.com',{resolver,emailChecks:false,resolveHost:async()=>{throw new Error('BLOCKED_TEST');}});
  assert.deepEqual(Object.keys(result.dns),['a','aaaa']);
  assert.ok(!result.findings.some(f=>/spf|dmarc/.test(f.code)));
  assert.equal(result.web,null);
});
function fixture(){
  const dir=mkdtempSync(join(tmpdir(),'sechub-collections-'));const store=openStore(dir),hub=createCollections(store);
  const registration=hub.register({name:'Corporate',zone:'corporate'});
  const auth=()=>hub.authenticate(registration.token);
  hub.claim(auth(),capabilities);
  return {...store,hub,auth,registration,dir,close(){store.db.close();rmSync(dir,{recursive:true,force:true});}};
}
test('coletor: token opaco, capacidades públicas sem segredos, ativos por zona e fila autenticada',()=>{
  const f=fixture();try{
    assert.ok(!JSON.stringify(f.hub.overview()).includes(f.registration.token));
    assert.equal(f.hub.authenticate('bad'),null);
    const asset=f.hub.createInternal({collectorId:f.registration.id,hostname:'app.casaeterra.com'},'admin');
    assert.equal(f.hub.overview().internalAssets[0].enabled,0);
    assert.throws(()=>f.hub.createInternal({collectorId:f.registration.id,hostname:'outside.example.com'},'admin'));
    const job=f.hub.enqueue('internal',asset.id,'admin');assert.equal(f.hub.enqueue('internal',asset.id,'admin').existing,true);
    const claim=f.hub.claim(f.auth(),capabilities).job;assert.equal(claim.id,job.id);
    assert.equal(f.hub.claim(f.auth(),capabilities).job,null);
    assert.throws(()=>f.hub.complete(f.auth(),{id:claim.id,lease:'wrong',status:'completed',result:{}}));
    f.hub.complete(f.auth(),{id:claim.id,lease:claim.lease,status:'completed',result:{dns:{a:{records:['10.7.0.20']},aaaa:{records:[]}},web:{status:200},findings:[{code:'test',title:'Test',severity:'info'}],Credentials:{SecretAccessKey:'NOT_PERSISTED'}}});
    assert.equal(f.hub.job(job.id).status,'completed');assert.equal(f.hub.job(job.id).result.findings.length,1);
    assert.equal(f.hub.overview().internalAssets[0].latest.result.findingCount,1);
    assert.ok(!JSON.stringify(f.hub.job(job.id)).includes('NOT_PERSISTED'));
    assert.throws(()=>f.hub.complete(f.auth(),{id:claim.id,lease:claim.lease,status:'completed',result:{}}));
  }finally{f.close();}
});
test('coletor: lease sobrevive ao reinício, expira sem redisparo e cancelamento é confirmado pelo worker',()=>{
  const f=fixture();try{
    const a=f.hub.createInternal({collectorId:f.registration.id,hostname:'app.casaeterra.com'},'admin');f.hub.enqueue('internal',a.id,'admin');const claim=f.hub.claim(f.auth(),capabilities).job;
    const other=openStore(f.dir);assert.equal(other.db.prepare('SELECT status FROM collection_jobs WHERE id=?').get(claim.id).status,'running');other.db.close();
    f.hub.cancel(claim.id,'admin');assert.equal(f.hub.heartbeat(f.auth(),claim).cancelled,true);
    f.hub.complete(f.auth(),{...claim,status:'cancelled',result:{}});assert.equal(f.hub.job(claim.id).status,'cancelled');
    const b=f.hub.createInternal({collectorId:f.registration.id,hostname:'second.casaeterra.com'},'admin');f.hub.enqueue('internal',b.id,'admin');const expired=f.hub.claim(f.auth(),capabilities).job;
    f.db.prepare('UPDATE collection_jobs SET lease_until=0 WHERE id=?').run(expired.id);f.hub.tick();
    assert.equal(f.hub.job(expired.id).status,'interrupted');assert.equal(f.hub.claim(f.auth(),capabilities).job,null);
    assert.throws(()=>f.hub.complete(f.auth(),{...expired,status:'completed',result:{}}));
    f.hub.revoke(f.registration.id,'admin');assert.equal(f.auth(),null);
  }finally{f.close();}
});
test('AWS: conexão pode ficar preparada, mas executar exige política local e conta correta no resultado',()=>{
  const f=fixture();try{
    const input={collectorId:f.registration.id,name:'Casa & Terra',accountId:'123456789012',roleArn:'arn:aws:iam::123456789012:role/SecHubReadOnly',sourceProfile:'sechub-source',regions:['us-east-1','sa-east-1']};
    const a=f.hub.createAws(input,'admin');assert.equal(f.hub.overview().awsConnections[0].enabled,0);
    f.hub.enqueue('aws',a.id,'admin');const claim=f.hub.claim(f.auth(),capabilities).job;
    assert.throws(()=>f.hub.complete(f.auth(),{...claim,status:'completed',result:{accountId:'999999999999',findings:[]}}));
    f.hub.complete(f.auth(),{...claim,status:'partial',result:{accountId:input.accountId,findings:[],sources:[{source:'securityhub',region:'us-east-1',status:'error',error:'AccessDenied'}]}});
    assert.equal(f.hub.job(claim.id).status,'partial');
    const other=f.hub.createAws({...input,roleArn:'arn:aws:iam::123456789012:role/NotApproved'},'admin');assert.throws(()=>f.hub.enqueue('aws',other.id,'admin'),/política/);
  }finally{f.close();}
});
