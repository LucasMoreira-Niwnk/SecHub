import test from 'node:test';
import assert from 'node:assert/strict';
import { Resolver } from 'node:dns/promises';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { scanDomain, inspectHTTPS } from '../lib/scanner.mjs';

test('scanner: DNS privé bloqueia HTTPS; redirecionamentos e evidência respeitam escopo',async()=>{
  const methods=['resolve4','resolve6','resolveMx','resolveNs','resolveTxt'];
  const saved=Object.fromEntries(methods.map(m=>[m,Resolver.prototype[m]]));
  const savedGet=https.get;
  let address='10.0.0.1', calls=0, location=null;
  try {
    for(const m of methods) Resolver.prototype[m]=async host=>m==='resolve4'?[address]:m==='resolveTxt'?(host.startsWith('_dmarc.')?[['v=DMARC1; p=reject']]:[['v=spf1 -all']]):[];
    https.get=(opts,cb)=>{
      calls++;
      assert.equal(opts.rejectUnauthorized,true);
      assert.equal(opts.servername,'example.com');
      opts.lookup('example.com',{all:true},(err,answers)=>assert.equal(answers[0].address,address));
      const req=new EventEmitter();req.destroy=()=>req.emit('close');
      queueMicrotask(()=>{
        cb({statusCode:location?302:200,headers:location?{location}:{'set-cookie':['session=SECRET; Path=/'], 'strict-transport-security':'max-age=31536000'},socket:{getProtocol:()=> 'TLSv1.3',getPeerCertificate:()=>({issuer:{O:'Test CA'},valid_to:new Date(Date.now()+90*86400000).toUTCString()})},destroy(){req.emit('close');}});
      });return req;
    };
    await assert.rejects(inspectHTTPS('example.com'),/privado/);assert.equal(calls,0);
    address='8.8.8.8';location='https://evil.example/';
    const redirect=await inspectHTTPS('example.com');assert.equal(redirect.redirectOutsideScope,true);assert.equal(calls,1);
    location=null;const result=await scanDomain('example.com');
    assert.equal(result.web.status,200);
    assert.ok(result.findings.some(f=>f.code==='cookie-secure'));
    assert.ok(result.findings.some(f=>f.code==='content-security-policy'));
    assert.ok(!result.findings.some(f=>f.code==='spf-missing'||f.code==='dmarc-policy'));
    assert.ok(!JSON.stringify(result).includes('SECRET'));
    assert.equal(result.coverage.sqlInjection,'não testado');
  } finally {for(const m of methods)Resolver.prototype[m]=saved[m];https.get=savedGet;}
});
