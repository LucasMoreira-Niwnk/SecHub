import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import { normalizeDomain, isPublicIP, validateGoogleClaims, parseInterval } from '../lib/security.mjs';
import { openStore } from '../lib/store.mjs';
import { verifyGoogleJWT } from '../lib/auth.mjs';

test('domínios: normalização e rejeição de URLs, IPs e payloads',()=>{
  assert.equal(normalizeDomain('CasaETerra.COM.'),'casaeterra.com');
  for(const input of ['https://example.com','localhost','127.0.0.1','example.com:443','example.com/path','a..com','-a.com',"a.com'; DROP TABLE domains;"]) assert.throws(()=>normalizeDomain(input));
});
test('rede: bloqueia endereços privados, metadata, documentação e transição IPv6',()=>{
  for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','172.16.0.1','192.168.1.1','0.0.0.0','100.64.0.1','198.18.0.1','203.0.113.2','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1','2002:7f00:1::1','2001::1']) assert.equal(isPublicIP(ip),false,ip);
  for(const ip of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(isPublicIP(ip),true,ip);
});
test('SSO: valida emissor, audience, domínio hd, nonce e email verificado',()=>{
  const valid={iss:'https://accounts.google.com',aud:'client',hd:'casaeterra.com',email:'admin@casaeterra.com',email_verified:true,nonce:'nonce',sub:'123',iat:1000,exp:2000};
  const options={clientId:'client',domain:'casaeterra.com',nonce:'nonce',now:1500};
  assert.equal(validateGoogleClaims(valid,options).sub,'123');
  for(const patch of [{hd:'attacker.com'},{aud:'other'},{email_verified:false},{nonce:'replay'},{iss:'https://evil.com'},{exp:1400},{exp:'2000'},{iat:3000},{email:'admin@other.com'}]) assert.throws(()=>validateGoogleClaims({...valid,...patch},options));
});
test('JWT Google: rejeita assinatura forjada e algoritmo não autorizado',async()=>{
  const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const {privateKey:otherKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const key={...publicKey.export({format:'jwk'}),kid:'test-key'};
  const original=globalThis.fetch;
  globalThis.fetch=async()=>({ok:true,json:async()=>({keys:[key]})});
  try {
    const head=Buffer.from(JSON.stringify({alg:'RS256',kid:'test-key'})).toString('base64url');
    const payload=Buffer.from(JSON.stringify({iss:'accounts.google.com',aud:'client',hd:'casaeterra.com',email:'admin@casaeterra.com',email_verified:true,nonce:'abc',sub:'123',iat:1000,exp:2000})).toString('base64url');
    const data=head+'.'+payload;
    const options={clientId:'client',domain:'casaeterra.com',nonce:'abc',now:1500};
    assert.equal((await verifyGoogleJWT(data+'.'+sign('RSA-SHA256',Buffer.from(data),privateKey).toString('base64url'),options)).sub,'123');
    await assert.rejects(verifyGoogleJWT(data+'.'+sign('RSA-SHA256',Buffer.from(data),otherKey).toString('base64url'),options));
    await assert.rejects(verifyGoogleJWT(Buffer.from('{"alg":"none"}').toString('base64url')+'.'+payload+'.fake',options));
  } finally {globalThis.fetch=original;}
});
test('agenda e persistência: valida limites e marca jobs interrompidos após reinício',()=>{
  for(const n of [0,-1,169,1.5,'x']) assert.throws(()=>parseInterval(n));
  assert.equal(parseInterval(24),24);
  const dir=mkdtempSync(join(tmpdir(),'sechub-test-'));
  let store=openStore(dir);
  store.db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run('1','example.com',new Date().toISOString());
  store.db.prepare('INSERT INTO scans(id,domain_id,status,started_at) VALUES(?,?,?,?)').run('job','1','running',new Date().toISOString());
  store.audit('test','domain.created','example.com');store.db.close();
  store=openStore(dir);
  assert.equal(store.db.prepare('SELECT status FROM scans').get().status,'interrupted');
  assert.equal(store.db.prepare('SELECT count(*) AS n FROM audit').get().n,1);
  assert.throws(()=>store.db.prepare('INSERT INTO domains(id,hostname,created_at) VALUES(?,?,?)').run('2','example.com','now'));
  store.db.close();rmSync(dir,{recursive:true,force:true});
});
