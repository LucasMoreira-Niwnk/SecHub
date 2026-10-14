import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizeDomain, isPublicIP, parseInterval } from '../lib/security.mjs';
import { openStore } from '../lib/store.mjs';

test('domínios: normalização e rejeição de URLs, IPs e payloads',()=>{
  assert.equal(normalizeDomain('CasaETerra.COM.'),'casaeterra.com');
  for(const input of ['https://example.com','localhost','127.0.0.1','example.com:443','example.com/path','a..com','-a.com',"a.com'; DROP TABLE domains;"]) assert.throws(()=>normalizeDomain(input));
});
test('rede: bloqueia endereços privados, metadata, documentação e transição IPv6',()=>{
  for(const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','172.16.0.1','192.168.1.1','0.0.0.0','100.64.0.1','198.18.0.1','203.0.113.2','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::1','2002:7f00:1::1','2001::1']) assert.equal(isPublicIP(ip),false,ip);
  for(const ip of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(isPublicIP(ip),true,ip);
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
