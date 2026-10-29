import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openStore} from '../lib/store.mjs';
import {createAd,registerAdSource,adRules,normalizeAdEvent} from '../lib/ad.mjs';

function fixture(){const dir=mkdtempSync(join(tmpdir(),'sechub-ad-')),store=openStore(dir),ad=createAd(store),registration=registerAdSource(store.db,{name:'DC test',controller:'10.20.0.6'});return {...store,ad,registration,source:ad.authenticate(registration.token),close(){store.db.close();rmSync(dir,{recursive:true,force:true});}};}
let seq=0;
const event=(overrides={})=>({eventId:4625,recordId:++seq,time:new Date(Date.now()-60000+seq).toISOString(),user:'User1',domain:'CORP',ip:'::ffff:10.20.0.30',status:'0xc000006a',...overrides});
const batch=events=>({status:'ok',events});
test('AD: normalização e regras rejeitam dados inválidos e descartam campos arbitrários',()=>{
  const e=normalizeAdEvent(event({password:'secret',Message:'not retained'}));assert.equal(e.ip,'10.20.0.30');assert.equal(e.user,'user1');assert.equal(e.outcome,'failure');assert.ok(!JSON.stringify(e).includes('secret'));
  assert.throws(()=>normalizeAdEvent(event({eventId:1})));assert.throws(()=>normalizeAdEvent(event({time:'bad'})));assert.throws(()=>normalizeAdEvent(event({recordId:-1})));assert.throws(()=>adRules({failureThreshold:0}));assert.throws(()=>adRules({timeZone:'invalid'}));assert.throws(()=>adRules({ignoredAccounts:'admin'}));assert.equal(adRules().offHours,false);
});
test('AD: ingestão transacional, reentrega deduplicada, tokens opacos e falhas explícitas',()=>{
  const f=fixture();try{const e=event();assert.equal(f.ad.authenticate('bad'),null);assert.equal(f.ad.ingest(f.source,batch([e])).inserted,1);assert.equal(f.ad.ingest(f.source,batch([e])).inserted,0);assert.ok(!JSON.stringify(f.ad.overview()).includes(f.registration.token));assert.throws(()=>f.ad.ingest(f.source,batch([event(),event({eventId:2})])));assert.equal(f.ad.overview().counts.events,1);assert.throws(()=>f.ad.ingest(f.source,{status:'error',error:'password=secret',events:[]}));f.ad.ingest(f.source,{status:'credentials_pending',error:'CREDENTIALS_PENDING',events:[]});assert.equal(f.ad.overview().sources[0].status,'credentials_pending');assert.throws(()=>f.ad.ingest(f.source,batch(Array(501).fill(e))));}finally{f.close();}
});
test('AD: correlação entre lotes detecta falhas, spray e sucesso; revisão é auditada',()=>{
  const f=fixture();try{f.ad.configure({failureThreshold:3,sprayThreshold:3},'admin');const attempts=Array.from({length:3},()=>event());f.ad.ingest(f.source,batch(attempts.slice(0,2)));assert.equal(f.ad.overview().alerts.length,0);f.ad.ingest(f.source,batch(attempts.slice(2)));assert.ok(f.ad.overview().alerts.some(a=>a.rule==='repeated-failures'));f.ad.ingest(f.source,batch([event({eventId:4624,status:'0x0',logonType:'3'}),event({user:'user2'}),event({user:'user3'})]));const alerts=f.ad.overview().alerts;assert.ok(alerts.some(a=>a.rule==='success-after-failures'));assert.ok(alerts.some(a=>a.rule==='password-spray'));assert.ok(!alerts.some(a=>a.rule==='new-origin'));const id=alerts[0].id;assert.ok(f.ad.alert(id).evidence.length);assert.throws(()=>f.ad.review(id,{status:'confirmed',reason:''},'reviewer'));f.ad.review(id,{status:'false-positive',reason:'Teste autorizado'},'reviewer');assert.equal(f.ad.alert(id).reviewed_by,'reviewer');assert.equal(f.db.prepare("SELECT count(*) n FROM audit WHERE action='ad.alert.review'").get().n,1);f.ad.ingest(f.source,batch(attempts));assert.equal(f.ad.overview().alerts.length,alerts.length);}finally{f.close();}
});
test('AD: tipos interativos, contas declaradas e SIDs de grupos evitam alarmes indevidos',()=>{
  const f=fixture();try{f.ad.configure({serviceAccounts:['corp\\svc'],privilegedAccounts:['admin'],ignoredAccounts:['ignored'],offHours:true,startHour:8,endHour:9,timeZone:'UTC'},'admin');f.ad.ingest(f.source,batch([event({eventId:4624,user:'svc',status:'0x0',logonType:'10'}),event({eventId:4624,user:'admin',status:'0x0',logonType:'3'}),event({eventId:4740,user:'ignored'}),event({eventId:4728,groupSid:'S-1-5-21-1-513',member:'normal'}),event({eventId:4728,groupSid:'S-1-5-21-1-512',member:'admin2'}),event({eventId:1102,actor:'corp\\operator'}),event({eventId:4740,user:'locked'})]));const alerts=f.ad.overview().alerts;assert.ok(alerts.some(a=>a.rule==='service-interactive'));assert.ok(alerts.some(a=>a.rule==='privileged-login'));assert.equal(alerts.filter(a=>a.rule==='privileged-membership').length,1);assert.equal(alerts.filter(a=>a.rule==='account-lockout').length,1);assert.ok(alerts.some(a=>a.rule==='audit-change'));assert.ok(!alerts.some(a=>a.account.includes('ignored')));}finally{f.close();}
});
test('AD: nova origem só alerta após histórico suficiente; retenção preserva evidência do alerta',()=>{
  const f=fixture();try{const prior=Array.from({length:20},()=>event({eventId:4624,status:'0x0',time:new Date(Date.now()-8*86400000+seq).toISOString(),ip:'10.20.0.10'}));f.ad.ingest(f.source,batch(prior));f.ad.ingest(f.source,batch([event({eventId:4624,status:'0x0',logonType:'10',ip:'10.20.0.99'})]));const alert=f.ad.overview().alerts.find(a=>a.rule==='new-origin');assert.ok(alert);f.db.prepare('UPDATE ad_events SET time=?').run(new Date(Date.now()-31*86400000).toISOString());f.ad.prune();assert.equal(f.ad.overview().counts.events,0);assert.equal(f.ad.alert(alert.id).evidence.length,1);}finally{f.close();}
});
