// Installed as root-owned code, outside the writable application checkout.
import { readdirSync,readFileSync,writeFileSync,renameSync,unlinkSync,openSync,closeSync,fstatSync,mkdtempSync,chownSync,chmodSync,rmSync,existsSync,constants } from 'node:fs';
import { join } from 'node:path';
import { execFile,spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { validateZapRequest,zapPlan,normalizeZapReport,ZAP_TIMEOUT_MS } from '../lib/zap.mjs';
import { resolveZapTarget } from '../lib/zap-scope.mjs';

const exec=promisify(execFile);
const spool='/var/spool/sechub-zap',work='/var/lib/sechub-zap-worker';
const policy=JSON.parse(readFileSync('/etc/sechub-zap/policy.json','utf8'));
if(!/^ghcr\.io\/zaproxy\/zaproxy@sha256:[a-f0-9]{64}$/.test(policy.image))throw new Error('Imagem deve ser fixada por digest.');
const idPattern=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
let stopping=false,ready=false,currentContainer;
function readJSON(path,max=65536){
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const s=fstatSync(fd);if(!s.isFile()||s.size>max)throw new Error('Arquivo inválido.');return JSON.parse(readFileSync(fd,'utf8'));}finally{closeSync(fd);}
}
function publish(name,value){
  const tmp=join(spool,'.worker-'+randomUUID()+'.tmp');
  writeFileSync(tmp,JSON.stringify(value),{mode:0o640,flag:'wx'});renameSync(tmp,join(spool,name));
}
const heartbeat=setInterval(()=>publish('status.json',{ready,at:new Date().toISOString(),version:1}),5000);
const docker=(...args)=>exec('/usr/bin/docker',args,{timeout:120000,maxBuffer:1024*1024});
const firewall=(...args)=>exec('/usr/sbin/iptables',['-w','5',...args],{timeout:10000});
async function seal(){
  // Block first, then remove old allowances: never expose an empty chain.
  await firewall('-I','SECHUB_ZAP','1','-j','DROP');
  const {stdout}=await firewall('-S','SECHUB_ZAP');
  const rules=stdout.split('\n').filter(line=>line.startsWith('-A SECHUB_ZAP '));
  for(let i=1;i<rules.length;i++)await firewall('-D','SECHUB_ZAP','2');
}
async function runContainer(args,timeout,id){
  return new Promise((resolve,reject)=>{
    const child=spawn('/usr/bin/docker',args,{stdio:['ignore','pipe','pipe']});
    // Raw logs can include HTTP evidence; consume without persisting them.
    child.stdout.resume();child.stderr.resume();
    const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('ZAP: tempo máximo excedido.'));},timeout);
    let cancelled=false;
    const cancelTimer=setInterval(()=>{if(existsSync(join(spool,id+'.cancel'))&&!cancelled){cancelled=true;void docker('rm','-f','sechub-zap-'+id);}},1000);
    child.on('error',e=>{clearTimeout(timer);clearInterval(cancelTimer);reject(e);});
    child.on('close',code=>{clearTimeout(timer);clearInterval(cancelTimer);if(cancelled)return reject(new Error('ZAP: cancelado pelo operador.'));code===0?resolve():reject(new Error('ZAP: execução falhou; confira runtime e plano.'));});
  });
}
async function execute(job){
  if(!idPattern.test(job.id))throw new Error('ZAP: identificador inválido.');
  if(!Number.isFinite(job.expiresAt)||job.expiresAt<Date.now())throw new Error('ZAP: despacho expirado; envie um novo trabalho.');
  if(existsSync(join(spool,job.id+'.cancel')))throw new Error('ZAP: cancelado pelo operador.');
  const r=validateZapRequest(job.hostname,job);
  if(r.mode==='sqli'&&(!policy.activeEnabled||Date.now()<Date.parse(r.windowStart)||Date.now()>=Date.parse(r.windowEnd)))throw new Error('ZAP: teste ativo desabilitado ou fora da janela.');
  const address=await resolveZapTarget(r.hostname,policy);
  const dir=mkdtempSync(join(work,'job-'));
  const name='sechub-zap-'+job.id;currentContainer=name;
  try {
    writeFileSync(join(dir,'plan.yaml'),zapPlan(r),{mode:0o644});
    chownSync(dir,1000,1000);chmodSync(dir,0o700);
    await seal();
    await firewall('-I','SECHUB_ZAP','1','-d',address,'-p','tcp','--dport','443','-j','RETURN');
    const timeout=Math.min(ZAP_TIMEOUT_MS,r.mode==='sqli'?Date.parse(r.windowEnd)-Date.now():ZAP_TIMEOUT_MS);
    await runContainer(['run','--rm','--name',name,'--network','sechub-zap','--dns','127.0.0.1','--add-host',`${r.hostname}:${address}`,'--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','1','--memory','2g','--pids-limit','256','--read-only','--tmpfs','/tmp:rw,nosuid,size=256m','--tmpfs','/home/zap/.ZAP:rw,uid=1000,gid=1000,size=256m','--mount',`type=bind,src=${dir},dst=/zap/wrk`,'-e','JAVA_OPTS=-Xmx1200m',policy.image,'zap.sh','-cmd','-silent','-autorun','/zap/wrk/plan.yaml'],timeout,job.id);
    const report=readJSON(join(dir,'report.json'),16*1024*1024);
    return normalizeZapReport(report,r.hostname,r.mode);
  }finally{
    await docker('rm','-f',name).catch(()=>{});
    await seal();currentContainer=null;
    rmSync(dir,{recursive:true,force:true});
  }
}
async function main(){
  await docker('image','inspect',policy.image);
  await docker('network','inspect','sechub-zap');
  // Recover containers and claimed jobs left by a power loss or service restart.
  const {stdout}=await docker('ps','-aq','--filter','name=^sechub-zap-');
  for(const id of stdout.trim().split(/\s+/).filter(Boolean))await docker('rm','-f',id);
  await seal();
  for(const f of readdirSync(spool).filter(f=>f.endsWith('.running.json'))) {
    const id=f.replace('.running.json','');if(!idPattern.test(id))continue;
    publish(id+'.result.json',{status:'interrupted',result:{error:'Worker reiniciado durante a execução.'}});unlinkSync(join(spool,f));
  }
  ready=true;publish('status.json',{ready,at:new Date().toISOString(),version:1});
  while(!stopping){
    const files=readdirSync(spool).filter(f=>idPattern.test(f.replace('.job.json',''))&&f.endsWith('.job.json')).sort();
    for(const f of files){
      if(stopping)break;
      const id=f.replace('.job.json',''),claimed=join(spool,id+'.running.json');
      renameSync(join(spool,f),claimed);
      try{
        const job=readJSON(claimed);if(job.id!==id)throw new Error('ZAP: identificador inconsistente.');
        const result=await execute(job);
        publish(id+'.result.json',{status:'completed',result});
        console.log('ZAP_COMPLETED',id);
      }catch(e){
        publish(id+'.result.json',{status:e.message==='ZAP: cancelado pelo operador.'?'cancelled':'failed',result:{error:String(e.message).startsWith('ZAP:')?e.message:'ZAP: falha interna do worker.'}});
        console.warn('ZAP_FAILED',id);
      }finally{unlinkSync(claimed);if(existsSync(join(spool,id+'.cancel')))unlinkSync(join(spool,id+'.cancel'));}
    }
    await new Promise(resolve=>setTimeout(resolve,2000));
  }
}
async function stop(){stopping=true;ready=false;publish('status.json',{ready,at:new Date().toISOString()});if(currentContainer)await docker('rm','-f',currentContainer).catch(()=>{});}
process.on('SIGTERM',()=>void stop());process.on('SIGINT',()=>void stop());
main().catch(e=>{console.error('ZAP_WORKER_START_FAILED',e.message);process.exitCode=1;}).finally(()=>{clearInterval(heartbeat);});
