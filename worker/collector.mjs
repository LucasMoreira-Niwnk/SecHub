import { readFileSync } from 'node:fs';
import { scanDomain } from '../lib/scanner.mjs';
import { createInternalResolver,internalPolicy } from '../lib/internal-scope.mjs';
import { collectAws,awsConnection } from '../lib/aws-collector.mjs';

const origin=new URL(process.env.COLLECTOR_APP_URL||'https://sechub.casaeterra.com');
if(origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash||origin.protocol!=='https:'&&!(process.env.COLLECTOR_DEV_MODE==='true'&&origin.protocol==='http:'&&['127.0.0.1','localhost'].includes(origin.hostname)))throw new Error('Configure uma origem HTTPS válida.');
const secret=process.env.COLLECTOR_TOKEN;
if(!/^[A-Za-z0-9_-]{32,200}$/.test(secret||''))throw new Error('Token do coletor não configurado.');
const policyPath=process.env.COLLECTOR_POLICY_PATH||'/etc/sechub-collector/policy.json';
let stopped=false,activeController;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function post(path,data){
  const response=await fetch(new URL('/api/collector/'+path,origin),{method:'POST',headers:{Authorization:'Bearer '+secret,'Content-Type':'application/json'},body:JSON.stringify(data),redirect:'error',signal:AbortSignal.timeout(15000)});
  if(!response.ok)throw new Error('CONTROLLER_HTTP_'+response.status);
  const raw=await response.text();if(raw.length>65536)throw new Error('CONTROLLER_RESPONSE_TOO_LARGE');
  return JSON.parse(raw);
}
function readPolicy(){
  const policy=JSON.parse(readFileSync(policyPath,'utf8'));
  return {internal:internalPolicy(policy.internal),aws:{roleArns:[],sourceProfiles:[],regions:[],...policy.aws}};
}
async function execute(job,policy){
  if(job.version!==1||!/^[-a-f0-9]{36}$/.test(job.id)||!['internal','aws'].includes(job.kind)||!Number.isFinite(job.deadline)||job.deadline<=Date.now()||job.deadline>Date.now()+610000)throw new Error('JOB_INVALID');
  const controller=new AbortController();activeController=controller;
  const timeout=setTimeout(()=>controller.abort(new Error('COLLECTION_TIMEOUT')),Math.min(job.deadline-Date.now(),600000));
  let cancelled=false,beating=false;
  const lease={id:job.id,lease:job.lease};
  const heartbeat=setInterval(async()=>{
    if(beating)return;beating=true;
    try{if((await post('heartbeat',lease)).cancelled){cancelled=true;controller.abort(new Error('CANCELLED'));}}
    catch{controller.abort(new Error('CONTROLLER_UNAVAILABLE'));}
    finally{beating=false;}
  },15000);
  try{
    let result;
    if(job.kind==='internal'){
      const {resolver,resolveHost}=createInternalResolver(job.input.hostname,policy.internal);
      await resolveHost(job.input.hostname);controller.signal.throwIfAborted();
      result=await scanDomain(job.input.hostname,{resolver,resolveHost,emailChecks:false,signal:controller.signal});
      result.coverage={baseline:'DNS, TLS e HTTPS',zone:'internal',authenticationAbuse:'não testado',sqlInjection:'não testado'};
    }else result=await collectAws(awsConnection(job.input),policy.aws,{signal:controller.signal});
    controller.signal.throwIfAborted();
    const partial=job.kind==='internal'?!result.web:result.limited||result.sources.some(s=>s.status!=='ok');
    const status=job.kind==='aws'&&result.sources.every(s=>s.status==='error')?'failed':partial?'partial':'completed';
    await post('result',{...lease,status,result});
    console.log('COLLECTION_COMPLETED',job.id,status);
  }catch(error){
    const message=/^Coleta:|^[A-Z][A-Z0-9_]{1,100}$/.test(error.message)?error.message:'COLLECTION_FAILED';
    await post('result',{...lease,status:cancelled?'cancelled':'failed',result:{error:message}}).catch(()=>{});
    console.warn('COLLECTION_FAILED',job.id);
  }finally{clearTimeout(timeout);clearInterval(heartbeat);activeController=null;}
}
async function main(){
  while(!stopped){
    try{
      const policy=readPolicy();const {job}=await post('claim',{version:1,capabilities:policy});
      if(job){await execute(job,policy);continue;}
    }catch(error){console.warn('COLLECTOR_UNAVAILABLE',/^CONTROLLER_HTTP_\d+$/.test(error.message)?error.message:'CONFIG_OR_CONNECTION_ERROR');}
    if(!stopped)await pause(10000);
  }
}
for(const sig of ['SIGTERM','SIGINT'])process.on(sig,()=>{stopped=true;activeController?.abort(new Error('COLLECTOR_STOPPED'));});
await main();
