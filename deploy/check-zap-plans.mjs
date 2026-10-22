// Offline compatibility check against the exact pinned image. No target is contacted.
import { mkdtempSync,writeFileSync,chmodSync,rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { zapPlan } from '../lib/zap.mjs';

const image=process.argv[2];
if(!/^ghcr\.io\/zaproxy\/zaproxy@sha256:[a-f0-9]{64}$/.test(image))throw new Error('Digest inválido.');
const dir=mkdtempSync(join(tmpdir(),'sechub-zap-check-'));chmodSync(dir,0o755);
try{
  for(const mode of ['baseline','sqli']){
    const plan=zapPlan({hostname:'fixture.example.com',mode,authorized:true,targets:['/search?q=fixture'],windowStart:new Date().toISOString(),windowEnd:new Date(Date.now()+3600000).toISOString()});
    const file=mode+'.yaml';writeFileSync(join(dir,file),plan,{mode:0o644});
    execFileSync('/usr/bin/docker',['run','--rm','--network','none','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','1','--memory','2g','--pids-limit','256','--read-only','--tmpfs','/tmp:rw,nosuid,size=256m','--tmpfs','/home/zap/.ZAP:rw,uid=1000,gid=1000,size=256m','--mount',`type=bind,src=${dir},dst=/zap/wrk`,'-e','JAVA_OPTS=-Xmx1200m',image,'zap.sh','-cmd','-silent','-autocheck','/zap/wrk/'+file],{stdio:'inherit',timeout:180000});
  }
}finally{rmSync(dir,{recursive:true,force:true});}
