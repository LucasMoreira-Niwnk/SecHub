// Root invokes a database writer as the application user; tokens never go to logs.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync,writeFileSync,existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { registerCollector } from '../lib/collections.mjs';

if(process.argv.includes('--database-writer')){
  const db=new DatabaseSync('/var/lib/sechub/sechub.sqlite');
  const audit=(actor,action,detail)=>db.prepare('INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)').run(new Date().toISOString(),actor,action,detail);
  const created=registerCollector(db,audit,{name:'Coletor corporativo',zone:'corporate',actor:'server-installation'});
  process.stdout.write(JSON.stringify(created));db.close();
}else{
  if(process.getuid?.()!==0)throw new Error('Execute com sudo.');
  const path='/etc/sechub-collector.env';
  if(existsSync(path)){console.log('Ambiente do coletor existente preservado.');}
  else{
    const setting=readFileSync('/etc/sechub.env','utf8').split(/\r?\n/).find(s=>s.startsWith('APP_URL='));
    const origin=new URL(setting?.slice(8).replace(/^["']|["']$/g,'')||'https://sechub.casaeterra.com');
    if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw new Error('APP_URL HTTPS inválida.');
    const raw=execFileSync('/usr/sbin/runuser',['-u','sechub','--','/opt/node24/bin/node',fileURLToPath(import.meta.url),'--database-writer'],{encoding:'utf8',maxBuffer:65536});
    const created=JSON.parse(raw);
    writeFileSync(path,`COLLECTOR_APP_URL=${origin.origin}\nCOLLECTOR_TOKEN=${created.token}\nCOLLECTOR_ID=${created.id}\nCOLLECTOR_POLICY_PATH=/etc/sechub-collector/policy.json\n`,{mode:0o600,flag:'wx'});
    console.log('Coletor registrado:',created.id);
  }
}
