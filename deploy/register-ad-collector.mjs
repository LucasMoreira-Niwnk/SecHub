import {DatabaseSync} from 'node:sqlite';
import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {isIP} from 'node:net';
import {registerAdSource} from '../lib/ad.mjs';

const controller=process.argv.at(-1);
if(!isIP(controller)||!controller.startsWith('10.'))throw new Error('Informe o IP privado do controlador autorizado.');
if(process.argv.includes('--database-writer')){
  const db=new DatabaseSync('/var/lib/sechub/sechub.sqlite');
  const source=registerAdSource(db,{name:'Active Directory',controller});
  db.prepare('INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)').run(new Date().toISOString(),'server-installation','ad.source.created',source.id);
  process.stdout.write(JSON.stringify(source));db.close();
}else{
  if(process.getuid?.()!==0)throw new Error('Execute com sudo.');
  if(existsSync('/etc/sechub-ad.env')){console.log('Registro AD existente preservado.');process.exit(0);}
  const setting=readFileSync('/etc/sechub.env','utf8').split(/\r?\n/).find(s=>s.startsWith('APP_URL='));
  const origin=new URL(setting?.slice(8).replace(/^["']|["']$/g,''));
  if(origin.protocol!=='https:'||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw new Error('APP_URL inválida.');
  const source=JSON.parse(execFileSync('/usr/sbin/runuser',['-u','sechub','--','/opt/node24/bin/node',fileURLToPath(import.meta.url),'--database-writer',controller],{encoding:'utf8',maxBuffer:65536}));
  writeFileSync('/etc/sechub-ad.env',`AD_APP_URL=${origin.origin}\nAD_TOKEN=${source.token}\nAD_CONTROLLER=${controller}\n`,{mode:0o600,flag:'wx'});
  console.log('Coletor AD registrado:',source.id);
}
