// Real ZAP against an ephemeral fixture on an internal-only Docker network.
import { mkdtempSync,writeFileSync,chmodSync,chownSync,readFileSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { zapPlan,normalizeZapReport } from '../lib/zap.mjs';
const image=process.argv[2];
if(!/^ghcr\.io\/zaproxy\/zaproxy@sha256:[a-f0-9]{64}$/.test(image))throw new Error('Digest inválido.');
const suffix=process.pid,network='sechub-fixture-'+suffix,fixture='sechub-fixture-server-'+suffix;
const dir=mkdtempSync(join(tmpdir(),'sechub-fixture-'));chownSync(dir,1000,1000);chmodSync(dir,0o755);
const docker=(...args)=>execFileSync('/usr/bin/docker',args,{encoding:'utf8',timeout:240000,maxBuffer:4*1024*1024});
try{
  execFileSync('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(dir,'key.pem'),'-out',join(dir,'cert.pem'),'-days','1','-subj','/CN=fixture.example.com'],{stdio:'ignore'});
  chownSync(join(dir,'key.pem'),1000,1000);
  writeFileSync(join(dir,'fixture.py'),`import http.server,ssl,json,urllib.parse
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  u=urllib.parse.urlsplit(self.path)
  q=urllib.parse.parse_qs(u.query).get('q',[''])[0]
  print(json.dumps({'method':'GET','path':u.path,'injected':"'" in q}),flush=True)
  content='You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near' if "'" in q else '<html><body><h1>Fixture</h1><a href="/search?q=fixture">Search</a><a href="/logout">Logout</a><form method="post" action="/submit"><input name="secret"></form></body></html>'
  self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.end_headers();self.wfile.write(content.encode())
 def do_POST(self):
  print(json.dumps({'method':'POST','path':self.path}),flush=True);self.send_response(405);self.end_headers()
 def log_message(self,*args):pass
server=http.server.HTTPServer(('0.0.0.0',443),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain('/fixture/cert.pem','/fixture/key.pem');server.socket=ctx.wrap_socket(server.socket,server_side=True);server.serve_forever()
`,{mode:0o644});
  docker('network','create','--internal',network);
  docker('run','-d','--name',fixture,'--network',network,'--network-alias','fixture.example.com','--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--mount',`type=bind,src=${dir},dst=/fixture,readonly`,'--entrypoint','python3',image,'/fixture/fixture.py');
  for(const mode of ['baseline','sqli']){
    const plan=zapPlan({hostname:'fixture.example.com',mode,authorized:true,targets:['/search?q=fixture'],windowStart:new Date().toISOString(),windowEnd:new Date(Date.now()+3600000).toISOString()});
    writeFileSync(join(dir,'plan.yaml'),plan,{mode:0o644});chmodSync(join(dir,'plan.yaml'),0o644);
    const output=docker('run','--rm','--hostname','sechub-zap','--add-host','sechub-zap:127.0.0.1','--network',network,'--user','1000:1000','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','1','--memory','2g','--pids-limit','256','--read-only','--tmpfs','/tmp:rw,nosuid,size=256m','--tmpfs','/home/zap/.ZAP:rw,uid=1000,gid=1000,size=256m','--tmpfs','/home/zap/.java:rw,uid=1000,gid=1000,size=8m','--mount',`type=bind,src=${dir},dst=/zap/wrk`,image,'zap.sh','-Xmx1200m','-cmd','-silent','-autorun','/zap/wrk/plan.yaml');
    const normalized=normalizeZapReport(JSON.parse(readFileSync(join(dir,'report.json'),'utf8')),'fixture.example.com',mode);
    if(mode==='sqli'&&!normalized.findings.some(f=>f.id==='zap-40018')){
      console.log(JSON.stringify({diagnosticFindings:normalized.findings.map(f=>f.id),requests:docker('logs',fixture).trim().split('\n').filter(Boolean).map(s=>JSON.parse(s))}));
      console.log(output);
      throw new Error('SQLi fixture was not detected');
    }
    console.log(JSON.stringify({mode,status:'ok',findings:normalized.findings.length,jvmMemoryLimited:output.includes('-Xmx1200m')}));
  }
  const requests=docker('logs',fixture).trim().split('\n').filter(Boolean).map(s=>JSON.parse(s));
  assert.ok(requests.length>0);
  assert.ok(requests.every(r=>r.method==='GET'&&['/','/search'].includes(r.path)),'Out-of-scope request to fixture');
  assert.ok(requests.some(r=>r.injected),'Active scanner did not send the expected fixture probe');
  console.log(JSON.stringify({fixtureRequests:requests.length,scope:'ok',externalNetwork:false}));
}finally{
  try{docker('rm','-f',fixture);}catch{}
  try{docker('network','rm',network);}catch{}
  rmSync(dir,{recursive:true,force:true});
}
