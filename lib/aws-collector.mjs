import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';

export const AWS_SOURCES=['securityhub','guardduty','inspector2','route53','resolver'];
const rolePattern=/^arn:aws:iam::(\d{12}):role\/[A-Za-z0-9+=,.@_\/-]{1,512}$/;
export function awsConnection(raw){
  const {accountId,roleArn,sourceProfile}=raw;
  if(typeof accountId!=='string'||!/^\d{12}$/.test(accountId)||typeof roleArn!=='string'||roleArn.match(rolePattern)?.[1]!==accountId||typeof sourceProfile!=='string'||!/^\w[\w.-]{0,63}$/.test(sourceProfile))throw new Error('Coleta: informe Account ID de 12 dígitos, Role ARN da conta e perfil de origem.');
  const regions=[...new Set(raw.regions||[])],sources=[...new Set(raw.sources||AWS_SOURCES)];
  if(!regions.length||regions.length>10||regions.some(r=>! /^(?:us|sa|eu|ap|ca|me|af|il|mx)\-[a-z]+\-\d+$/.test(r))||!sources.length||sources.some(s=>!AWS_SOURCES.includes(s)))throw new Error('Coleta: regiões ou fontes AWS inválidas.');
  if(raw.externalId&& !/^[\w+=,.@:\/-]{2,128}$/.test(raw.externalId))throw new Error('Coleta: External ID inválido.');
  return {accountId,roleArn,sourceProfile,regions,sources,externalId:raw.externalId||''};
}
export function validateAwsPolicy(connection,policy={}){
  const c=awsConnection(connection);
  if(!policy.roleArns?.includes(c.roleArn)||!policy.sourceProfiles?.includes(c.sourceProfile)||c.regions.some(r=>!policy.regions?.includes(r)))throw new Error('Coleta: conta, Role, perfil ou região fora da política do coletor.');
  return c;
}
export function awsError(error){
  if(error.code==='ENOENT')return 'AWS_CLI_NOT_INSTALLED';
  const text=String(error.stderr||error.code||'');
  if(/SSO.*(?:expired|invalid)|Error loading SSO/i.test(text))return 'AWS_SSO_LOGIN_REQUIRED';
  if(/profile.*could not be found/i.test(text))return 'AWS_PROFILE_NOT_CONFIGURED';
  return text.match(/\b(?:AccessDeniedException|AccessDenied|InvalidAccessException|ExpiredTokenException|ExpiredToken|ResourceNotFoundException|UnrecognizedClientException|InvalidClientTokenId|UnauthorizedOperation|ThrottlingException|SubscriptionRequiredException)\b/)?.[0]||'AWS_COLLECTION_FAILED';
}
const text=(v,max=1200)=>String(v??'').replace(/[\x00-\x1f]/g,' ').slice(0,max);
const severity=value=>['critical','high','medium','low','info'].includes(String(value).toLowerCase())?String(value).toLowerCase():'info';
const id=(source,value)=>source+'-'+createHash('sha256').update(String(value)).digest('hex').slice(0,24);
export function awsFinding(source,f,accountId,region){
  if(source==='securityhub')return {id:id(source,f.ProductArn+'/'+f.Id),source,severity:severity(f.Severity?.Label),title:text(f.Title,200),evidence:text(f.Description),remediation:text(f.Remediation?.Recommendation?.Text),reference:text(f.Compliance?.SecurityControlId||f.GeneratorId,200),resource:text(f.Resources?.[0]?.Id,500),accountId,region};
  if(source==='guardduty')return {id:id(source,f.arn||f.id),source,severity:Number(f.severity)>=9?'critical':Number(f.severity)>=7?'high':Number(f.severity)>=4?'medium':'low',title:text(f.title||f.type,200),evidence:text(f.description),remediation:'Investigue o recurso e o contexto do alerta no GuardDuty.',reference:text(f.type,200),resource:text(f.resource?.instanceDetails?.instanceId||f.resource?.resourceType,500),accountId,region};
  return {id:id(source,f.findingArn),source,severity:severity(f.severity),title:text(f.title,200),evidence:text(f.description),remediation:text(f.remediation?.recommendation?.text)||'Revise as versões afetadas e a correção indicada pelo Amazon Inspector.',reference:text(f.packageVulnerabilityDetails?.vulnerabilityId||f.type,200),resource:text(f.resources?.[0]?.id,500),accountId,region};
}

export function createAwsCli({cliPath='/opt/aws-cli/v2/current/bin/aws',env=process.env,execute=promisify(execFile)}={}){
  if(!cliPath.startsWith('/'))throw new Error('Coleta: caminho absoluto do AWS CLI obrigatório.');
  const baseEnv=Object.fromEntries(Object.entries(env).filter(([k])=>!/^AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|PROFILE|ENDPOINT_URL.*)$/.test(k)));
  Object.assign(baseEnv,{AWS_PAGER:'',AWS_CLI_AUTO_PROMPT:'off',AWS_RETRY_MODE:'standard',AWS_MAX_ATTEMPTS:'3',AWS_IGNORE_CONFIGURED_ENDPOINT_URLS:'true'});
  return async ({service,operation,args=[],region,profile,credentials,paginate=false,signal})=>{
    const command=[service,operation,...args,'--region',region,'--output','json','--no-cli-pager','--cli-connect-timeout','5','--cli-read-timeout','20'];
    if(profile)command.push('--profile',profile);
    if(paginate)command.push('--max-items','200','--page-size','50');
    const childEnv={...baseEnv};
    if(credentials)Object.assign(childEnv,{AWS_ACCESS_KEY_ID:credentials.AccessKeyId,AWS_SECRET_ACCESS_KEY:credentials.SecretAccessKey,AWS_SESSION_TOKEN:credentials.SessionToken});
    try{
      const {stdout}=await execute(cliPath,command,{env:childEnv,signal,timeout:60000,maxBuffer:4*1024*1024,windowsHide:true});
      return JSON.parse(stdout);
    }catch(error){if(signal?.aborted)throw signal.reason;throw new Error(awsError(error));}
  };
}

export async function collectAws(raw,policy,{run=createAwsCli({cliPath:policy.cliPath}),signal}={}){
  const c=validateAwsPolicy(raw,policy),started=new Date().toISOString(),findings=[],assets=[],sources=[];
  const assumed=await run({service:'sts',operation:'assume-role',region:c.regions[0],profile:c.sourceProfile,signal,args:['--role-arn',c.roleArn,'--role-session-name','SecHubReadOnly','--duration-seconds','900',...(c.externalId?['--external-id='+c.externalId]:[])]});
  const credentials=assumed.Credentials;
  if(!credentials?.AccessKeyId||!credentials.SecretAccessKey||!credentials.SessionToken||!Number.isFinite(Date.parse(credentials.Expiration))||Date.parse(credentials.Expiration)<=Date.now())throw new Error('AWS_SESSION_INVALID');
  const call=(service,operation,region,args=[],paginate=false)=>run({service,operation,region,args,paginate,credentials,signal});
  const identity=await call('sts','get-caller-identity',c.regions[0]);
  if(identity.Account!==c.accountId)throw new Error('AWS_ACCOUNT_MISMATCH');
  let limited=false;
  for(const region of c.regions)for(const source of c.sources){
    if(source==='route53'&&region!==c.regions[0])continue;
    signal?.throwIfAborted();
    const summary={source,region:source==='route53'?'global':region,status:'ok',count:0,limited:false};
    const addPage=page=>{if(page.NextToken||page.nextToken||page.IsTruncated){summary.limited=true;limited=true;}};
    const array=(page,key)=>{if(!Array.isArray(page[key]))throw new Error('AWS_RESPONSE_INVALID');return page[key];};
    try{
      const rows=[];
      if(source==='securityhub'){
        const page=await call(source,'get-findings',region,['--filters',JSON.stringify({AwsAccountId:[{Value:c.accountId,Comparison:'EQUALS'}],Region:[{Value:region,Comparison:'EQUALS'}],RecordState:[{Value:'ACTIVE',Comparison:'EQUALS'}]})],true);addPage(page);
        rows.push(...array(page,'Findings').filter(f=>f.AwsAccountId===c.accountId&&f.Region===region).map(f=>awsFinding(source,f,c.accountId,region)));
      }else if(source==='guardduty'){
        const detectors=await call(source,'list-detectors',region,[],true);addPage(detectors);
        array(detectors,'DetectorIds');if(detectors.DetectorIds.length>2){summary.limited=true;limited=true;}
        if(!detectors.DetectorIds?.length)summary.status='not_enabled';
        for(const detector of (detectors.DetectorIds||[]).slice(0,2)){
          const page=await call(source,'list-findings',region,['--detector-id',detector,'--finding-criteria',JSON.stringify({Criterion:{'service.archived':{Eq:['false']}}})],true);addPage(page);
          const ids=array(page,'FindingIds');
          for(let offset=0;offset<ids.length;offset+=50){
            const found=await call(source,'get-findings',region,['--detector-id',detector,'--finding-ids',...ids.slice(offset,offset+50)]);
            rows.push(...array(found,'Findings').filter(f=>f.accountId===c.accountId).map(f=>awsFinding(source,f,c.accountId,region)));
          }
        }
      }else if(source==='inspector2'){
        const page=await call(source,'list-findings',region,['--filter-criteria',JSON.stringify({awsAccountId:[{comparison:'EQUALS',value:c.accountId}],findingStatus:[{comparison:'EQUALS',value:'ACTIVE'}]})],true);addPage(page);
        rows.push(...array(page,'findings').filter(f=>f.awsAccountId===c.accountId).map(f=>awsFinding(source,f,c.accountId,region)));
      }else if(source==='route53'){
        const zones=await call(source,'list-hosted-zones',region,[],true);addPage(zones);
        for(const zone of array(zones,'HostedZones'))assets.push({id:text(zone.Id,200),type:'dns-zone',name:text(zone.Name,253),private:!!zone.Config?.PrivateZone,region:'global'});
        summary.count=(zones.HostedZones||[]).length;
      }else{
        const page=await call('route53resolver','list-resolver-endpoints',region,[],true);addPage(page);
        for(const endpoint of array(page,'ResolverEndpoints'))assets.push({id:text(endpoint.Id,200),type:'dns-resolver',name:text(endpoint.Name,253),direction:text(endpoint.Direction,30),status:text(endpoint.Status,60),region});
        summary.count=(page.ResolverEndpoints||[]).length;
      }
      if(rows.length){summary.count=rows.length;findings.push(...rows.slice(0,Math.max(0,1000-findings.length)));if(findings.length>=1000){limited=true;summary.limited=true;}}
    }catch(error){signal?.throwIfAborted();summary.status='error';summary.error=/^[A-Za-z0-9_]{1,80}$/.test(error.message)?error.message:'AWS_COLLECTION_FAILED';}
    sources.push(summary);
  }
  return {started,finished:new Date().toISOString(),accountId:c.accountId,findings,assets:assets.slice(0,1000),sources,limited:limited||assets.length>1000};
}
