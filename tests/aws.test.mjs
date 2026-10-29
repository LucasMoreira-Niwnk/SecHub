import test from 'node:test';
import assert from 'node:assert/strict';
import { awsConnection,validateAwsPolicy,collectAws,createAwsCli,awsError } from '../lib/aws-collector.mjs';
const accountId='123456789012',roleArn=`arn:aws:iam::${accountId}:role/SecHubReadOnly`;
const connection={accountId,roleArn,sourceProfile:'sechub-source',regions:['us-east-1','sa-east-1']};
const policy={roleArns:[roleArn],sourceProfiles:['sechub-source'],regions:connection.regions};
const credentials={AccessKeyId:'TEMP_TEST',SecretAccessKey:'TEST_SECRET',SessionToken:'TEST_TOKEN',Expiration:new Date(Date.now()+900000).toISOString()};
test('AWS: valida Account ID, ARN da mesma conta e allowlist de perfis/regiões',()=>{
  assert.deepEqual(awsConnection(connection).regions,connection.regions);assert.ok(validateAwsPolicy(connection,policy));
  for(const patch of [{accountId:'casaeterra'},{roleArn:'arn:aws:iam::999999999999:role/ReadOnly'},{roleArn:42},{sourceProfile:'--endpoint-url'},{regions:['moon-1'] }])assert.throws(()=>awsConnection({...connection,...patch}));
  assert.throws(()=>validateAwsPolicy({...connection,regions:['eu-west-1']},policy));
});
test('AWS CLI: não passa credenciais em argumentos, ignora endpoints externos e limita paginação',async()=>{
  const seen=[];
  const run=createAwsCli({env:{PATH:'/bin',AWS_ACCESS_KEY_ID:'OLD',AWS_SECRET_ACCESS_KEY:'OLD_SECRET',AWS_ENDPOINT_URL:'https://evil.invalid'},execute:async(file,args,options)=>{seen.push({file,args,options});return {stdout:'{}'};}});
  await run({service:'securityhub',operation:'get-findings',region:'us-east-1',paginate:true,credentials});
  assert.ok(!JSON.stringify(seen[0].args).includes('TEST_SECRET'));assert.ok(seen[0].args.includes('--max-items'));
  assert.equal(seen[0].options.env.AWS_ENDPOINT_URL,undefined);assert.equal(seen[0].options.env.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS,'true');
  assert.equal(seen[0].options.env.AWS_SECRET_ACCESS_KEY,'TEST_SECRET');
  await run({service:'sts',operation:'assume-role',region:'us-east-1',profile:'sechub-source'});assert.equal(seen[1].options.env.AWS_ACCESS_KEY_ID,undefined);
  assert.equal(awsError({stderr:'error (AccessDeniedException) TOKEN_NEVER_EXPOSED'}),'AccessDeniedException');assert.equal(awsError({code:'ENOENT'}),'AWS_CLI_NOT_INSTALLED');
});
function fakeRun(calls,{denyInspector=false,wrongAccount=false,invalidPage=false}={}){
  return async request=>{
    calls.push(request);const {service,operation,region}=request;
    if(operation==='assume-role')return {Credentials:credentials};
    if(operation==='get-caller-identity')return {Account:wrongAccount?'999999999999':accountId};
    if(service==='securityhub')return invalidPage?{}:{Findings:[{Id:'sh-'+region,ProductArn:'product',AwsAccountId:accountId,Region:region,Severity:{Label:'HIGH'},Title:'Finding',Description:'Evidence',Resources:[{Id:'resource'}]},{Id:'outside',ProductArn:'product',AwsAccountId:accountId,Region:'eu-west-1',Title:'OUTSIDE_REGION'}],NextToken:'more'};
    if(operation==='list-detectors')return {DetectorIds:['detector']};
    if(service==='guardduty'&&operation==='list-findings')return {FindingIds:['finding']};
    if(service==='guardduty')return {Findings:[{id:'gd-'+region,accountId,severity:9.5,title:'Threat',description:'Investigate',resource:{instanceDetails:{instanceId:'i-fixture'}}}]};
    if(service==='inspector2'){if(denyInspector)throw new Error('AccessDeniedException');return {findings:[{findingArn:'inspector-'+region,awsAccountId:accountId,severity:'MEDIUM',title:'Package',resources:[{id:'i-fixture'}]}]};}
    if(service==='route53')return {HostedZones:[{Id:'/hostedzone/fixture',Name:'internal.example.',Config:{PrivateZone:true}}]};
    if(service==='route53resolver')return {ResolverEndpoints:[{Id:'rslvr',Name:'Internal resolver',Direction:'INBOUND',Status:'OPERATIONAL'}]};
    throw new Error('UNEXPECTED_READ_OPERATION');
  };
}
test('AWS: coleta somente contas/regiões autorizadas, importa 5 fontes e informa limites/erros parciais',async()=>{
  const calls=[],result=await collectAws(connection,policy,{run:fakeRun(calls,{denyInspector:true})});
  assert.equal(result.findings.length,4);assert.ok(!JSON.stringify(result).includes('TEST_SECRET'));assert.ok(!JSON.stringify(result).includes('OUTSIDE_REGION'));
  assert.ok(result.limited);assert.equal(result.sources.filter(s=>s.source==='inspector2'&&s.status==='error').length,2);
  assert.equal(calls.filter(c=>c.service==='route53').length,1);assert.equal(result.assets.filter(a=>a.type==='dns-resolver').length,2);
  assert.ok(result.findings.some(f=>f.severity==='critical'));assert.ok(result.assets.some(a=>a.private));
  const filters=JSON.parse(calls.find(c=>c.service==='securityhub').args[1]);assert.equal(filters.Region[0].Value,'us-east-1');
  assert.ok(calls.every(c=>['assume-role','get-caller-identity','get-findings','list-findings','list-detectors','list-hosted-zones','list-resolver-endpoints'].includes(c.operation)));
});
test('AWS: falha de identidade interrompe antes de consultar serviços; resposta inválida não vira vazio saudável',async()=>{
  const calls=[];await assert.rejects(collectAws(connection,policy,{run:fakeRun(calls,{wrongAccount:true})}),/AWS_ACCOUNT_MISMATCH/);assert.equal(calls.length,2);
  const result=await collectAws({...connection,sources:['securityhub']},policy,{run:fakeRun([],{invalidPage:true})});assert.ok(result.sources.every(s=>s.status==='error'&&s.error==='AWS_RESPONSE_INVALID'));
});
