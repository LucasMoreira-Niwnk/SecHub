import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync,mkdtempSync,rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID,generateKeyPairSync } from 'node:crypto';
import { SignedXml } from 'xml-crypto';
import { openStore } from '../lib/store.mjs';
import { createSaml,samlDiagnostic } from '../lib/saml.mjs';

const certPath=new URL('./fixtures/idp-test.cert.txt',import.meta.url);
const cert=readFileSync(certPath,'utf8');
const key=readFileSync(new URL('./fixtures/idp-test.key.txt',import.meta.url),'utf8');
const origin='https://sechub.casaeterra.com';
const acs=origin+'/auth/saml/acs';
const entityId=origin+'/auth/saml/metadata';
const idpIssuer='https://accounts.google.com/o/saml2?idpid=TEST_ONLY';
const email='admin@casaeterra.com';
function signXml(xml,element,privateKey=key) {
  const sig=new SignedXml({privateKey,publicCert:cert,signatureAlgorithm:'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',canonicalizationAlgorithm:'http://www.w3.org/2001/10/xml-exc-c14n#'});
  const xpath=`/*[local-name(.)='Response']${element==='Assertion'?"/*[local-name(.)='Assertion']":''}`;
  sig.addReference({xpath,transforms:['http://www.w3.org/2000/09/xmldsig#enveloped-signature','http://www.w3.org/2001/10/xml-exc-c14n#'],digestAlgorithm:'http://www.w3.org/2001/04/xmlenc#sha256'});
  sig.computeSignature(xml,{location:{reference:xpath+"/*[local-name(.)='Issuer']",action:'after'}});
  return sig.getSignedXml();
}
function response(requestId,options={}) {
  const instant=new Date().toISOString();
  const before=new Date(Date.now()-60000).toISOString();
  const after=options.expired?new Date(Date.now()-180000).toISOString():new Date(Date.now()+300000).toISOString();
  const xml=`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_${randomUUID()}" Version="2.0" IssueInstant="${instant}" Destination="${acs}" InResponseTo="${requestId}"><saml:Issuer>${idpIssuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_${randomUUID()}" Version="2.0" IssueInstant="${instant}"><saml:Issuer>${options.issuer||idpIssuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${options.email||email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${requestId}" Recipient="${options.recipient||acs}" NotOnOrAfter="${after}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${before}" NotOnOrAfter="${after}"><saml:AudienceRestriction><saml:Audience>${options.audience||entityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${instant}" SessionIndex="test-session"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`;
  if(options.unsigned) return xml;
  const signedAssertion=options.responseOnly?xml:signXml(xml,'Assertion',options.key);
  return options.assertionOnly?signedAssertion:signXml(signedAssertion,'Response',options.key);
}

test('SAML assinado: autentica, rejeita replay, adulteração, IdP/audiência/destinatário e email indevidos',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'sechub-saml-'));
  const {db}=openStore(dir);
  try {
    const saml=createSaml({db,appURL:new URL(origin),domain:'casaeterra.com',allowed:[email],env:{SAML_ENTRY_POINT:'https://accounts.google.com/o/saml2/idp?idpid=TEST_ONLY',SAML_IDP_ISSUER:idpIssuer,SAML_IDP_CERT_PATH:certPath}});
    const begin=async()=>{const flow=await saml.begin();return {...flow,requestId:db.prepare('SELECT request_id FROM saml_flows ORDER BY rowid DESC LIMIT 1').get().request_id};};
    const valid=await begin();
    const fields={RelayState:valid.relay,SAMLResponse:Buffer.from(response(valid.requestId)).toString('base64')};
    await assert.rejects(saml.complete(fields,'other-browser'),{samlCode:'SAML_BROWSER_STATE'});
    assert.equal(await saml.complete(fields,valid.relay),email);
    await assert.rejects(saml.complete(fields,valid.relay),{samlCode:'SAML_FLOW_EXPIRED'});
    const responseOnly=await begin();
    assert.equal(await saml.complete({RelayState:responseOnly.relay,SAMLResponse:Buffer.from(response(responseOnly.requestId,{responseOnly:true})).toString('base64')},responseOnly.relay),email);
    for(const [options,expectedCode] of [[{issuer:'evil-idp'},'SAML_ISSUER'],[{audience:'wrong-app'},'SAML_AUDIENCE'],[{recipient:'https://evil.example/acs'},'SAML_RECIPIENT'],[{email:'admin@evil.example'},'SAML_EMAIL_DOMAIN'],[{email:'unlisted@casaeterra.com'},'SAML_EMAIL_NOT_ALLOWED'],[{expired:true},'SAML_SUBJECT'],[{assertionOnly:true},'SAML_RESPONSE_SIGNATURE'],[{unsigned:true},'SAML_RESPONSE_SIGNATURE'],[{tampered:true},'SAML_RESPONSE_SIGNATURE'],[{responseOnly:true,tampered:true},'SAML_RESPONSE_SIGNATURE'],[{key:generateKeyPairSync('rsa',{modulusLength:2048}).privateKey},'SAML_RESPONSE_SIGNATURE']]) {
      const flow=await begin();let xml=response(flow.requestId,options);
      if(options.tampered)xml=xml.replace('admin@casaeterra.com','evil@casaeterra.com');
      await assert.rejects(saml.complete({RelayState:flow.relay,SAMLResponse:Buffer.from(xml).toString('base64')},flow.relay),error=>samlDiagnostic(error).code===expectedCode,expectedCode);
    }
    assert.equal(db.prepare('SELECT count(*) AS n FROM saml_requests').get().n,0);
    assert.equal(db.prepare('SELECT count(*) AS n FROM saml_flows').get().n,0);
  } finally {db.close();rmSync(dir,{recursive:true,force:true});}
});

test('diagnóstico SAML não expõe conteúdo bruto, assertion ou identidade',()=>{
  const secret='PRIVATE_ASSERTION_CONTENT';
  assert.equal(samlDiagnostic(new Error('Invalid document signature '+secret)).code,'SAML_RESPONSE_SIGNATURE');
  assert.equal(samlDiagnostic(new Error('Invalid signature')).code,'SAML_ASSERTION_SIGNATURE');
  assert.equal(samlDiagnostic(new Error('InResponseTo is not valid '+secret)).code,'SAML_CORRELATION');
  for(const error of [new Error(secret),new Error('Audience mismatch '+secret),{samlCode:'UNTRUSTED_'+secret,message:secret}]) {
    assert.ok(!JSON.stringify(samlDiagnostic(error)).includes(secret));
  }
});

test('SAML pendente: publica metadados sem IdP e não permite login',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'sechub-saml-pending-'));
  const {db}=openStore(dir);
  try {
    const saml=createSaml({db,appURL:new URL(origin),domain:'casaeterra.com',allowed:[],env:{}});
    assert.equal(saml.configured,false);
    assert.match(saml.metadata(),/https:\/\/sechub.casaeterra.com\/auth\/saml\/acs/);
    await assert.rejects(saml.begin());
    await assert.rejects(saml.complete({RelayState:'x',SAMLResponse:'fake'},'x'));
  } finally {db.close();rmSync(dir,{recursive:true,force:true});}
});
