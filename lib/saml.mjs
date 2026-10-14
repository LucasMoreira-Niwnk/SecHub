import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { SAML, generateServiceProviderMetadata } from '@node-saml/node-saml';
import { token, hash } from './auth.mjs';

const emailFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const lifetime = 600000;
const skew = 60000;

const diagnosticHints = {
  SAML_INVALID_FORM:'A resposta SAML não contém os campos esperados.',
  SAML_BROWSER_STATE:'O navegador não enviou o cookie de login ou o RelayState não corresponde. Reinicie o login na mesma aba pelo endereço HTTPS do SecHUB.',
  SAML_FLOW_EXPIRED:'A solicitação expirou ou já foi utilizada. Inicie um novo login.',
  SAML_SIGNATURE:'Confira o certificado público do Google e marque Resposta assinada no Admin Console.',
  SAML_RESPONSE_SIGNATURE:'A assinatura da resposta completa está ausente ou não confere com o certificado configurado. Confira Resposta assinada e a impressão digital do certificado selecionado nessa aplicação Google.',
  SAML_ASSERTION_SIGNATURE:'A assinatura da assertion não pôde ser validada com o certificado configurado.',
  SAML_AUDIENCE:'O Entity ID da aplicação no Google deve corresponder ao SAML_SP_ENTITY_ID do servidor.',
  SAML_CORRELATION:'A resposta não corresponde à solicitação de login iniciada pelo SecHUB.',
  SAML_TIME:'Confira o relógio do servidor e inicie um novo login.',
  SAML_ISSUER:'SAML_IDP_ISSUER deve corresponder exatamente ao Entity ID fornecido pelo Google.',
  SAML_SUBJECT:'A confirmação de identidade está ausente, incompatível ou expirada. Confira a configuração SAML e o relógio do servidor.',
  SAML_RECIPIENT:'A URL ACS no Google deve corresponder ao APP_URL seguido de /auth/saml/acs.',
  SAML_NAMEID_FORMAT:'Selecione EMAIL no formato Name ID e Email principal como valor no Google.',
  SAML_EMAIL_DOMAIN:'O email recebido não pertence ao WORKSPACE_DOMAIN configurado.',
  SAML_EMAIL_NOT_ALLOWED:'O email principal da conta Google precisa constar em ALLOWED_EMAILS. Reinicie o serviço após alterar o arquivo.',
  SAML_NO_IDENTITY:'O Google não retornou uma identidade de autenticação válida.',
  SAML_INVALID_RESPONSE:'Não foi possível validar a resposta SAML. Confira os dados da integração.'
};
function reject(code) {const error=new Error(code);error.samlCode=code;throw error;}
export function samlDiagnostic(error) {
  let code=Object.hasOwn(diagnosticHints,error?.samlCode)?error.samlCode:null;
  // Classify known library errors without returning or logging their raw content.
  if(!code) {
    const message=String(error?.message||'');
    if(message.startsWith('Invalid document signature')) code='SAML_RESPONSE_SIGNATURE';
    else if(message==='Invalid signature' || message.startsWith('Invalid signature from encrypted assertion')) code='SAML_ASSERTION_SIGNATURE';
    else if(/signature|certificate|public key/i.test(message)) code='SAML_SIGNATURE';
    else if(/audience/i.test(message)) code='SAML_AUDIENCE';
    else if(/InResponseTo/i.test(message)) code='SAML_CORRELATION';
    else if(/subject confirmation/i.test(message)) code='SAML_SUBJECT';
    else if(/expired|not yet valid|timestamp|NotOnOrAfter|NotBefore|assertion.*age/i.test(message)) code='SAML_TIME';
    else code='SAML_INVALID_RESPONSE';
  }
  return {code,hint:diagnosticHints[code]};
}

// Called only on the assertion returned by node-saml after signature validation.
export function authorizeAssertion(profile, {idpIssuer,requestId,acs,domain,allowed,now=Date.now()}) {
  const assertion = profile?.getAssertion?.()?.Assertion;
  const issuer = assertion?.Issuer;
  const subject = assertion?.Subject;
  const conditions = assertion?.Conditions;
  const confirmation = subject?.[0]?.SubjectConfirmation;
  const data = confirmation?.[0]?.SubjectConfirmationData?.[0]?.$;
  const name = subject?.[0]?.NameID;
  const email = typeof name?.[0]?._==='string' ? name[0]._.trim().toLowerCase() : '';
  const expires = Date.parse(conditions?.[0]?.$?.NotOnOrAfter);
  const subjectExpires = Date.parse(data?.NotOnOrAfter);
  const issued = Date.parse(assertion?.$?.IssueInstant);
  if(issuer?.length!==1 || issuer[0]._!==idpIssuer) reject('SAML_ISSUER');
  if(subject?.length!==1 || conditions?.length!==1 || confirmation?.length!==1 ||
     confirmation[0].$?.Method!=='urn:oasis:names:tc:SAML:2.0:cm:bearer') reject('SAML_SUBJECT');
  if(data?.Recipient!==acs) reject('SAML_RECIPIENT');
  if(data?.InResponseTo!==requestId || profile.inResponseTo!==requestId) reject('SAML_CORRELATION');
  if(name?.length!==1 || name[0].$?.Format!==emailFormat) reject('SAML_NAMEID_FORMAT');
  if(!Number.isFinite(expires) || expires<=now-skew || !Number.isFinite(subjectExpires) || subjectExpires<=now-skew ||
     !Number.isFinite(issued) || issued>now+skew || issued<now-lifetime-skew) reject('SAML_TIME');
  if(!/^[^\s@]+@[^\s@]+$/.test(email) || !email.endsWith('@'+domain)) reject('SAML_EMAIL_DOMAIN');
  if(!allowed.includes(email)) reject('SAML_EMAIL_NOT_ALLOWED');
  return email;
}

export function createSaml({db,appURL,domain,allowed,env=process.env}) {
  const acs=appURL.origin+'/auth/saml/acs';
  const entityId=env.SAML_SP_ENTITY_ID||appURL.origin+'/auth/saml/metadata';
  const entryPoint=env.SAML_ENTRY_POINT;
  const idpIssuer=env.SAML_IDP_ISSUER;
  const certPath=env.SAML_IDP_CERT_PATH;
  const configured=!!(entryPoint && idpIssuer && certPath && allowed.length);
  let cert;
  if(configured) {
    if(appURL.protocol!=='https:') throw new Error('SAML exige APP_URL HTTPS.');
    const target=new URL(entryPoint);
    if(target.protocol!=='https:' || target.hostname!=='accounts.google.com' || target.username || target.password) throw new Error('URL SAML deve pertencer ao Google Workspace.');
    cert=readFileSync(certPath,'utf8');
    const x509=new X509Certificate(cert);
    if(Date.parse(x509.validTo)<=Date.now() || Date.parse(x509.validFrom)>Date.now()) throw new Error('Certificado SAML fora da validade.');
  }
  function instance(requestId,onSave) {
    return new SAML({callbackUrl:acs,issuer:entityId,audience:entityId,entryPoint,idpIssuer,idpCert:cert,
      identifierFormat:emailFormat,disableRequestedAuthnContext:true,
      validateInResponseTo:'always',requestIdExpirationPeriodMs:lifetime,
      // The required response signature covers the enclosed assertion. A second,
      // independent signature on that assertion is not necessary.
      wantAssertionsSigned:false,wantAuthnResponseSigned:true,
      acceptedClockSkewMs:skew,maxAssertionAgeMs:lifetime,
      signatureAlgorithm:'sha256',digestAlgorithm:'sha256',
      cacheProvider:{
        async saveAsync(id,value) {
          const createdAt=Date.now();
          db.prepare('INSERT INTO saml_requests(id,value,expires) VALUES(?,?,?)').run(id,value,createdAt+lifetime);
          onSave?.(id);return {createdAt,value};
        },
        async getAsync(id) {
          if(requestId && id!==requestId) return null;
          return db.prepare('SELECT value FROM saml_requests WHERE id=? AND expires>?').get(id,Date.now())?.value??null;
        },
        async removeAsync(id) {
          if(!id || (requestId && id!==requestId)) return null;
          db.prepare('DELETE FROM saml_requests WHERE id=?').run(id);return id;
        }
      }
    });
  }
  return {configured,acs,entityId,
    metadata:()=>generateServiceProviderMetadata({issuer:entityId,callbackUrl:acs,identifierFormat:emailFormat,wantAssertionsSigned:false}),
    async begin() {
      if(!configured) throw new Error('SAML ainda não configurado.');
      if(db.prepare('SELECT count(*) AS n FROM saml_flows WHERE expires>?').get(Date.now()).n>=500) throw new Error('Limite temporário de solicitações de login.');
      const relay=token();let requestId;
      const url=await instance(null,id=>{requestId=id;}).getAuthorizeUrlAsync(relay,undefined,{});
      db.prepare('INSERT INTO saml_flows(id,request_id,expires) VALUES(?,?,?)').run(hash(relay),requestId,Date.now()+lifetime);
      return {url,relay};
    },
    async complete(fields,browserRelay) {
      if(!configured || typeof fields.RelayState!=='string' || typeof fields.SAMLResponse!=='string') reject('SAML_INVALID_FORM');
      if(!browserRelay || fields.RelayState!==browserRelay) reject('SAML_BROWSER_STATE');
      const flow=db.prepare('DELETE FROM saml_flows WHERE id=? AND expires>? RETURNING request_id').get(hash(fields.RelayState),Date.now());
      if(!flow) reject('SAML_FLOW_EXPIRED');
      try {
        const {profile,loggedOut}=await instance(flow.request_id).validatePostResponseAsync({SAMLResponse:fields.SAMLResponse});
        if(loggedOut || !profile) reject('SAML_NO_IDENTITY');
        return authorizeAssertion(profile,{idpIssuer,requestId:flow.request_id,acs,domain,allowed});
      } finally {db.prepare('DELETE FROM saml_requests WHERE id=?').run(flow.request_id);}
    }
  };
}
