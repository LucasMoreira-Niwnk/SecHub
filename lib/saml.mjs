import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { SAML, generateServiceProviderMetadata } from '@node-saml/node-saml';
import { token, hash } from './auth.mjs';

const emailFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const lifetime = 600000;
const skew = 60000;

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
  if(issuer?.length!==1 || issuer[0]._!==idpIssuer || subject?.length!==1 ||
     conditions?.length!==1 || confirmation?.length!==1 ||
     confirmation[0].$?.Method!=='urn:oasis:names:tc:SAML:2.0:cm:bearer' ||
     data?.Recipient!==acs || data?.InResponseTo!==requestId || profile.inResponseTo!==requestId ||
     name?.length!==1 || name[0].$?.Format!==emailFormat ||
     !Number.isFinite(expires) || expires<=now-skew || !Number.isFinite(subjectExpires) || subjectExpires<=now-skew ||
     !Number.isFinite(issued) || issued>now+skew || issued<now-lifetime-skew ||
     !/^[^\s@]+@[^\s@]+$/.test(email) || !email.endsWith('@'+domain) || !allowed.includes(email)) {
    throw new Error('Identidade SAML não autorizada.');
  }
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
      wantAssertionsSigned:true,wantAuthnResponseSigned:true,
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
    metadata:()=>generateServiceProviderMetadata({issuer:entityId,callbackUrl:acs,identifierFormat:emailFormat,wantAssertionsSigned:true}),
    async begin() {
      if(!configured) throw new Error('SAML ainda não configurado.');
      if(db.prepare('SELECT count(*) AS n FROM saml_flows WHERE expires>?').get(Date.now()).n>=500) throw new Error('Limite temporário de solicitações de login.');
      const relay=token();let requestId;
      const url=await instance(null,id=>{requestId=id;}).getAuthorizeUrlAsync(relay,undefined,{});
      db.prepare('INSERT INTO saml_flows(id,request_id,expires) VALUES(?,?,?)').run(hash(relay),requestId,Date.now()+lifetime);
      return {url,relay};
    },
    async complete(fields,browserRelay) {
      if(!configured || typeof fields.RelayState!=='string' || fields.RelayState!==browserRelay || typeof fields.SAMLResponse!=='string') throw new Error('Fluxo SAML inválido.');
      const flow=db.prepare('DELETE FROM saml_flows WHERE id=? AND expires>? RETURNING request_id').get(hash(fields.RelayState),Date.now());
      if(!flow) throw new Error('Fluxo SAML expirado ou já utilizado.');
      try {
        const {profile,loggedOut}=await instance(flow.request_id).validatePostResponseAsync({SAMLResponse:fields.SAMLResponse});
        if(loggedOut || !profile) throw new Error('Resposta SAML sem identidade.');
        return authorizeAssertion(profile,{idpIssuer,requestId:flow.request_id,acs,domain,allowed});
      } finally {db.prepare('DELETE FROM saml_requests WHERE id=?').run(flow.request_id);}
    }
  };
}
