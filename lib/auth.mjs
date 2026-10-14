import { randomBytes, createHash, createPublicKey, verify } from 'node:crypto';
import { validateGoogleClaims } from './security.mjs';

export const token = () => randomBytes(32).toString('base64url');
export const hash = value => createHash('sha256').update(value).digest('hex');
let jwksCache;
export async function verifyGoogleJWT(jwt, options) {
  const parts = jwt?.split('.');
  if(parts?.length!==3) throw new Error('Token Google inválido.');
  const header = JSON.parse(Buffer.from(parts[0],'base64url'));
  if(header.alg!=='RS256' || typeof header.kid!=='string') throw new Error('Algoritmo Google inválido.');
  if(!jwksCache || jwksCache.expires<Date.now() || !jwksCache.keys.some(k=>k.kid===header.kid)) {
    const res = await fetch('https://www.googleapis.com/oauth2/v3/certs',{signal:AbortSignal.timeout(10000)});
    if(!res.ok) throw new Error('Não foi possível validar a identidade Google.');
    jwksCache = {keys:(await res.json()).keys,expires:Date.now()+3600000};
  }
  const jwk = jwksCache.keys.find(k=>k.kid===header.kid);
  if(!jwk || !verify('RSA-SHA256',Buffer.from(parts[0]+'.'+parts[1]),createPublicKey({key:jwk,format:'jwk'}),Buffer.from(parts[2],'base64url'))) throw new Error('Assinatura Google inválida.');
  return validateGoogleClaims(JSON.parse(Buffer.from(parts[1],'base64url')),options);
}
