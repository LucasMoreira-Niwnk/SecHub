import { lookup } from 'node:dns/promises';
import { isPublicIP,normalizeDomain } from './security.mjs';

export async function resolveZapTarget(hostname,policy,resolver=lookup){
  hostname=normalizeDomain(hostname);
  if(!Array.isArray(policy.allowedRoots)||!policy.allowedRoots.some(root=>hostname===normalizeDomain(root)||hostname.endsWith('.'+normalizeDomain(root))))throw new Error('ZAP: host fora da política autorizada.');
  const records=await resolver(hostname,{all:true});
  if(!records.length||records.some(x=>!isPublicIP(x.address)))throw new Error('ZAP: DNS privado, reservado ou misto bloqueado.');
  const address=records.find(x=>x.family===4)?.address;
  if(!address)throw new Error('ZAP: worker exige endereço público IPv4.');
  return address;
}
