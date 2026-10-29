import { BlockList,isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { networkInterfaces } from 'node:os';
import { Resolver } from 'node:dns/promises';

export function internalHostname(value){
  if(typeof value!=='string'||value.length>253||/[\s\/:@?#\\%]/.test(value))throw new Error('Coleta: hostname interno inválido.');
  const host=domainToASCII(value.toLowerCase().replace(/\.$/,''));
  if(isIP(host)||!host||!host.split('.').every(p=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p)))throw new Error('Coleta: hostname interno inválido.');
  return host;
}
const privateRanges=new BlockList();
for(const [ip,prefix,family] of [['10.0.0.0',8,'ipv4'],['172.16.0.0',12,'ipv4'],['192.168.0.0',16,'ipv4'],['fc00::',7,'ipv6']])privateRanges.addSubnet(ip,prefix,family);
export const privateAddress=ip=>!!isIP(ip)&&privateRanges.check(ip,isIP(ip)===4?'ipv4':'ipv6');
export function privateCIDR(value){
  if(typeof value!=='string'||!/^[-a-fA-F0-9:.]+\/\d+$/.test(value))throw new Error('Coleta: CIDR inválido.');
  const [ip,raw]=value.split('/'),family=isIP(ip),prefix=Number(raw);
  const min=family===6?7:ip.startsWith('10.')?8:ip.startsWith('172.')?12:16;
  if(!family||!privateAddress(ip)||prefix<min||prefix>(family===6?128:32))throw new Error('Coleta: use somente CIDRs privados explícitos.');
  const test=new BlockList();test.addSubnet(ip,prefix,family===4?'ipv4':'ipv6');return value;
}
export function inCIDRs(ip,cidrs){
  if(!isIP(ip))return false;
  return cidrs.some(cidr=>{const [base,prefix]=cidr.split('/');if(isIP(base)!==isIP(ip))return false;const list=new BlockList();list.addSubnet(base,Number(prefix),isIP(ip)===4?'ipv4':'ipv6');return list.check(ip,isIP(ip)===4?'ipv4':'ipv6');});
}
export function internalPolicy(raw={}){
  for(const key of ['suffixes','cidrs','dnsServers','blockedCidrs'])if(raw[key]!==undefined&&!Array.isArray(raw[key]))throw new Error('Coleta: política interna inválida.');
  const suffixes=(raw.suffixes||[]).map(internalHostname),cidrs=(raw.cidrs||[]).map(privateCIDR),dnsServers=raw.dnsServers||[];
  if(suffixes.length>20||cidrs.length>50||dnsServers.length>4||dnsServers.some(ip=>!privateAddress(ip)))throw new Error('Coleta: política DNS inválida.');
  const blockedCidrs=raw.blockedCidrs||[];
  for(const value of blockedCidrs){const [ip,p]=String(value).split('/');if(!isIP(ip)||!/^\d+$/.test(p)||Number(p)>(isIP(ip)===4?32:128))throw new Error('Coleta: bloqueio CIDR inválido.');}
  return {suffixes,cidrs,dnsServers,blockedCidrs};
}
export function approvedInternalHost(host,policy){return policy.suffixes.some(s=>host===s||host.endsWith('.'+s));}
export function validateInternalAddresses(addresses,policy,localIPs=Object.values(networkInterfaces()).flat().map(a=>a.address)){
  if(!addresses.length)throw new Error('Coleta: DNS sem endereço resolvido.');
  if(addresses.some(ip=>!privateAddress(ip)||!inCIDRs(ip,policy.cidrs)||inCIDRs(ip,['fd00:ec2::/32',...policy.blockedCidrs])||[...localIPs,...(policy.dnsServers||[])].includes(ip)))throw new Error('Coleta: endereço fora do escopo, metadata, servidor DNS ou próprio coletor bloqueado.');
  return addresses;
}
export function createInternalResolver(host,raw,resolver){
  const policy=internalPolicy(raw);host=internalHostname(host);
  if(!approvedInternalHost(host,policy)||!policy.cidrs.length||!policy.dnsServers.length)throw new Error('Coleta: configure sufixos, CIDRs e DNS autorizados no coletor.');
  resolver??=new Resolver({timeout:2500,tries:2});resolver.setServers(policy.dnsServers);
  const resolveHost=async name=>{
    if(internalHostname(name)!==host)throw new Error('Coleta: hostname fora do escopo.');
    const answers=await Promise.all(['resolve4','resolve6'].map(async method=>{try{return await resolver[method](host);}catch(e){if(['ENODATA','ENOTFOUND'].includes(e.code))return [];throw new Error('Coleta: DNS indisponível ou inconclusivo.');}}));
    return validateInternalAddresses([...new Set(answers.flat())],policy);
  };
  return {resolver,resolveHost};
}
