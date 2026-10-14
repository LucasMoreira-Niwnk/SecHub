import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

export function normalizeDomain(value) {
  if (typeof value !== 'string' || value.length > 253) throw new Error('Domínio inválido.');
  const raw = value.trim().toLowerCase().replace(/\.$/, '');
  if (/[\s\/:@?#\\%]/.test(raw)) throw new Error('Informe apenas um nome DNS, sem protocolo, porta ou caminho.');
  const host = domainToASCII(raw);
  if (isIP(host) || !host.includes('.') || !host.split('.').every(p => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p))) {
    throw new Error('Informe apenas um nome DNS, sem protocolo, porta ou caminho.');
  }
  return host;
}

export function isPublicIP(ip) {
  if (isIP(ip) === 4) {
    const [a,b,c] = ip.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) ||
      (a === 192 && b === 0 && c === 2) || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113));
  }
  // Only global IPv6 unicast; special-use and transition ranges are rejected.
  if (isIP(ip) === 6) {
    const first = parseInt(ip.split(':')[0],16);
    return first >= 0x2000 && first <= 0x3fff && !/^2001:(?:0*:|0?db8:|0?2:|0?1[0-9a-f]:)/i.test(ip) && !/^2002:/i.test(ip);
  }
  return false;
}

export function validateGoogleClaims(claims, { clientId, domain, nonce, now = Date.now()/1000 }) {
  if (!['https://accounts.google.com','accounts.google.com'].includes(claims.iss) ||
      claims.aud !== clientId || claims.hd !== domain || claims.email_verified !== true ||
      claims.nonce !== nonce || !claims.sub || !Number.isFinite(claims.exp) || claims.exp <= now ||
      !Number.isFinite(claims.iat) || claims.iat > now + 60 || typeof claims.email !== 'string' ||
      !claims.email.toLowerCase().endsWith('@' + domain)) throw new Error('Identidade Google não autorizada.');
  return claims;
}

export function parseInterval(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 168) throw new Error('Intervalo deve ser de 1 a 168 horas.');
  return n;
}
