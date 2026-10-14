import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

export function openStore(dir) {
  mkdirSync(dir,{recursive:true});
  const db = new DatabaseSync(resolve(dir,'sechub.sqlite'));
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS domains(id TEXT PRIMARY KEY, hostname TEXT UNIQUE NOT NULL, interval_hours INTEGER NOT NULL DEFAULT 24, enabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, next_run TEXT);
    CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, domain_id TEXT NOT NULL REFERENCES domains(id), status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, result TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, email TEXT NOT NULL, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS oauth_states(id TEXT PRIMARY KEY, nonce TEXT NOT NULL, verifier TEXT NOT NULL, expires INTEGER NOT NULL);
  `);
  db.prepare("UPDATE scans SET status='interrupted', finished_at=? WHERE status='running'").run(new Date().toISOString());
  const audit = (actor,action,detail) => db.prepare('INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)').run(new Date().toISOString(),actor,action,detail);
  return {db,audit};
}
