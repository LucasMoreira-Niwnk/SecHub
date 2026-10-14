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
    CREATE TABLE IF NOT EXISTS saml_requests(id TEXT PRIMARY KEY, value TEXT NOT NULL, expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS saml_flows(id TEXT PRIMARY KEY, request_id TEXT NOT NULL, expires INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS discoveries(id TEXT PRIMARY KEY, domain_id TEXT NOT NULL REFERENCES domains(id), actor TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT, result TEXT);
  `);
  const addColumn=(table,name,definition)=>{
    if(!db.prepare(`PRAGMA table_info(${table})`).all().some(c=>c.name===name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
  };
  addColumn('domains','parent_id','TEXT REFERENCES domains(id)');
  addColumn('domains','source',"TEXT NOT NULL DEFAULT 'manual'");
  addColumn('domains','dns_state',"TEXT NOT NULL DEFAULT 'unknown'");
  addColumn('domains','addresses',"TEXT NOT NULL DEFAULT '[]'");
  addColumn('domains','dns_checked_at','TEXT');
  addColumn('scans','actor',"TEXT NOT NULL DEFAULT 'scheduler'");
  db.exec(`CREATE INDEX IF NOT EXISTS scans_domain_time ON scans(domain_id,started_at DESC);
    CREATE INDEX IF NOT EXISTS scans_domain_status_time ON scans(domain_id,status,started_at DESC);
    CREATE INDEX IF NOT EXISTS discoveries_domain_status ON discoveries(domain_id,status);
    CREATE INDEX IF NOT EXISTS domains_parent ON domains(parent_id);`);
  if(db.prepare("SELECT value FROM settings WHERE key='auth_protocol'").get()?.value!=='saml-v1') {
    db.exec("BEGIN; DELETE FROM sessions; DELETE FROM oauth_states; INSERT OR REPLACE INTO settings(key,value) VALUES('auth_protocol','saml-v1'); COMMIT;");
  }
  db.prepare("UPDATE scans SET status='interrupted', finished_at=? WHERE status='running'").run(new Date().toISOString());
  db.prepare("UPDATE discoveries SET status='interrupted', finished_at=? WHERE status='running'").run(new Date().toISOString());
  const audit = (actor,action,detail) => db.prepare('INSERT INTO audit(at,actor,action,detail) VALUES(?,?,?,?)').run(new Date().toISOString(),actor,action,detail);
  return {db,audit};
}
