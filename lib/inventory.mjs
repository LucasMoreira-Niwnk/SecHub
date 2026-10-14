export const MAX_ASSETS=500;
export const MAX_SUBDOMAINS=100;
export const withinDomain=(hostname,parent)=>hostname!==parent && hostname.endsWith('.'+parent);

export function relinkHierarchy(db) {
  const all=db.prepare('SELECT id,hostname,parent_id FROM domains ORDER BY length(hostname) DESC').all();
  const update=db.prepare('UPDATE domains SET parent_id=? WHERE id=?');
  for(const item of all) {
    const parent=all.find(other=>withinDomain(item.hostname,other.hostname));
    if(item.parent_id!==(parent?.id??null)) update.run(parent?.id??null,item.id);
  }
}

export function decodeScan(scan) {return scan?{...scan,result:scan.result?JSON.parse(scan.result):null}:null;}
export function inventory(db) {
  const last=db.prepare('SELECT * FROM scans WHERE domain_id=? ORDER BY started_at DESC,rowid DESC LIMIT 1');
  const completed=db.prepare("SELECT * FROM scans WHERE domain_id=? AND status='completed' ORDER BY started_at DESC,rowid DESC LIMIT 1");
  return db.prepare('SELECT * FROM domains ORDER BY hostname').all().map(d=>({...d,addresses:JSON.parse(d.addresses),latest_scan:decodeScan(last.get(d.id)),latest_completed_scan:decodeScan(completed.get(d.id))}));
}
