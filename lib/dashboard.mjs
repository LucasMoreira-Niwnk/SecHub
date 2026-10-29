const zone='America/Sao_Paulo';
const dateFormat=new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit'});
const clockFormat=new Intl.DateTimeFormat('en-GB',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'});
const dateKey=value=>{const p=Object.fromEntries(dateFormat.formatToParts(value).map(v=>[v.type,v.value]));return `${p.year}-${p.month}-${p.day}`;};
const shift=(date,days)=>new Date(Date.parse(date+'T12:00:00Z')+days*86400000).toISOString().slice(0,10);
function midnight(date){
  const target=Date.parse(date+'T00:00:00Z');let instant=target;
  for(let i=0;i<3;i++){
    const p=Object.fromEntries(clockFormat.formatToParts(new Date(instant)).map(v=>[v.type,v.value]));
    const seen=Date.UTC(Number(p.year),Number(p.month)-1,Number(p.day),Number(p.hour),Number(p.minute),Number(p.second));
    instant+=target-seen;
  }
  return new Date(instant).toISOString();
}
export function dashboardRange(params=new URLSearchParams(),now=new Date()){
  const today=dateKey(now),days=params.get('days')||'7',scope=params.get('accounts')||'users';
  if(!['users','machines','all'].includes(scope))throw new Error('Dashboard: filtro de contas inválido.');
  let start,end;
  if(params.has('start')||params.has('end')){
    start=params.get('start');end=params.get('end');
    for(const value of [start,end])if(!/^\d{4}-\d{2}-\d{2}$/.test(value||'')||!Number.isFinite(Date.parse(value+'T00:00:00Z'))||new Date(value+'T00:00:00Z').toISOString().slice(0,10)!==value)throw new Error('Dashboard: datas inválidas.');
  }else{
    if(!/^(?:[1-9]|[12]\d|30)$/.test(days))throw new Error('Dashboard: selecione de 1 a 30 dias.');
    start=shift(today,1-Number(days));end=today;
  }
  const count=Math.round((Date.parse(end)-Date.parse(start))/86400000)+1;
  if(count<1||count>30||end>today||start<shift(today,-29))throw new Error('Dashboard: período deve estar nos últimos 30 dias.');
  const buckets=Array.from({length:count},(_,i)=>{const date=shift(start,i);return {date,from:midnight(date),to:midnight(shift(date,1))};});
  return {start,end,days:count,from:buckets[0].from,to:buckets.at(-1).to,timeZone:zone,accounts:scope,buckets};
}
export function createDashboard(db){
  function build(params,now=new Date()){
    const range=dashboardRange(params,now),{from,to,accounts}=range;
    const accountFilter=accounts==='all'?"account<>''":accounts==='machines'?"substr(account,-1)='$'":"account<>'' AND substr(account,-1)<>'$' AND lower(json_extract(data,'$.user')) NOT IN ('anonymous logon','system','local service','network service','-')";
    const authFilter=`time>=? AND time<? AND outcome IN ('success','failure') AND ${accountFilter}`;
    const totals=db.prepare(`SELECT count(*) attempts,coalesce(sum(outcome='success'),0) successes,coalesce(sum(outcome='failure'),0) failures,count(DISTINCT account) accounts,coalesce(sum(event_id=4624 AND outcome='success'),0) logons FROM ad_events WHERE ${authFilter}`).get(from,to);
    const rank=outcome=>db.prepare(`SELECT account,count(*) count,count(DISTINCT nullif(origin,'')) origins,max(time) lastSeen FROM ad_events WHERE ${authFilter} AND outcome=? GROUP BY account ORDER BY count DESC,account LIMIT 10`).all(from,to,outcome);
    const series=range.buckets.map(b=>({...b,...db.prepare(`SELECT coalesce(sum(outcome='success'),0) successes,coalesce(sum(outcome='failure'),0) failures FROM ad_events WHERE ${authFilter}`).get(b.from,b.to)}));
    const alertStats=db.prepare("SELECT count(*) total,coalesce(sum(status='pending'),0) pending,coalesce(sum(status='confirmed'),0) confirmed,coalesce(sum(status='false-positive'),0) falsePositive FROM ad_alerts WHERE created_at>=? AND created_at<?").get(from,to);
    const alertsByRule=db.prepare('SELECT rule,title,severity,count(*) count FROM ad_alerts WHERE created_at>=? AND created_at<? GROUP BY rule,title,severity ORDER BY count DESC,rule LIMIT 10').all(from,to);
    const origins=db.prepare(`SELECT origin,count(*) count,count(DISTINCT account) accounts FROM ad_events WHERE ${authFilter} AND outcome='failure' AND origin<>'' GROUP BY origin ORDER BY count DESC,origin LIMIT 5`).all(from,to);
    const eventTypes=db.prepare(`SELECT event_id eventId,count(*) count FROM ad_events WHERE ${authFilter} GROUP BY event_id ORDER BY count DESC,event_id`).all(from,to);
    const coverage=db.prepare('SELECT min(time) firstEvent,max(time) lastEvent,count(*) retainedEvents FROM ad_events').get();
    const executions=(table,column,extra='')=>db.prepare(`SELECT status,count(*) count FROM ${table} WHERE ${column}>=? AND ${column}<? ${extra} GROUP BY status`).all(from,to);
    return {range:{...range,buckets:undefined},generatedAt:now.toISOString(),ad:{totals,topSuccess:rank('success'),topFailures:rank('failure'),series,alertStats,alertsByRule,origins,eventTypes,coverage},modules:{public:executions('scans','started_at'),zap:executions('zap_scans','created_at'),internal:executions('collection_jobs','created_at',"AND kind='internal'"),aws:executions('collection_jobs','created_at',"AND kind='aws'")}};
  }
  return {build};
}
