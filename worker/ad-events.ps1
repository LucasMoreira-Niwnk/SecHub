$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PARAMS__')) | ConvertFrom-Json
try {
  $log = Get-WinEvent -ListLog Security
  $newest = Get-WinEvent -LogName Security -MaxEvents 1
  $upper = [long]$newest.RecordId
  $cursor = [long]$p.cursor
  $warning = ''
  if ($cursor -gt $upper) { $cursor = 0; $warning = 'LOG_RESET' }
  if ($cursor -gt 0 -and [long]$log.OldestRecordNumber -gt ($cursor + 1)) { $warning = 'LOG_GAP' }
  $ids = 'EventID=4624 or EventID=4625 or EventID=4672 or EventID=4728 or EventID=4732 or EventID=4740 or EventID=4756 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776 or EventID=1102 or EventID=4719'
  $range = "EventRecordID > $cursor and EventRecordID <= $upper"
  if ($cursor -eq 0) { $range += ' and TimeCreated[timediff(@SystemTime) <= 900000]' }
  $xpath = "*[System[($ids) and ($range)]]"
  $items = @()
  try { $items = @(Get-WinEvent -LogName Security -FilterXPath $xpath -Oldest -MaxEvents 501) }
  catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
  $backlog = $items.Count -gt 500
  $items = @($items | Select-Object -First 500)
  $events = @($items | ForEach-Object {
    $event = $_; $xml = [xml]$event.ToXml(); $d = @{}
    foreach ($entry in $xml.Event.EventData.Data) { if ($entry.Name) { $d[[string]$entry.Name] = ([string]$entry.'#text').Substring(0,[Math]::Min(300,([string]$entry.'#text').Length)) } }
    $user = $d.TargetUserName; $domain = $d.TargetDomainName
    if (-not $user) { $user = $d.SubjectUserName; $domain = $d.SubjectDomainName }
    $status = $d.Status
    if ($d.SubStatus -and $d.SubStatus -notin @('0x0','0x00000000')) { $status = $d.SubStatus }
    [ordered]@{ eventId=[int]$event.Id; recordId=[long]$event.RecordId; time=$event.TimeCreated.ToUniversalTime().ToString('o'); computer=[string]$xml.Event.System.Computer; user=$user; domain=$domain; actor=([string]$d.SubjectDomainName + '\' + [string]$d.SubjectUserName); ip=$d.IpAddress; workstation=$d.WorkstationName; logonType=$d.LogonType; status=$status; group=$d.TargetUserName; groupSid=$d.TargetSid; member=$d.MemberName }
  })
  $next = $upper
  if ($backlog -and $items.Count -gt 0) { $next = [long]$items[-1].RecordId }
  @{events=$events; cursor=$next; backlog=$backlog; warning=$warning} | ConvertTo-Json -Depth 6 -Compress
} catch {
  $code = 'EVENT_QUERY_FAILED'
  if ($_.Exception -is [UnauthorizedAccessException] -or $_.FullyQualifiedErrorId -match 'Unauthorized|AccessDenied') { $code = 'ACCESS_DENIED' }
  @{error=$code} | ConvertTo-Json -Compress
  exit 1
}
