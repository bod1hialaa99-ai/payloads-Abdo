<#
  PowerBI-Audit.ps1 — Automated Power BI pentest / config audit (v1.1, sanitized output)
  ---------------------------------------------------------------------------------
  SCOPE  : dashboards D1/D2/D3 (GUIDs below) + the Power BI platform reachable by
           YOUR account. Deep data queries run ONLY against D1's dataset.
  OUTPUT : folder pbi-evidence-<timestamp>\
             SUMMARY.txt      <- SANITIZED, safe to share with your assistant
             SUMMARY.json     <- SANITIZED, machine-readable version of the same
             MANUAL-STEPS.txt <- local only (contains real URLs) - your to-do list
             MAPPING-KEEP-LOCAL.txt <- pseudonym -> real name (NEVER share)
             NN-*.json / *.txt     <- raw evidence (NEVER share)
  RULE   : everything except SUMMARY.txt / SUMMARY.json / console colors is local-only.
           No table/db/server/user names appear in SUMMARY.* - only WS-xx/DS-xx/TBL-xx/
           SRV-xx/USR-xx/GW-xx/APP-xx/FILE-xx pseudonyms + counts + verdicts.
  USAGE  : powershell -ExecutionPolicy Bypass -File .\PowerBI-Audit.ps1   [-NoSample]
#>
param(
    [string]$D1Workspace = "26471425-5fcd-4f48-b7dc-284b57edab98",
    [string]$D1Report    = "efdcac53-a136-43e8-a860-a3da6954e142",
    [string]$D1Dataset   = "abb04290-49f1-4cea-b62c-cd6a432bf063",
    [string]$D2App       = "b99fcdf7-1ab8-496e-9cc2-629c52d7876c",
    [string]$D2Report    = "54c492fd-7994-496d-8255-2de536f335fa",
    [string]$D3App       = "d923e468-c642-48cb-a4d1-e057a39aaaba",
    [string]$D3Report    = "0ba00849-7e2b-4e20-a23d-41299c664e33",
    [switch]$NoSample
)

$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMdd-HHmm"
$E     = Join-Path (Get-Location) "pbi-evidence-$stamp"
New-Item -ItemType Directory -Force -Path $E | Out-Null
try { Start-Transcript -Path (Join-Path $E "console-transcript.txt") | Out-Null } catch {}

# ---------- pseudonymization layer --------------------------------------------
$MapIdx = @{}; $MapFile = Join-Path $E "MAPPING-KEEP-LOCAL.txt"
function Anon([string]$real,[string]$prefix){
    if(-not $real){ return "$prefix-??" }
    $key = "$prefix|$real"
    if($MapIdx.ContainsKey($key)){ return $MapIdx[$key] }
    $n = 1 + @($MapIdx.Keys | Where-Object { $_ -like "$prefix|*" }).Count
    $p = "{0}-{1:d2}" -f $prefix,$n
    $MapIdx[$key] = $p
    Add-Content -Path $MapFile -Value "$p = $real"
    return $p
}

# ---------- tiny framework ----------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[object]
$Manual   = New-Object System.Collections.Generic.List[object]
$script:Seq = 0; $script:MSeq = 0
function Add-Finding([string]$Sev,[string]$Status,[string]$Title,[string]$Detail,[string]$Evidence){
    $script:Seq++
    $Findings.Add([pscustomobject]@{ ID=("F-{0:d2}" -f $script:Seq); Sev=$Sev; Status=$Status; Title=$Title; Detail=$Detail; Evidence=$Evidence }) | Out-Null
    $c = @{CRITICAL="Red";HIGH="Magenta";MEDIUM="Yellow";LOW="Cyan";INFO="Gray";SECURE="Green"}[$Sev]
    Write-Host ("  [{0}][{1}] F-{2:d2} {3} :: {4}" -f $Sev,$Status,$script:Seq,$Title,$Detail) -ForegroundColor $c
}
function Add-Manual([string]$Sev,[string]$What,[string]$Where,[switch]$ROE,[string]$ForFinding){
    $script:MSeq++
    $Manual.Add([pscustomobject]@{ ID=("M-{0:d2}" -f $script:MSeq); Sev=$Sev; What=$What; Where=$Where; ROE=$ROE.IsPresent; For=$ForFinding }) | Out-Null
}
function ApiGet([string]$Url){
    try { return @{ ok=$true; data=(Invoke-PowerBIRestMethod -Method Get -Url $Url | ConvertFrom-Json).value; err="" } }
    catch { return @{ ok=$false; data=$null; err=(($_.ErrorDetails.Message)+" "+($_.Exception.Message)) } }
}
function ApiPost([string]$Url,[string]$Body){
    try { return @{ ok=$true; data=(Invoke-PowerBIRestMethod -Method Post -Url $Url -Body $Body); err="" } }
    catch { return @{ ok=$false; data=$null; err=(($_.ErrorDetails.Message)+" "+($_.Exception.Message)) } }
}
function Save-Json($Obj,[string]$Name){ $Obj | ConvertTo-Json -Depth 10 | Out-File (Join-Path $E $Name) -Encoding utf8 }
function Mask-Email([string]$e){ if($e -match '^(.{2}).*?@(.+)$'){"$($Matches[1])***@$($Matches[2])"}else{$e} }
function DaxQuote([string]$t){ return "'" + ($t -replace "'","''") + "'" }
function FirstVal($row){ if($row){ ($row.PSObject.Properties | Select-Object -First 1).Value } }
function RowProp($rows){ foreach($c in @('[Name]','Name','[Table]','[ID]')){ if($rows -and ($rows | Where-Object { $_.$c })){ return $c } }; return $null }

# ---------- module + login ----------------------------------------------------
Write-Host "=== PowerBI-Audit v1.1 $stamp ===" -ForegroundColor White
if (-not (Get-Module -ListAvailable MicrosoftPowerBIMgmt)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module MicrosoftPowerBIMgmt -Scope CurrentUser -Force
}
Import-Module MicrosoftPowerBIMgmt
try { $null = Get-PowerBIAccessToken } catch { Connect-PowerBIServiceAccount }
try { $null = Get-PowerBIAccessToken } catch { Write-Host "LOGIN FAILED - aborting." -ForegroundColor Red; exit 1 }

# ================= PHASE 1 - identity ========================================
Write-Host "`nPHASE 1/6 : identity" -ForegroundColor White
$tok = (Get-PowerBIAccessToken)['Authorization'] -replace '^Bearer ',''
function Decode-JWT([string]$t){
    $p=$t.Split('.')[1].Replace('-','+').Replace('_','/')
    switch($p.Length%4){ 2{$p+='=='} 3{$p+='='} }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))|ConvertFrom-Json
}
$claims = Decode-JWT $tok; $me = $claims.upn
$meA  = Anon $me "USR"
$isAdmin = $claims.wids -contains "62e90394-69f5-4237-9190-012177145e10"
if ($isAdmin) { Add-Finding CRITICAL VERIFIED "Global-Admin role in your token" "role template 62e90394-... present" "01-claims-redacted.json"
                Add-Manual CRITICAL "Confirm whether Global Admin is intended for $meA" "platform" }
if ($claims.roles) { Add-Finding HIGH NEEDS-CONFIRM "Application roles in your token" "roles claim populated" "01-claims-redacted.json" }
$tenantMask = $claims.tid.Substring(0,8) + "***"
Save-Json ([pscustomobject]@{ aud=$claims.aud; upn=(Mask-Email $me); tid=$tenantMask; roles=$claims.roles; wids=$claims.wids; groupCount=@($claims.groups).Count }) "01-claims-redacted.json"

# ================= PHASE 2 - platform sweep ==================================
Write-Host "`nPHASE 2/6 : platform sweep (all workspaces you can see)" -ForegroundColor White
$ws = Get-PowerBIWorkspace
$wsA = @{}; foreach($w in $ws){ $wsA[$w.Id] = Anon $w.Name "WS" }
$ws | Select Id,Name,Type,State | Out-File (Join-Path $E "02-workspaces.txt")
Write-Host ("  workspaces visible: {0}" -f @($ws).Count)

$adm = ApiGet 'admin/groups?$top=100'
if ($adm.ok -and @($adm.data).Count -gt 0) {
    Save-Json $adm.data "03-adminprobe.json"
    if ($isAdmin) { Add-Finding INFO VERIFIED "Admin API works and you are admin" "$(@($adm.data).Count) workspaces tenant-wide visible" "03-adminprobe.json" }
    else { Add-Finding CRITICAL VERIFIED "NON-ADMIN account reads tenant-wide workspaces" "$(@($adm.data).Count) returned via admin API" "03-adminprobe.json" }
} else {
    Add-Finding SECURE VERIFIED "Admin API blocked" "boundary held for your account" "03-adminprobe.txt"
    $adm.err | Out-File (Join-Path $E "03-adminprobe.txt")
}

$rep = ApiGet 'reports'; $dash = ApiGet 'dashboards'; $apps = ApiGet 'apps'
$imp = $null; try { $imp = Get-PowerBIImport } catch {}
Save-Json $rep.data "04-reports.json"; Save-Json $dash.data "04-dashboards.json"
Save-Json $apps.data "04-apps.json";  Save-Json $imp    "04-imports.json"
Write-Host ("  reports:{0} dashboards:{1} apps:{2} imports:{3}" -f @($rep.data).Count,@($dash.data).Count,@($apps.data).Count,@($imp).Count)

$myRoles = @()
foreach ($w in $ws) {
    $u = ApiGet "groups/$($w.Id)/users"
    if ($u.ok) {
        Save-Json $u.data ("05-users-{0}.json" -f (($w.Name) -replace '[\\/:*?"<>|]','_'))
        $mine = $u.data | Where-Object { $_.emailAddress -ieq $me -or $_.identifier -ieq $me }
        if ($mine) { $myRoles += [pscustomobject]@{ ws=$wsA[$w.Id]; role=$mine.groupUserAccessRight } }
    }
}
Save-Json $myRoles "05-my-roles.json"
$writeRoles = @($myRoles | Where-Object { $_.role -in @('Admin','Member','Contributor') })
if ($writeRoles.Count -gt 0) {
    Add-Finding HIGH VERIFIED "Write-level roles held by your account" (($writeRoles | ForEach-Object { "$($_.ws)=$($_.role)" }) -join '; ') "05-my-roles.json"
}

# ================= PHASE 3 - datasources / params / dataflows / gateways =====
Write-Host "`nPHASE 3/6 : datasource & config metadata (all workspaces)" -ForegroundColor White
$secretRx = '(?i)passw|secret|token|apikey|api_key|key=|bearer|pwd=|sas='
$dsRows = New-Object System.Collections.Generic.List[object]
foreach ($w in $ws) {
    $wA = $wsA[$w.Id]
    $dss = ApiGet "groups/$($w.Id)/datasets"
    foreach ($ds in @($dss.data)) {
        $dsA = Anon $ds.Name "DS"
        $src = ApiGet "groups/$($w.Id)/datasets/$($ds.Id)/datasources"
        foreach ($s in @($src.data)) {
            $cd = $s.connectionDetails
            $srvA = $null; if($cd.server){ $srvA = Anon $cd.server "SRV" }
            $dsRows.Add([pscustomobject]@{ ws=$wA; ds=$dsA; type=$s.datasourceType
                srv=$srvA; db=($cd.database); url=($cd.url); creds=$s.credentialType; sso=$s.singleSignOnType; gw=$s.gatewayId }) | Out-Null
        }
        $pars = ApiGet "groups/$($w.Id)/datasets/$($ds.Id)/parameters"
        foreach ($p in @($pars.data)) {
            if (($p.currentValue -and $p.currentValue -match $secretRx) -or $p.name -match $secretRx) {
                Add-Finding HIGH VERIFIED "Secret-looking dataset parameter" "$dsA in $wA (name/value in evidence only)" "06-parameters.json" }
        }
    }
    $dfs = ApiGet "groups/$($w.Id)/dataflows"
    foreach ($df in @($dfs.data)) {
        $dfA = Anon $df.Name "DF"
        $fds = ApiGet "groups/$($w.Id)/dataflows/$($df.ObjectId)/datasources"
        foreach ($s in @($fds.data)) {
            $srvA = $null; if($s.connectionDetails.server){ $srvA = Anon $s.connectionDetails.server "SRV" }
            $dsRows.Add([pscustomobject]@{ ws=$wA; ds=$dfA; type=$s.datasourceType; srv=$srvA; db=$s.connectionDetails.database; url=$s.connectionDetails.url; creds=$s.credentialType; sso=$s.singleSignOnType; gw=$s.gatewayId }) | Out-Null
        }
    }
}
Save-Json $dsRows "06-datasources-sanitized.json"     # already pseudonymized
$basic = @($dsRows | Where-Object { $_.creds -eq "Basic" })
$kerb  = @($dsRows | Where-Object { $_.sso -eq "Kerberos" })
$hosts = @($dsRows | Where-Object { $_.srv }).srv | Select-Object -Unique
if ($basic.Count) { Add-Finding MEDIUM INFO "Stored Basic credentials behind gateway" "$($basic.Count) datasource(s) [$($basic.type | Select-Object -Unique)]: creds recoverable only on the gateway host" "06-datasources-sanitized.json"
    Add-Manual MEDIUM "Gateway-host check: if local admin on the GW host is in reach, stored datasource credentials become recoverable (recovery-key path)" "platform" }
if ($kerb.Count)  { Add-Finding LOW INFO "Kerberos SSO datasources" "$($kerb.Count) - delegation surface on the gateway service account" "06-datasources-sanitized.json" }
if ($hosts.Count) { Add-Finding LOW INFO "Internal hostnames disclosed via API" "$($hosts.Count) unique internal server(s) visible: $($hosts -join ', ')" "06-datasources-sanitized.json" }

$gws = ApiGet 'gateways'
Save-Json (@($gws.data) | ForEach-Object { [pscustomobject]@{ id=$_.Id; name=$_.Name; type=$_.Type } }) "07-gateways.json"
foreach ($g in @($gws.data)) { $gds = ApiPost "" ""; $gds = ApiGet "gateways/$($g.Id)/datasources"; Save-Json (@($gds.data) | Select datasourceType,credentialType,singleSignOnType) "07-gw-datasources.json" }
if (@($gws.data).Count) { Add-Finding INFO INFO "Gateways visible" "$(@($gws.data).Count) gateway(s) usable by your account" "07-gateways.json" }
Write-Host ("  datasource rows: {0} | gateways: {1}" -f $dsRows.Count,@($gws.data).Count)

# ================= PHASE 4 - D1 deep tests ===================================
Write-Host "`nPHASE 4/6 : D1 deep tests (in-scope dataset)" -ForegroundColor White
$g = $D1Workspace; $r = $D1Report; $d = $D1Dataset
$d1WA = $wsA[$g]; if(-not $d1WA){ $d1WA = "WS-D1" }
$rpt = Get-PowerBIReport -WorkspaceId $g
$link = $rpt | Where-Object { $_.Id -eq $r }
if ($link -and $link.DatasetId) { $d = $link.DatasetId }
$d1A = Anon $link.Name "DS"

$d1Users = ApiGet "groups/$g/users"
$mineRole = ($d1Users.data | Where-Object { $_.emailAddress -ieq $me }).groupUserAccessRight
$viewers  = @($d1Users.data | Where-Object { $_.groupUserAccessRight -eq "Viewer" }).Count
$writers  = @($d1Users.data | Where-Object { $_.groupUserAccessRight -in @('Admin','Member','Contributor') })
Save-Json ($d1Users.data | Select displayName,emailAddress,groupUserAccessRight) "08-d1-users.json"
if ($mineRole -in @('Admin','Member','Contributor')) {
    Add-Finding HIGH VERIFIED "Your account holds $mineRole on the D1 workspace ($d1WA)" "Write-level => RLS is NOT applied to you on $d1A; Viewer population: $viewers" "08-d1-users.json"
}
$contractors = @($writers | Where-Object { $_.emailAddress -match '(?i)contract|vendor|ext|temp|consult' })
if ($contractors.Count) { Add-Finding HIGH NEEDS-CONFIRM "External/contractor accounts with write roles on D1" "$($contractors.Count) account(s) (emails in evidence only)" "08-d1-users.json"
    Add-Manual HIGH "Confirm with client whether the contractor write-role(s) on $d1WA are approved" $d1WA -ForFinding ("F-{0:d2}" -f $script:Seq) }

try {
    Export-PowerBIReport -Id $r -WorkspaceId $g -OutFile (Join-Path $E "d1-report-download.pbix") -ErrorAction Stop
    $sz = [Math]::Round((Get-Item (Join-Path $E "d1-report-download.pbix")).Length/1KB)
    Add-Finding HIGH VERIFIED "Full .pbix model downloadable via API" "D1 report model downloaded ($sz KB) - contains entire dataset, not the filtered view" "d1-report-download.pbix"
} catch {
    $err=(($_.ErrorDetails.Message)+" "+($_.Exception.Message)); $err | Out-File (Join-Path $E "09-export.txt")
    Add-Finding SECURE VERIFIED "API .pbix export blocked for your account" "boundary held" "09-export.txt"
}

# ---- model + data (D1 only) ----
$eq = $true
$tq = ApiPost "groups/$g/datasets/$d/executeQueries" '{"queries":[{"query":"EVALUATE INFO.VIEW.TABLES()"}]}'
if (-not $tq.ok) { $tq.err | Out-File (Join-Path $E "10-tables.txt")
    Add-Finding SECURE VERIFIED "executeQueries blocked on D1 dataset" "boundary held" "10-tables.txt"; $eq = $false }
$tblA = @{}; $target = $null; $counts = @{}
if ($eq) {
    $j = $tq.data | ConvertFrom-Json
    $rows = $j.results[0].tables[0].rows
    $prop = RowProp $rows
    $tables = @($rows | ForEach-Object { $_.$prop })
    Save-Json $tables "10-d1-tables.json"
    foreach($t in $tables){ $tblA[$t] = Anon $t "TBL" }
    Write-Host ("  tables in model: {0}" -f $tables.Count)
    Add-Finding HIGH VERIFIED "Full model schema readable via executeQueries" "$($tables.Count) tables enumerable as role=$mineRole" "10-d1-tables.json"

    $i = 0
    foreach ($t in ($tables | Select-Object -First 25)) {
        $c = ApiPost "groups/$g/datasets/$d/executeQueries" ('{"queries":[{"query":"EVALUATE COUNTROWS(' + (DaxQuote $t) + ')"}]}')
        if ($c.ok) { $j2 = $c.data | ConvertFrom-Json; $counts[$t] = FirstVal $j2.results[0].tables[0].rows[0] }
        $i++; if ($i % 5 -eq 0) { Write-Host "    counted $i" }
    }
    Save-Json $counts "11-d1-counts.json"
    $nonzero = @($counts.Keys | Where-Object { $counts[$_] -gt 0 })
    if ($nonzero.Count) {
        $top = ($counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { "$($tblA[$_.Key])=$($_.Value)" }) -join ' '
        Add-Finding HIGH VERIFIED "Data rows readable via executeQueries" "$($nonzero.Count)/$($tables.Count) sampled tables non-empty; largest: $top" "11-d1-counts.json"

        $sensRx = '(?i)salar|employ|payroll|human|hr|claim|policy|premium|customer|client|invoice|payment|financ|revenue|loss|account'
        $target = ($nonzero | Where-Object { $_ -match $sensRx } | Select-Object -First 1)
        if (-not $target) { $target = $nonzero | Sort-Object { $counts[$_] } -Descending | Select-Object -First 1 }
        if (-not $NoSample) {
            $s = ApiPost "groups/$g/datasets/$d/executeQueries" ('{"queries":[{"query":"EVALUATE TOPN(3,' + (DaxQuote $target) + ')"}]}')
            if ($s.ok) { $js = $s.data | ConvertFrom-Json
                Save-Json $js.results[0].tables[0].rows "12-d1-sample.json"
                $first = $js.results[0].tables[0].rows | Select-Object -First 1
                Add-Finding HIGH VERIFIED "Actual data extracted from D1 dataset" "3 rows x $($first.PSObject.Properties.Count) cols from $($tblA[$target]) (rows kept LOCAL in evidence only)" "12-d1-sample.json" }
        }
    }
}
# ---- impersonation (RLS) ----
if ($eq -and $target -and $counts[$target]) {
    $other = ($d1Users.data | Where-Object { $_.emailAddress -and $_.emailAddress -ine $me } | Select-Object -First 1).emailAddress
    if ($other) {
        $oA = Anon $other "USR"
        $body = '{"queries":[{"query":"EVALUATE COUNTROWS(' + (DaxQuote $target) + ')"}],"impersonatedUserName":"' + $other + '"}'
        $ic = ApiPost "groups/$g/datasets/$d/executeQueries" $body
        if ($ic.ok) {
            $ji = $ic.data | ConvertFrom-Json
            $icount = FirstVal $ji.results[0].tables[0].rows[0]
            Save-Json @{ own=$counts[$target]; as=$oA; impersonated=$icount } "13-impersonation.json"
            if ($icount -eq $counts[$target]) {
                Add-Finding MEDIUM NEEDS-CONFIRM "Dataset appears to have NO RLS" "$($tblA[$target]): same count as self and as $oA -> confirm sensitivity + Viewer population ($viewers)" "13-impersonation.json"
                Add-Manual MEDIUM "Compare report visuals (B1) with count $($counts[$target]) on $($tblA[$target]); if report unfiltered too, RLS absent" $d1WA
            } else {
                Add-Finding HIGH VERIFIED "Impersonation works (other users' RLS slices readable)" "own=$($counts[$target]) vs impersonated=$icount as $oA" "13-impersonation.json"
            }
        } else { $ic.err | Out-File (Join-Path $E "13-impersonation.txt")
            Add-Finding SECURE VERIFIED "Impersonated query blocked" "boundary held" "13-impersonation.txt" }
    }
    $gtBody = @{ accessLevel='View'; datasetId=$d; identities=@(@{ username=$other; datasets=@($d) }) } | ConvertTo-Json -Depth 6
    $gt = ApiPost "groups/$g/reports/$r/GenerateToken" $gtBody
    if ($gt.ok) { Save-Json $gt.data "14-embedtoken.json"
        Add-Finding HIGH VERIFIED "Embed token minted with another user identity" "identity=$oA on D1 report - RLS bypass primitive" "14-embedtoken.json" }
    else { $gt.err | Out-File (Join-Path $E "14-embedtoken.txt")
        Add-Finding SECURE VERIFIED "Embed-token mint blocked" "boundary held" "14-embedtoken.txt" }
}
$rf = ApiGet "groups/$g/datasets/$d/refreshes?`$top=10"
Save-Json $rf.data "15-d1-refreshes.json"
if (@($rf.data | Where-Object { $_.status -match 'Failed' }).Count) {
    Add-Finding LOW INFO "Failed refreshes on D1" "error bodies may leak paths/accounts (evidence only)" "15-d1-refreshes.json" }

# ================= PHASE 5 - D2/D3 app probes ================================
Write-Host "`nPHASE 5/6 : D2 / D3 app reports" -ForegroundColor White
foreach ($pair in @(@{n="D2";a=$D2App;rid=$D2Report}, @{n="D3";a=$D3App;rid=$D3Report})) {
    $ar = ApiGet "apps/$($pair.a)/reports"
    if (-not $ar.ok) { Add-Finding INFO INFO "$($pair.n) app reports not listable" "API boundary" "17-$($pair.n).txt"; $ar.err | Out-File (Join-Path $E "17-$($pair.n).txt"); continue }
    Save-Json (@($ar.data) | Select Id,Name,DatasetId) "17-$($pair.n)-app-reports.json"
    $dset = ($ar.data | Where-Object { $_.Id -eq $pair.rid }).datasetId
    if (-not $dset -and $ar.data) { $dset = ($ar.data | Select-Object -First 1).datasetId }
    Write-Host ("  {0}: reports={1} datasetResolved={2}" -f $pair.n,@($ar.data).Count,($dset -ne $null))
    if ($dset) {
        $p = ApiPost "datasets/$dset/executeQueries" '{"queries":[{"query":"EVALUATE INFO.VIEW.TABLES()"}]}'
        if ($p.ok) { Save-Json $p.data "18-$($pair.n)-appprobe.json"
            Add-Finding HIGH VERIFIED "$($pair.n) app dataset queryable by app consumer" "executeQueries succeeded - app audience member can query model" "18-$($pair.n)-appprobe.json" }
        else { $p.err | Out-File (Join-Path $E "18-$($pair.n)-appprobe.txt")
            Add-Finding SECURE VERIFIED "$($pair.n) app dataset NOT queryable" "boundary held" "18-$($pair.n)-appprobe.txt" }
    }
}

# ================= PHASE 6 - local artifacts =================================
Write-Host "`nPHASE 6/6 : local workstation artifacts" -ForegroundColor White
$pbix = Get-ChildItem "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads" -Recurse -Include *.pbix,*.pbit,*.pbip -ErrorAction SilentlyContinue
if ($pbix) { $pbix | Select FullName,Length,LastWriteTime | Out-File (Join-Path $E "19-local-pbix.txt")
    $fa = $pbix | ForEach-Object { Anon $_.FullName "FILE" }
    Add-Finding LOW INFO "Local .pbix/.pbit files present" "$($fa.Count) file(s) - each contains full cached data of its dataset" "19-local-pbix.txt" }
$svc = Get-Service | Where-Object { $_.DisplayName -match 'gateway|power\s*bi' }
$svc | Out-File (Join-Path $E "20-services.txt")
if ($svc) { Add-Finding MEDIUM INFO "Gateway/Power BI services on YOUR machine" (($svc | ForEach-Object { $_.DisplayName }) -join '; ') "20-services.txt" }
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Power BI Desktop" -Recurse -ErrorAction SilentlyContinue | Select FullName,Length | Out-File (Join-Path $E "21-desktop-artifacts.txt")

# ================= fixed manual browser tests ================================
Add-Manual HIGH "B1 baseline: open dashboard, record which rows/regions you SEE (needed to compare with API counts)" "D1,D2,D3"
Add-Manual HIGH "B2 /edit: open /edit URL of each report - Viewer must land read-only; editor loads = finding" "D1,D2,D3"
Add-Manual MEDIUM "B3 visual Export data: record allowed level (summary/underlying) + row counts" "D1,D2,D3"
Add-Manual MEDIUM "B4 Share dialog: record offered link types only (do NOT send)" "D1,D2,D3"
Add-Manual HIGH "B5 File->Download report (.pbix): does the UI allow it; if yes open in Desktop" "D1,D2,D3"
Add-Manual HIGH "B6 [ROE] File->Embed->Website or portal (publish-to-web): public link = critical exposure; screenshot then DELETE embed" "D1,D2,D3" -ROE
Add-Manual MEDIUM "B7 [ROE] forward a specific-people share link to internal test account - does it grant access?" "D1,D2,D3" -ROE
Add-Manual MEDIUM "B8 [ROE] attempt external share to an outside email" "D1,D2,D3" -ROE
Add-Manual LOW "TC-36 Analyze in Excel on D1: pivot all tables, compare rows vs visuals" "D1"
Add-Manual MEDIUM "TC-37 partial-RLS: with Build permission create new report on $d1A, drag fields from EVERY table - unfiltered tables reveal missing RLS" "D1"

# ================= output =====================================================
$rank = ('CRITICAL','HIGH','MEDIUM','LOW','INFO','SECURE')
$score = ($Findings | Group-Object Sev | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
$mRank = ($rank | ForEach-Object { $n=$_; @($Manual | Where-Object Sev -eq $_).Count })

$summaryTxt = @"
POWER BI AUDIT SUMMARY (sanitized - safe to share)
run=$stamp  tenant=$tenantMask  user=$meA  scope=D1+D2+D3+platform
scoreboard: $score
pseudonyms: WS=workspace DS=dataset TBL=table SRV=server USR=user GW=gateway DF=dataflow FILE=local file
(real names exist ONLY in local MAPPING-KEEP-LOCAL.txt + evidence files)

FINDINGS:
$($Findings | Sort-Object @{Expression={ $rank.IndexOf($_.Sev) }} | ForEach-Object { "[{0}][{1}] {2} {3} :: {4} (ev:{5})" -f $_.Sev,$_.Status,$_.ID,$_.Title,$_.Detail,$_.Evidence } | Out-String -Width 220)

MANUAL ACTIONS (work through with your assistant - details in MANUAL-STEPS.txt):
$($Manual | Sort-Object @{Expression={ $rank.IndexOf($_.Sev) }} | ForEach-Object { "{0} [{1}]{2} {3} @ {4}{5}" -f $_.ID,$_.Sev,$(if($_.ROE){'[ROE]'}else{''}),$_.What,$_.Where,$(if($_.For){" (from $_.For)"}else{''}) } | Out-String -Width 220)

full evidence (local only): $E
"@
$summaryTxt | Out-File (Join-Path $E "SUMMARY.txt") -Encoding utf8

[pscustomobject]@{ run=$stamp; tenant=$tenantMask; user=$meA; scope="D1+D2+D3+platform"
    scoreboard=$score; findings=$Findings; manual=$Manual } |
    ConvertTo-Json -Depth 6 | Out-File (Join-Path $E "SUMMARY.json") -Encoding utf8

$manualTxt = @"
MANUAL STEPS (LOCAL FILE - contains real URLs - do not share)
D1 : https://app.powerbi.com/groups/$D1Workspace/reports/$D1Report/d6ad6132c0ae19b64abe?experience=power-bi
D1e: https://app.powerbi.com/groups/$D1Workspace/reports/$D1Report/edit?experience=power-bi
D2 : https://app.powerbi.com/groups/me/apps/$D2App/reports/$D2Report/ReportSection9e9d6b77273fc73e3584?experience=power-bi
D3 : https://app.powerbi.com/groups/me/apps/$D3App/reports/$D3Report/c38c2b21e667d0470005?experience=power-bi
"@
($manualTxt + "`n" + (($Manual | Sort-Object @{Expression={ $rank.IndexOf($_.Sev) }}) | ForEach-Object { "{0} [{1}]{2} {3} @ {4}" -f $_.ID,$_.Sev,$(if($_.ROE){'[ROE]'}else{''}),$_.What,$_.Where } | Out-String)) |
    Out-File (Join-Path $E "MANUAL-STEPS.txt") -Encoding utf8

"SHARE-SAFE: SUMMARY.txt, SUMMARY.json`nKEEP-LOCAL: everything else in this folder (mapping, evidence, transcript, pbix)" |
    Out-File (Join-Path $E "README.txt") -Encoding utf8

Write-Host "`n================ DONE ================" -ForegroundColor Green
$Findings | Sort-Object @{Expression={ $rank.IndexOf($_.Sev) }} | Format-Table ID,Sev,Status,Title -AutoSize | Out-String -Width 200 | Write-Host -ForegroundColor White
Write-Host "SHARE-SAFE SUMMARY: $E\SUMMARY.txt  (+SUMMARY.json)" -ForegroundColor Yellow
try { Stop-Transcript | Out-Null } catch {}
Invoke-Item $E
