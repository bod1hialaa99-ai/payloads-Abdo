<#
  PowerBI-Audit.ps1 — Automated Power BI pentest / config audit (v1.2)
  ------------------------------------------------------------------
  v1.2 changes:
    - each finding now carries Impact + Fix + a REPRO ID (R-xx)
    - REPRO-STEPS.txt (LOCAL, real GUIDs/names) = exact commands to re-show each finding
    - fixed false-positive admin probe (empty response counted as 1)
    - fixed false-positive gateway services (Bluetooth/ALG matched)
    - executeQueries counting is throttle-safe (2.5s pacing, stops after 3 failures)
    - impersonation + embed-token tests decoupled from counting success
    - D2/D3 dataset resolution with diagnostics
  SHARE-SAFE outputs : SUMMARY.txt + SUMMARY.json   (pseudonyms only)
  KEEP-LOCAL        : everything else (mapping, evidence, REPRO-STEPS.txt, MANUAL-STEPS.txt)
  USAGE             : powershell -ExecutionPolicy Bypass -File .\PowerBI-Audit.ps1 [-NoSample]
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

# ---------- pseudonymization --------------------------------------------------
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

# ---------- framework ---------------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[object]
$Manual   = New-Object System.Collections.Generic.List[object]
$Repros   = New-Object System.Collections.Generic.List[object]
$script:Seq = 0; $script:MSeq = 0; $script:RSeq = 0
function Add-Finding([string]$Sev,[string]$Status,[string]$Title,[string]$Detail,[string]$Evidence,
                     [string]$Impact="",[string]$Fix="",[string]$ReproCmd=""){
    $script:Seq++
    $rid = ""
    if($ReproCmd){
        $script:RSeq++
        $rid = "R-{0:d2}" -f $script:RSeq
        $Repros.Add([pscustomobject]@{ ID=$rid; For=("F-{0:d2}" -f $script:Seq); Title=$Title; Command=$ReproCmd }) | Out-Null
    }
    $Findings.Add([pscustomobject]@{ ID=("F-{0:d2}" -f $script:Seq); Sev=$Sev; Status=$Status; Title=$Title
        Detail=$Detail; Evidence=$Evidence; Impact=$Impact; Fix=$Fix; Repro=$rid }) | Out-Null
    $c = @{CRITICAL="Red";HIGH="Magenta";MEDIUM="Yellow";LOW="Cyan";INFO="Gray";SECURE="Green"}[$Sev]
    Write-Host ("  [{0}][{1}] F-{2:d2} {3}" -f $Sev,$Status,$script:Seq,$Title) -ForegroundColor $c
    return $Findings[$Findings.Count-1].ID
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
function CountSafe($x){ if($x){ @($x).Count } else { 0 } }

# ---------- module + login ----------------------------------------------------
Write-Host "=== PowerBI-Audit v1.2 $stamp ===" -ForegroundColor White
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
$meA = Anon $me "USR"
$isAdmin = $claims.wids -contains "62e90394-69f5-4237-9190-012177145e10"
if ($isAdmin) { Add-Finding CRITICAL VERIFIED "Global-Admin role in your token" "role template present" "01-claims-redacted.json" "full tenant control from a contractor identity" "remove admin roles from this account" "Get-PowerBIAccessToken then decode wids" }
if ($claims.roles) { Add-Finding HIGH NEEDS-CONFIRM "Application roles in your token" "roles claim populated" "01-claims-redacted.json" "possible elevated app permissions" "review app role assignments in Entra" "decode token roles claim" }
$tenantMask = $claims.tid.Substring(0,8) + "***"
Save-Json ([pscustomobject]@{ aud=$claims.aud; upn=(Mask-Email $me); tid=$tenantMask; roles=$claims.roles; wids=$claims.wids; groupCount=@($claims.groups).Count }) "01-claims-redacted.json"

# ================= PHASE 2 - platform sweep ==================================
Write-Host "`nPHASE 2/6 : platform sweep" -ForegroundColor White
$ws = Get-PowerBIWorkspace
$wsA = @{}; foreach($w in $ws){ $wsA[$w.Id] = Anon $w.Name "WS" }
$ws | Select Id,Name,Type,State | Out-File (Join-Path $E "02-workspaces.txt")
Write-Host ("  workspaces visible: {0}" -f (CountSafe $ws))

# admin probe (v1.2: null-safe counting + raw response saved)
$admRaw = ""
try { $admRaw = Invoke-PowerBIRestMethod -Method Get -Url 'admin/groups?$top=100' } catch { $admRaw = "ERROR: " + (($_.ErrorDetails.Message)+" "+($_.Exception.Message)) }
$admRaw | Out-File (Join-Path $E "03-adminprobe-raw.txt") -Encoding utf8
$admData = $null
if ($admRaw -notmatch '^ERROR') { try { $admData = ($admRaw | ConvertFrom-Json).value } catch {} }
$admCount = CountSafe $admData
if ($admCount -gt 0) {
    Save-Json $admData "03-adminprobe.json"
    if ($isAdmin) { Add-Finding INFO VERIFIED "Admin API works (you are admin)" "$admCount workspaces tenant-wide" "03-adminprobe.json" "expected for admins" "" "Invoke-PowerBIRestMethod -Method Get -Url 'admin/groups?`$top=10'" }
    else { Add-Finding CRITICAL VERIFIED "NON-ADMIN account reads tenant-wide workspaces" "$admCount returned via admin API" "03-adminprobe.json" "tenant-wide workspace/metadata exposure from a non-admin identity" "restrict Power BI admin API to Fabric/Power BI admins" "Invoke-PowerBIRestMethod -Method Get -Url 'admin/groups?`$top=10'" }
} elseif ($admRaw -notmatch '^ERROR') {
    Add-Finding INFO NEEDS-CONFIRM "Admin API returned 200 with EMPTY result" "unusual - retest manually (repro R file)" "03-adminprobe-raw.txt" "unclear admin boundary" "" "Invoke-PowerBIRestMethod -Method Get -Url 'admin/groups?`$top=10'"
} else {
    Add-Finding SECURE VERIFIED "Admin API blocked" "boundary held" "03-adminprobe-raw.txt" "good: non-admin cannot enumerate tenant" "" "Invoke-PowerBIRestMethod -Method Get -Url 'admin/groups?`$top=10'"
}

$rep = ApiGet 'reports'; $dash = ApiGet 'dashboards'; $apps = ApiGet 'apps'
$imp = $null; try { $imp = Get-PowerBIImport } catch {}
Save-Json $rep.data "04-reports.json"; Save-Json $dash.data "04-dashboards.json"
Save-Json $apps.data "04-apps.json";  Save-Json $imp "04-imports.json"
Write-Host ("  reports:{0} dashboards:{1} apps:{2} imports:{3}" -f (CountSafe $rep.data),(CountSafe $dash.data),(CountSafe $apps.data),(CountSafe $imp))

$myRoles = @()
foreach ($w in $ws) {
    $u = ApiGet "groups/$($w.Id)/users"
    if ($u.ok) {
        Save-Json $u.data ("05-users-{0}.json" -f (($w.Name) -replace '[\\/:*?"<>|]','_'))
        $mine = $u.data | Where-Object { $_.emailAddress -ieq $me -or $_.identifier -ieq $me }
        if ($mine) { $myRoles += [pscustomobject]@{ ws=$wsA[$w.Id]; role=$mine.groupUserAccessRight; guid=$w.Id } }
    }
}
Save-Json ($myRoles | Select ws,role,guid) "05-my-roles.json"
$writeRoles = @($myRoles | Where-Object { $_.role -in @('Admin','Member','Contributor') })
if ($writeRoles.Count -gt 0) {
    $rolesTxt   = ($writeRoles | ForEach-Object { "$($_.ws)=$($_.role)" }) -join '; '
    $rolesRepro = ($writeRoles | ForEach-Object { "pbi `"groups/$($_.guid)/users`" | ft displayName,groupUserAccessRight   # $($_.ws)" }) -join "`n"
    Add-Finding HIGH VERIFIED "Write-level roles held by your account" $rolesTxt "05-my-roles.json" `
        "RLS is bypassed by design on datasets in these workspaces; write access far beyond a read-only contractor profile" `
        "downgrade account to Viewer; re-review contractor workspace grants" $rolesRepro
}

# ================= PHASE 3 - datasources / params / dataflows / gateways =====
Write-Host "`nPHASE 3/6 : datasource & config metadata" -ForegroundColor White
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
            $dsRows.Add([pscustomobject]@{ ws=$wA; ds=$dsA; type=$s.datasourceType; srv=$srvA
                db=$cd.database; url=$cd.url; creds=$s.credentialType; sso=$s.singleSignOnType; gw=$s.gatewayId }) | Out-Null
        }
        $pars = ApiGet "groups/$($w.Id)/datasets/$($ds.Id)/parameters"
        foreach ($p in @($pars.data)) {
            if (($p.currentValue -and $p.currentValue -match $secretRx) -or $p.name -match $secretRx) {
                Add-Finding HIGH VERIFIED "Secret-looking dataset parameter" "$dsA in $wA (name/value in evidence only)" "06-datasources-sanitized.json" `
                    "possible plaintext credential in dataset config" "move secret to a secure store / gateway credential" `
                    "pbi `"groups/$($w.Id)/datasets/$($ds.Id)/parameters`" | ft name,currentValue"
            }
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
Save-Json $dsRows "06-datasources-sanitized.json"
$basic = @($dsRows | Where-Object { $_.creds -eq "Basic" })
$kerb  = @($dsRows | Where-Object { $_.sso -eq "Kerberos" })
$hosts = @($dsRows | Where-Object { $_.srv } | Select-Object -ExpandProperty srv -Unique)
if ($basic.Count) {
    Add-Finding MEDIUM INFO "Stored Basic credentials behind gateway" "$($basic.Count) datasource(s), types: $(($basic.type | Select-Object -Unique) -join ',')" "06-datasources-sanitized.json" `
        "creds recoverable if gateway host is compromised (documented gateway architecture)" "use SSO/Kerberos or per-source least-privilege accounts" `
        "pbi gateways | fl ; then pbi `"gateways/<id>/datasources`" | fl credentialType"
    Add-Manual MEDIUM "Gateway-host check: stored datasource credentials become recoverable with gateway-host admin access" "platform"
}
if ($kerb.Count)  { Add-Finding LOW INFO "Kerberos SSO datasources" "$($kerb.Count) - delegation surface on gateway service account" "06-datasources-sanitized.json" "domain delegation abuse path if service account over-privileged" "review SPNs/constrained delegation" "pbi `"gateways/<id>/datasources`" | fl singleSignOnType" }
if ($hosts.Count) { Add-Finding MEDIUM INFO "Internal hostnames disclosed via API" "$($hosts.Count) unique internal servers visible (pseudonymized)" "06-datasources-sanitized.json" "internal recon map: server+db inventory for lateral movement" "restrict datasource connection-detail visibility for Members" "pbi `"groups/<ws-guid>/datasets/<ds-guid>/datasources`" | fl connectionDetails" }

$gws = ApiGet 'gateways'
Save-Json (@($gws.data) | Select Id,Name,Type) "07-gateways.json"
foreach ($g in @($gws.data)) { $gds = ApiGet "gateways/$($g.Id)/datasources"; Save-Json (@($gds.data) | Select datasourceType,credentialType,singleSignOnType) "07-gw-datasources.json" }
if ((CountSafe $gws.data)) { Add-Finding INFO INFO "Gateways visible" "$(CountSafe $gws.data) gateway(s) usable by your account" "07-gateways.json" "" "" "pbi gateways | fl" }
Write-Host ("  datasource rows: {0} | gateways: {1}" -f $dsRows.Count,(CountSafe $gws.data))

# ================= PHASE 4 - D1 deep tests ===================================
Write-Host "`nPHASE 4/6 : D1 deep tests" -ForegroundColor White
$g = $D1Workspace; $r = $D1Report; $d = $D1Dataset
$d1WA = $wsA[$g]; if(-not $d1WA){ $d1WA = "WS-D1" }
$rpt = Get-PowerBIReport -WorkspaceId $g
$link = $rpt | Where-Object { $_.Id -eq $r }
if ($link -and $link.DatasetId) { $d = $link.DatasetId }
$d1A = Anon $link.Name "DS"

$d1Users = ApiGet "groups/$g/users"
$mineRole = ($d1Users.data | Where-Object { $_.emailAddress -ieq $me }).groupUserAccessRight
$viewers  = CountSafe ($d1Users.data | Where-Object { $_.groupUserAccessRight -eq "Viewer" })
$writers  = @($d1Users.data | Where-Object { $_.groupUserAccessRight -in @('Admin','Member','Contributor') })
Save-Json ($d1Users.data | Select displayName,emailAddress,groupUserAccessRight) "08-d1-users.json"
if ($mineRole -in @('Admin','Member','Contributor')) {
    Add-Finding HIGH VERIFIED "Your account holds $mineRole on the D1 workspace" "RLS is NOT applied to you on $d1A; Viewer population: $viewers" "08-d1-users.json" `
        "full read of the executive model regardless of any RLS; $viewers viewers are the properly-scoped population" `
        "grant Viewers; use RLS + Viewer for consumers; separate dev workspace" `
        "pbi `"groups/$g/users`" | ft displayName,groupUserAccessRight"
}
$contractors = @($writers | Where-Object { $_.emailAddress -match '(?i)contract|vendor|ext|temp|consult' })
if ($contractors.Count) {
    $fid = Add-Finding HIGH NEEDS-CONFIRM "External/contractor accounts with write roles on D1" "$($contractors.Count) account(s) (emails in evidence only)" "08-d1-users.json" `
        "write access (RLS bypass) held by non-employee identities" "move contractors to Viewer; time-box grants" `
        "pbi `"groups/$g/users`" | ? {`$_.emailAddress -match 'contract|vendor|ext|temp|consult'} | ft emailAddress,groupUserAccessRight"
    Add-Manual HIGH "Confirm with client whether contractor write-role(s) on D1 are approved" $d1WA -ForFinding $fid
}

try {
    Export-PowerBIReport -Id $r -WorkspaceId $g -OutFile (Join-Path $E "d1-report-download.pbix") -ErrorAction Stop
    $sz = [Math]::Round((Get-Item (Join-Path $E "d1-report-download.pbix")).Length/1KB)
    Add-Finding HIGH VERIFIED "Full .pbix model downloadable via API" "D1 model downloaded ($sz KB)" "d1-report-download.pbix" "entire dataset incl. cached data in one file" "disable download/export for Viewers in tenant settings" "Export-PowerBIReport -Id $r -WorkspaceId $g -OutFile test.pbix"
} catch {
    $err = (($_.ErrorDetails.Message)+" "+($_.Exception.Message)); $err | Out-File (Join-Path $E "09-export.txt")
    Add-Finding SECURE VERIFIED "API .pbix export blocked for your account" "boundary held" "09-export.txt" "good control" "" "Export-PowerBIReport -Id $r -WorkspaceId $g -OutFile test.pbix"
}

# ---- model schema ----
$eq = $true
$tq = ApiPost "groups/$g/datasets/$d/executeQueries" '{"queries":[{"query":"EVALUATE INFO.VIEW.TABLES()"}]}'
if (-not $tq.ok) { $tq.err | Out-File (Join-Path $E "10-tables.txt")
    Add-Finding SECURE VERIFIED "executeQueries blocked on D1" "boundary held" "10-tables.txt" "" "" ('$g="{0}";$d="{1}"; then POST executeQueries' -f $g,$d); $eq = $false }
$tblA = @{}; $tables = @(); $counts = @{}; $target = $null
if ($eq) {
    $j = $tq.data | ConvertFrom-Json
    $rows = $j.results[0].tables[0].rows
    $prop = RowProp $rows
    $tables = @($rows | ForEach-Object { $_.$prop })
    Save-Json $tables "10-d1-tables.json"
    foreach($t in $tables){ $tblA[$t] = Anon $t "TBL" }
    Write-Host ("  tables in model: {0}" -f $tables.Count)
    Add-Finding HIGH VERIFIED "Full model schema readable via executeQueries" "$($tables.Count) tables enumerable as role=$mineRole" "10-d1-tables.json" `
        "complete schema disclosure of the executive model (all table/column names)" `
        "restrict executeQueries tenant setting / dataset write to owners only" `
        ('$g="{0}";$d="{1}"; dax "EVALUATE INFO.VIEW.TABLES()"' -f $g,$d)

    # ---- throttle-safe counting ----
    Write-Host "  counting rows (paced ~2.5s per table - please wait)..."
    $fails = 0; $i = 0
    foreach ($t in ($tables | Select-Object -First 15)) {
        $c = ApiPost "groups/$g/datasets/$d/executeQueries" ('{"queries":[{"query":"EVALUATE COUNTROWS(' + (DaxQuote $t) + ')"}]}')
        if ($c.ok) { $fails = 0; $j2 = $c.data | ConvertFrom-Json; $counts[$t] = FirstVal $j2.results[0].tables[0].rows[0] }
        else { $fails++ }
        $i++
        Write-Host ("    {0}/{1} {2}" -f $i,[Math]::Min(15,$tables.Count),$(if($c.ok){"ok"}else{"fail $fails"}))
        if ($fails -ge 3) {
            Add-Finding MEDIUM INFO "executeQueries throttled during counting" "stopped after 3 consecutive failures at table #$i - rerun script to continue" "11-d1-counts.json" "rate limit hit; remaining tables uncounted" "" ""
            break
        }
        Start-Sleep -Milliseconds 2500
    }
    Save-Json $counts "11-d1-counts.json"
    $nonzero = @($counts.Keys | Where-Object { $counts[$_] -gt 0 })
    if ($nonzero.Count) {
        $top = ($counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { "$($tblA[$_.Key])=$($_.Value)" }) -join ' '
        Add-Finding HIGH VERIFIED "Data rows readable via executeQueries" "$($nonzero.Count)/$($tables.Count) sampled tables non-empty; largest: $top" "11-d1-counts.json" `
            "direct bulk read of model data via API, bypassing report visuals/filters" `
            "same as schema finding: restrict executeQueries + write roles" `
            ('$g="{0}";$d="{1}"; dax "EVALUATE COUNTROWS(<TableName>)"   # pick from 10-d1-tables.json' -f $g,$d)

        $sensRx = '(?i)salar|employ|payroll|human|hr|claim|policy|premium|customer|client|invoice|payment|financ|revenue|loss|account'
        $target = ($nonzero | Where-Object { $_ -match $sensRx } | Select-Object -First 1)
        if (-not $target) { $target = $nonzero | Sort-Object { $counts[$_] } -Descending | Select-Object -First 1 }
        if (-not $NoSample) {
            Start-Sleep -Milliseconds 2500
            $s = ApiPost "groups/$g/datasets/$d/executeQueries" ('{"queries":[{"query":"EVALUATE TOPN(3,' + (DaxQuote $target) + ')"}]}')
            if ($s.ok) { $js = $s.data | ConvertFrom-Json
                Save-Json $js.results[0].tables[0].rows "12-d1-sample.json"
                $first = $js.results[0].tables[0].rows | Select-Object -First 1
                Add-Finding HIGH VERIFIED "Actual data extracted from D1 dataset" "3 rows x $($first.PSObject.Properties.Count) cols from $($tblA[$target]) (rows LOCAL only)" "12-d1-sample.json" `
                    "proof of data extraction beyond report visuals" "same as above" `
                    ('$g="{0}";$d="{1}"; dax "EVALUATE TOPN(3,{2})"' -f $g,$d,(DaxQuote $target)) }
        }
    }
}

# ---- RLS impersonation (decoupled: works even if counting was throttled) ----
$other = ($d1Users.data | Where-Object { $_.emailAddress -and $_.emailAddress -ine $me } | Select-Object -First 1).emailAddress
$oA = $null
if ($other) { $oA = Anon $other "USR" }
if ($eq -and $other -and $tables.Count -gt 0) {
    if (-not $target) { $target = $tables | Select-Object -First 1 }
    if (-not $counts.ContainsKey($target) -or -not $counts[$target]) {
        Start-Sleep -Milliseconds 2500
        $c0 = ApiPost "groups/$g/datasets/$d/executeQueries" ('{"queries":[{"query":"EVALUATE COUNTROWS(' + (DaxQuote $target) + ')"}]}')
        if ($c0.ok) { $j0 = $c0.data | ConvertFrom-Json; $counts[$target] = FirstVal $j0.results[0].tables[0].rows[0] }
    }
    if ($counts[$target]) {
        Start-Sleep -Milliseconds 2500
        $body = '{"queries":[{"query":"EVALUATE COUNTROWS(' + (DaxQuote $target) + ')"}],"impersonatedUserName":"' + $other + '"}'
        $ic = ApiPost "groups/$g/datasets/$d/executeQueries" $body
        if ($ic.ok) {
            $ji = $ic.data | ConvertFrom-Json
            $icount = FirstVal $ji.results[0].tables[0].rows[0]
            Save-Json @{ table=$tblA[$target]; own=$counts[$target]; as=$oA; impersonated=$icount } "13-impersonation.json"
            if ($icount -eq $counts[$target]) {
                $fid = Add-Finding MEDIUM NEEDS-CONFIRM "Dataset appears to have NO RLS" "$($tblA[$target]): same count as self and as $oA" "13-impersonation.json" `
                    "every Viewer likely sees all rows; confirm sensitivity of the table locally" "define+test RLS roles; use Test as role" `
                    ('impersonate: Invoke-PowerBIRestMethod -Method Post -Url "groups/{0}/datasets/{1}/executeQueries" -Body (chr(39)+"{\"queries\":[{\"query\":\"EVALUATE COUNTROWS(' + (DaxQuote $target) + ')\"}],\"impersonatedUserName\":\"' + $other + '\"}"+chr(39))' -f $g,$d)
                Add-Manual MEDIUM "Compare report visuals (B1) with the count in 13-impersonation.json on $($tblA[$target])" $d1WA -ForFinding $fid
            } else {
                Add-Finding HIGH VERIFIED "Impersonation works (other users' RLS slices readable)" "own=$($counts[$target]) vs impersonated=$icount as $oA" "13-impersonation.json" `
                    "you can query the dataset AS any user -> full RLS bypass primitive" "restrict executeQueries to dataset owners" ""
            }
        } else { $ic.err | Out-File (Join-Path $E "13-impersonation.txt")
            Add-Finding SECURE VERIFIED "Impersonated query blocked" "boundary held" "13-impersonation.txt" "" "" "" }
    }
}
# ---- embed token (decoupled) ----
if ($eq -and $other) {
    Start-Sleep -Milliseconds 2000
    $gtBody = @{ accessLevel='View'; datasetId=$d; identities=@(@{ username=$other; datasets=@($d) }) } | ConvertTo-Json -Depth 6
    $gt = ApiPost "groups/$g/reports/$r/GenerateToken" $gtBody
    if ($gt.ok) { Save-Json $gt.data "14-embedtoken.json"
        Add-Finding HIGH VERIFIED "Embed token minted with another user identity" "identity=$oA on D1 report" "14-embedtoken.json" "RLS bypass via embed-token effectiveIdentity" "restrict GenerateToken permissions" "" }
    else { $gt.err | Out-File (Join-Path $E "14-embedtoken.txt")
        Add-Finding SECURE VERIFIED "Embed-token mint blocked" "boundary held" "14-embedtoken.txt" "good control" "" "" }
}
$rf = ApiGet "groups/$g/datasets/$d/refreshes?`$top=10"
Save-Json $rf.data "15-d1-refreshes.json"
if ((CountSafe ($rf.data | Where-Object { $_.status -match 'Failed' })) -gt 0) {
    Add-Finding LOW INFO "Failed refreshes on D1" "error bodies may leak paths/accounts (evidence only)" "15-d1-refreshes.json" "info-leak in error messages" "scrub refresh error visibility" "pbi 'groups/$g/datasets/$d/refreshes?`$top=10' | ft status,startTime"
}

# ================= PHASE 5 - D2/D3 app probes ================================
Write-Host "`nPHASE 5/6 : D2 / D3 app reports" -ForegroundColor White
foreach ($pair in @(@{n="D2";a=$D2App;rid=$D2Report}, @{n="D3";a=$D3App;rid=$D3Report})) {
    $ar = ApiGet "apps/$($pair.a)/reports"
    if (-not $ar.ok) { $ar.err | Out-File (Join-Path $E "17-$($pair.n).txt")
        Add-Finding INFO INFO "$($pair.n) app reports not listable" "API boundary" "17-$($pair.n).txt" "" "" "pbi `"apps/$($pair.a)/reports`""; continue }
    Save-Json (@($ar.data) | Select Id,Name,DatasetId) "17-$($pair.n)-app-reports.json"
    if (@($ar.data).Count -gt 0) { ($ar.data | Select-Object -First 1) | ConvertTo-Json -Depth 6 | Out-File (Join-Path $E "17-$($pair.n)-firstitem.json") }
    $dset = ($ar.data | Where-Object { $_.Id -eq $pair.rid }).datasetId
    if (-not $dset -and $ar.data) { $dset = ($ar.data | Select-Object -First 1).datasetId }
    Write-Host ("  {0}: reports={1} datasetResolved={2}" -f $pair.n,(CountSafe $ar.data),($dset -ne $null))
    if ($dset) {
        $p = ApiPost "datasets/$dset/executeQueries" '{"queries":[{"query":"EVALUATE INFO.VIEW.TABLES()"}]}'
        if ($p.ok) { Save-Json $p.data "18-$($pair.n)-appprobe.json"
            Add-Finding HIGH VERIFIED "$($pair.n) app dataset queryable by app consumer" "executeQueries succeeded on app dataset" "18-$($pair.n)-appprobe.json" "app audience member can query the model directly" "restrict executeQueries" "Invoke-PowerBIRestMethod -Method Post -Url `"datasets/$dset/executeQueries`" -Body '{`"queries`":[{`"query`":`"EVALUATE INFO.VIEW.TABLES()`"}]}'" }
        else { $p.err | Out-File (Join-Path $E "18-$($pair.n)-appprobe.txt")
            Add-Finding SECURE VERIFIED "$($pair.n) app dataset NOT queryable" "boundary held" "18-$($pair.n)-appprobe.txt" "good control" "" "Invoke-PowerBIRestMethod -Method Post -Url `"datasets/$dset/executeQueries`" -Body '{`"queries`":[{`"query`":`"EVALUATE INFO.VIEW.TABLES()`"}]}'" }
    } else {
        Add-Finding INFO NEEDS-CONFIRM "$($pair.n) datasetId not exposed via app API" "manual F12 needed to find dataset GUID" "17-$($pair.n)-firstitem.json" "" "" "open the app report in browser, F12 -> Network -> search 'datasets' or 'semanticModel'"
        Add-Manual MEDIUM "Find $($pair.n) dataset GUID via browser F12 (search 'semanticModel' in network calls), then re-run probe" $pair.n
    }
}

# ================= PHASE 6 - local artifacts =================================
Write-Host "`nPHASE 6/6 : local workstation artifacts" -ForegroundColor White
$pbix = Get-ChildItem "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads" -Recurse -Include *.pbix,*.pbit,*.pbip -ErrorAction SilentlyContinue
if ($pbix) { $pbix | Select FullName,Length,LastWriteTime | Out-File (Join-Path $E "19-local-pbix.txt")
    Add-Finding LOW INFO "Local .pbix/.pbit files present" "$($pbix.Count) file(s) - each contains full cached data" "19-local-pbix.txt" "data-at-rest exposure on endpoint" "store pbix in governed workspaces only" "" }
# v1.2: REAL gateway services only (no Bluetooth/ALG false positives)
$svc = Get-Service | Where-Object { $_.DisplayName -match 'On-premises data gateway|Power BI Gateway|PBIEgw' }
$svc | Out-File (Join-Path $E "20-services.txt")
if ($svc) { Add-Finding MEDIUM INFO "Power BI gateway service on YOUR machine" (($svc | ForEach-Object { $_.DisplayName + " (" + $_.Name + ")" }) -join '; ') "20-services.txt" "endpoint hosts a gateway - local admin here => stored datasource credentials at risk" "harden gateway hosts, tier them" "Get-Service | ? { `$_.DisplayName -match 'On-premises data gateway|Power BI Gateway|PBIEgw' }" }
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Power BI Desktop" -Recurse -ErrorAction SilentlyContinue | Select FullName,Length | Out-File (Join-Path $E "21-desktop-artifacts.txt")

# ================= fixed manual browser tests ================================
Add-Manual HIGH "B1 baseline: open dashboard, record which rows/regions you SEE (compare with API counts)" "D1,D2,D3"
Add-Manual HIGH "B2 /edit: open /edit URL - Viewer must land read-only; editor loads = finding" "D1,D2,D3"
Add-Manual MEDIUM "B3 visual Export data: allowed level (summary/underlying) + row counts" "D1,D2,D3"
Add-Manual MEDIUM "B4 Share dialog: record offered link types only (do NOT send)" "D1,D2,D3"
Add-Manual HIGH "B5 File->Download report (.pbix): UI allow? open in Desktop if yes" "D1,D2,D3"
Add-Manual HIGH "B6 [ROE] File->Embed->Website or portal (publish-to-web): public link = critical; screenshot then DELETE embed" "D1,D2,D3" -ROE
Add-Manual MEDIUM "B7 [ROE] forward a specific-people share link to internal test account" "D1,D2,D3" -ROE
Add-Manual MEDIUM "B8 [ROE] attempt external share to an outside email" "D1,D2,D3" -ROE
Add-Manual LOW "TC-36 Analyze in Excel on D1: pivot all tables, compare vs visuals" "D1"
Add-Manual MEDIUM "TC-37 partial-RLS: create new report on $d1A (Build perm), drag fields from EVERY table" "D1"

# ================= output =====================================================
$rank = ('CRITICAL','HIGH','MEDIUM','LOW','INFO','SECURE')
$score = ($Findings | Group-Object Sev | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '

$findingLines = foreach($f in ($Findings | Sort-Object @{Expression={ $rank.IndexOf($_.Sev) }})){
    $l1 = "[{0}][{1}] {2} {3}" -f $f.Sev,$f.Status,$f.ID,$f.Title
    if($f.Detail){ $l1 += " :: $($f.Detail)" }
    if($f.Evidence){ $l1 += " (ev:{0}" -f $f.Evidence }
    if($f.Repro){ $l1 += " repro:{0}" -f $f.Repro }
    if($f.Evidence){ $l1 += ")" }
    $l2 = ""
    if($f.Impact){ $l2 = "     impact: $($f.Impact)" }
    if($f.Fix){ if($l2){$l2 += " | "}else{$l2="     "}; $l2 += "fix: $($f.Fix)" }
    if($l2){ $l1; $l2 } else { $l1 }
}
$manualLines = foreach($m in ($Manual | Sort-Object @{Expression={ $rank.IndexOf($_.Sev) }})){
    $roe = ""; if($m.ROE){ $roe = "[ROE]" }
    $for = ""; if($m.For){ $for = " (from $($m.For))" }
    "{0} [{1}]{2} {3} @ {4}{5}" -f $m.ID,$m.Sev,$roe,$m.What,$m.Where,$for
}

$summaryTxt = @"
POWER BI AUDIT SUMMARY (sanitized - safe to share)
run=$stamp  tenant=$tenantMask  user=$meA  scope=D1+D2+D3+platform
scoreboard: $score
pseudonyms: WS=workspace DS=dataset TBL=table SRV=server USR=user DF=dataflow FILE=local file
Repro commands with REAL ids/names are in LOCAL file REPRO-STEPS.txt (never share it)

FINDINGS:
$($findingLines -join "`n")

MANUAL ACTIONS (details + real URLs in LOCAL MANUAL-STEPS.txt):
$($manualLines -join "`n")

full evidence (local only): $E
"@
$summaryTxt | Out-File (Join-Path $E "SUMMARY.txt") -Encoding utf8

[pscustomobject]@{ run=$stamp; tenant=$tenantMask; user=$meA; scope="D1+D2+D3+platform"
    scoreboard=$score; findings=$Findings; manual=$Manual } |
    ConvertTo-Json -Depth 6 | Out-File (Join-Path $E "SUMMARY.json") -Encoding utf8

# REPRO-STEPS.txt (LOCAL - real GUIDs/names)
$reproTxt = foreach($rp in $Repros){
    "=== {0} (for {1}) {2}`n{3}`n" -f $rp.ID,$rp.For,$rp.Title,$rp.Command
}
("REPRO STEPS (LOCAL FILE - real ids - do not share)`nD1 helpers first:`n" + `
 ('$g="{0}"; $d="{1}"; $r="{2}"' -f $D1Workspace,$D1Dataset,$D1Report) + `
 "`nfunction pbi(`$u){try{(Invoke-PowerBIRestMethod -Method Get -Url `$u|ConvertFrom-Json).value}catch{}}`n" + `
 "function dax(`$q){Invoke-PowerBIRestMethod -Method Post -Url `"groups/`$g/datasets/`$d/executeQueries`" -Body ('{`"queries`":[{`"query`":`"'+`$q+'`"}]}')}`n`n" + `
 ($reproTxt -join "`n")) | Out-File (Join-Path $E "REPRO-STEPS.txt") -Encoding utf8

$manualTxt = @"
MANUAL STEPS (LOCAL FILE - real URLs - do not share)
D1 : https://app.powerbi.com/groups/$D1Workspace/reports/$D1Report/d6ad6132c0ae19b64abe?experience=power-bi
D1e: https://app.powerbi.com/groups/$D1Workspace/reports/$D1Report/edit?experience=power-bi
D2 : https://app.powerbi.com/groups/me/apps/$D2App/reports/$D2Report/ReportSection9e9d6b77273fc73e3584?experience=power-bi
D3 : https://app.powerbi.com/groups/me/apps/$D3App/reports/$D3Report/c38c2b21e667d0470005?experience=power-bi
"@
($manualTxt + "`n" + ($manualLines -join "`n")) | Out-File (Join-Path $E "MANUAL-STEPS.txt") -Encoding utf8

"SHARE-SAFE: SUMMARY.txt, SUMMARY.json`nKEEP-LOCAL: everything else (mapping, evidence, transcript, REPRO-STEPS, MANUAL-STEPS, pbix)" |
    Out-File (Join-Path $E "README.txt") -Encoding utf8

Write-Host "`n================ DONE ================" -ForegroundColor Green
$Findings | Sort-Object @{Expression={ $rank.IndexOf($_.Sev) }} | Format-Table ID,Sev,Status,Title,Repro -AutoSize | Out-String -Width 200 | Write-Host -ForegroundColor White
Write-Host "SHARE-SAFE SUMMARY: $E\SUMMARY.txt (+SUMMARY.json)" -ForegroundColor Yellow
try { Stop-Transcript | Out-Null } catch {}
Invoke-Item $E
