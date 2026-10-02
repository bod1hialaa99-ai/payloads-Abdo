<#
  PowerBI-Audit.ps1 — Automated Power BI pentest / configuration audit (v1.0)
  ---------------------------------------------------------------------------
  SCOPE   : 3 dashboards (D1/D2/D3, GUIDs below) + the Power BI platform
            as reachable by YOUR logged-in account. Deep data queries run
            ONLY against D1's dataset. Everything else is read-only metadata.
  OUTPUT  : .\pbi-evidence-<timestamp>\  -> raw JSON evidence + SUMMARY.txt
            SUMMARY.txt is small and safe to paste back to your assistant.
  MANUAL  : Browser-only tests (share dialog, publish-to-web, /edit, export
            buttons) cannot be automated. They are LISTED in SUMMARY.txt.
  USAGE   : powershell -ExecutionPolicy Bypass -File .\PowerBI-Audit.ps1
            (add -NoSample to skip pulling any data rows)
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
$stamp   = Get-Date -Format "yyyyMMdd-HHmm"
$E       = Join-Path (Get-Location) "pbi-evidence-$stamp"
New-Item -ItemType Directory -Force -Path $E | Out-Null
try { Start-Transcript -Path (Join-Path $E "console-transcript.txt") | Out-Null } catch {}

# ---------- tiny framework ---------------------------------------------------
$Findings = New-Object System.Collections.Generic.List[object]
$script:Seq = 0
function Add-Finding([string]$Sev,[string]$Status,[string]$Title,[string]$Detail,[string]$Evidence){
    $script:Seq++
    $Findings.Add([pscustomobject]@{
        ID="F-{0:d2}" -f $script:Seq; Sev=$Sev; Status=$Status; Title=$Title; Detail=$Detail; Evidence=$Evidence }) | Out-Null
    $color = @{CRITICAL="Red";HIGH="Magenta";MEDIUM="Yellow";LOW="Cyan";INFO="Gray";SECURE="Green"}[$Sev]
    Write-Host ("  [{0}] [{1}] {2} :: {3}" -f $Sev,$Status,$Title,$Detail) -ForegroundColor $color
}
function ApiGet([string]$Url){
    try { return @{ ok=$true;  data=(Invoke-PowerBIRestMethod -Method Get -Url $Url | ConvertFrom-Json).value; err="" } }
    catch { return @{ ok=$false; data=$null; err=(($_.ErrorDetails.Message)+($_.Exception.Message)) } }
}
function ApiPost([string]$Url,[string]$Body){
    try { return @{ ok=$true;  data=(Invoke-PowerBIRestMethod -Method Post -Url $Url -Body $Body); err="" } }
    catch { return @{ ok=$false; data=$null; err=(($_.ErrorDetails.Message)+($_.Exception.Message)) } }
}
function Save-Json($Obj,[string]$Name){ $Obj | ConvertTo-Json -Depth 10 | Out-File (Join-Path $E $Name) -Encoding utf8 }
function Mask-Email([string]$e){ if($e -match '^(.{2}).*?@(.+)$'){"$($Matches[1])***@$($Matches[2])"}else{$e} }
function DaxQuote([string]$t){ return "'" + ($t -replace "'","''") + "'" }
function FirstVal($row){ if($row){ ($row.PSObject.Properties | Select-Object -First 1).Value } }
function RowProp($rows){ # find the name-ish property of INFO.VIEW rows
    foreach($c in @('[Name]','Name','[Table]','[ID]')){ if($rows -and ($rows | Where-Object { $_.$c })){ return $c } }
    return $null
}

# ---------- module + login ---------------------------------------------------
Write-Host "=== PowerBI-Audit $stamp ===" -ForegroundColor White
if (-not (Get-Module -ListAvailable MicrosoftPowerBIMgmt)) {
    Write-Host "Module missing - installing for current user..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module MicrosoftPowerBIMgmt -Scope CurrentUser -Force
}
Import-Module MicrosoftPowerBIMgmt
try { $null = Get-PowerBIAccessToken } catch { Connect-PowerBIServiceAccount }
try { $null = Get-PowerBIAccessToken } catch { Write-Host "LOGIN FAILED - aborting." -ForegroundColor Red; exit 1 }

# ================= PHASE 1 — identity (TC-01) ================================
Write-Host "`nPHASE 1/6 : identity" -ForegroundColor White
$tok = (Get-PowerBIAccessToken)['Authorization'] -replace '^Bearer ',''
function Decode-JWT([string]$t){
    $p=$t.Split('.')[1].Replace('-','+').Replace('_','/')
    switch($p.Length%4){ 2{$p+='=='} 3{$p+='='} }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))|ConvertFrom-Json
}
$claims = Decode-JWT $tok
$me     = $claims.upn
$isAdmin= $false
if ($claims.wids -contains "62e90394-69f5-4237-9190-012177145e10") { $isAdmin = $true
    Add-Finding CRITICAL VERIFIED "Global Administrator in token" "Your token carries the Global Admin role template" "claims.json" }
if ($claims.roles) {
    Add-Finding HIGH NEEDS-CONFIRM "Application roles in token" "roles: $($claims.roles -join ',')" "claims.json" }
Save-Json ([pscustomobject]@{ aud=$claims.aud; upn=(Mask-Email $me); tid=$claims.tid; appid=$claims.appid;
    roles=$claims.roles; wids=$claims.wids; groupCount=@($claims.groups).Count }) "01-claims-redacted.json"

# ================= PHASE 2 — platform enumeration (TC-02..06) ================
Write-Host "`nPHASE 2/6 : platform enumeration" -ForegroundColor White
$ws = Get-PowerBIWorkspace
$ws | Select Id,Name,Type,State | Out-File (Join-Path $E "02-workspaces.txt")
Write-Host ("  workspaces visible: {0}" -f @($ws).Count)

# TC-03 admin boundary
$adm = ApiGet 'admin/groups?$top=100'
if ($adm.ok -and @($adm.data).Count -gt 0) {
    if ($isAdmin) { Add-Finding INFO VERIFIED "Admin API works (you ARE admin)" "expected for admin account" "03-adminprobe.json"; Save-Json $adm.data "03-adminprobe.json" }
    else { Save-Json $adm.data "03-adminprobe.json"
           Add-Finding CRITICAL VERIFIED "NON-ADMIN read tenant-wide workspaces" "$(@($adm.data).Count) workspaces returned via admin API" "03-adminprobe.json" }
} else {
    Add-Finding SECURE VERIFIED "Admin API correctly blocked" ($adm.err.Substring(0,[Math]::Min(120,$adm.err.Length))) "03-adminprobe.txt"
    $adm.err | Out-File (Join-Path $E "03-adminprobe.txt")
}

# cross-workspace reachable items
$rep = ApiGet 'reports';   $dash = ApiGet 'dashboards'; $apps = ApiGet 'apps'
$imp = $null; try { $imp = Get-PowerBIImport } catch {}
Save-Json $rep.data "04-reports.json"; Save-Json $dash.data "04-dashboards.json"
Save-Json $apps.data "04-apps.json";   Save-Json $imp    "04-imports.json"
Write-Host ("  reports:{0} dashboards:{1} apps:{2} imports:{3}" -f @($rep.data).Count,@($dash.data).Count,@($apps.data).Count,@($imp).Count)

# per-workspace users + my role (TC-05)
$myRoles = @()
foreach ($w in $ws) {
    $u = ApiGet "groups/$($w.Id)/users"
    if ($u.ok) {
        Save-Json $u.data ("05-users-{0}.json" -f $w.Name -replace '[\\/:*?"<>|]','_')
        $mine = $u.data | Where-Object { $_.emailAddress -ieq $me -or $_.identifier -ieq $me }
        if ($mine) { $myRoles += [pscustomobject]@{ ws=$w.Name; role=$mine.groupUserAccessRight } }
    }
}
$myRoles | Out-File (Join-Path $E "05-my-roles.txt") -Encoding utf8
$writeRoles = $myRoles | Where-Object { $_.role -in @('Admin','Member','Contributor') }
if (@($writeRoles).Count -gt 0) {
    Add-Finding HIGH NEEDS-CONFIRM "Write-level workspace roles held" ("roles: " + (($writeRoles | ForEach-Object { "$($_.ws)=$($_.role)" }) -join '; ')) "05-my-roles.txt"
}

# ================= PHASE 3 — datasource & config metadata (TC-07,08,10) ======
Write-Host "`nPHASE 3/6 : datasources / parameters / gateways" -ForegroundColor White
$secretRx  = '(?i)passw|secret|token|apikey|api_key|key=|bearer|pwd=|sas='
$dsRows = New-Object System.Collections.Generic.List[object]
foreach ($w in $ws) {
    $dss = ApiGet "groups/$($w.Id)/datasets"
    if (-not $dss.ok) { continue }
    foreach ($ds in @($dss.data)) {
        $src = ApiGet "groups/$($w.Id)/datasets/$($ds.Id)/datasources"
        foreach ($s in @($src.data)) {
            $cd = $s.connectionDetails
            $dsRows.Add([pscustomobject]@{ ws=$w.Name; dataset=$ds.Name; type=$s.datasourceType
                server=$cd.server; database=$cd.database; url=$cd.url
                creds=$s.credentialType; sso=$s.singleSignOnType; gw=$s.gatewayId }) | Out-Null
        }
        $pars = ApiGet "groups/$($w.Id)/datasets/$($ds.Id)/parameters"
        foreach ($p in @($pars.data)) {
            if ($p.currentValue -and ($p.currentValue -match $secretRx -or $p.name -match $secretRx)) {
                Add-Finding HIGH VERIFIED "Secret-looking dataset parameter" "[$($w.Name)/$($ds.Name)] $($p.name)" "06-parameters.json"
            }
        }
    }
}
Save-Json $dsRows "06-datasources.json"
$basic = $dsRows | Where-Object { $_.creds -eq "Basic" }
$kerb  = $dsRows | Where-Object { $_.sso -eq "Kerberos" }
$hosts = $dsRows | Where-Object { $_.server } | Select-Object -ExpandProperty server -Unique
if (@($basic).Count) { Add-Finding MEDIUM INFO "Stored Basic credentials behind gateway" "$(@($basic).Count) datasources - recoverable only on the gateway host" "06-datasources.json" }
if (@($kerb).Count)  { Add-Finding LOW INFO "Kerberos SSO datasources" "$(@($kerb).Count) - delegation surface on gateway service account" "06-datasources.json" }
if (@($hosts).Count) { Add-Finding LOW INFO "Internal hostnames disclosed" "$(@($hosts).Count) unique servers visible via datasource API" "06-datasources.json" }

$gws = ApiGet 'gateways'
Save-Json $gws.data "07-gateways.json"
foreach ($g in @($gws.data)) { $gds = ApiGet "gateways/$($g.Id)/datasources"; Save-Json $gds.data "07-gw-$($g.Id)-datasources.json" }
Write-Host ("  gateway(s): {0} | datasource rows: {1}" -f @($gws.data).Count,$dsRows.Count)

# ================= PHASE 4 — D1 deep tests (TC-20..23,30..35) ================
Write-Host "`nPHASE 4/6 : D1 Executive Scorecard deep tests" -ForegroundColor White
$g = $D1Workspace; $r = $D1Report; $d = $D1Dataset
$rpt = Get-PowerBIReport -WorkspaceId $g
$link = $rpt | Where-Object { $_.Id -eq $r }
if ($link -and $link.DatasetId) { if ($link.DatasetId -ne $d) {
        Write-Host "  NOTE: resolved dataset $($link.DatasetId) differs from default - using resolved." -ForegroundColor Yellow }
    $d = $link.DatasetId }
$d1Users = ApiGet "groups/$g/users"
$mineRole = ($d1Users.data | Where-Object { $_.emailAddress -ieq $me }).groupUserAccessRight
$viewers  = @($d1Users.data | Where-Object { $_.groupUserAccessRight -eq "Viewer" }).Count
$writers  = @($d1Users.data | Where-Object { $_.groupUserAccessRight -in @('Admin','Member','Contributor') })
if ($mineRole -in @('Admin','Member','Contributor')) {
    Add-Finding HIGH VERIFIED "Your account has $mineRole on the Executive Scorecard workspace" "Write-level => RLS is NOT applied to you on this dataset; viewers impacted: $viewers" "05-users-*.json"
}
if ($writers) {
    $contractors = @($writers | Where-Object { $_.emailAddress -match '(?i)contract|vendor|ext|temp' })
    if ($contractors.Count) { Add-Finding HIGH NEEDS-CONFIRM "Contractor/vendor accounts with write roles" "$($contractors.Count) such accounts on D1 workspace" "05-users-*.json" }
}

# TC-23 pbix download
try {
    Export-PowerBIReport -Id $r -WorkspaceId $g -OutFile (Join-Path $E "d1-report-download.pbix") -ErrorAction Stop
    $sz = [Math]::Round((Get-Item (Join-Path $E "d1-report-download.pbix")).Length/1KB)
    Add-Finding HIGH VERIFIED "Full .pbix model downloadable via API" "d1-report-download.pbix ($sz KB) - contains the entire model, not the filtered view" "d1-report-download.pbix"
} catch {
    Add-Finding SECURE VERIFIED "API .pbix export blocked" (($_.ErrorDetails.Message)+($_.Exception.Message)) "09-export.txt"
    (($_.ErrorDetails.Message)+($_.Exception.Message)) | Out-File (Join-Path $E "09-export.txt")
}

# TC-30..33 model + data (ONLY on D1 dataset - in scope)
$eq = $true
$tq = ApiPost "groups/$g/datasets/$d/executeQueries" '{"queries":[{"query":"EVALUATE INFO.VIEW.TABLES()"}]}'
if (-not $tq.ok) {
    Add-Finding SECURE VERIFIED "executeQueries blocked on D1" $tq.err "10-tables.txt"
    $tq.err | Out-File (Join-Path $E "10-tables.txt"); $eq = $false
}
if ($eq) {
    $j   = $tq.data | ConvertFrom-Json
    $rows = $j.results[0].tables[0].rows
    $prop = RowProp $rows
    $tables = @($rows | ForEach-Object { $_.$prop })
    Save-Json $tables "10-d1-tables.json"
    Write-Host ("  tables in model: {0}" -f $tables.Count)
    Add-Finding HIGH VERIFIED "Full model schema readable via executeQueries" "$($tables.Count) tables enumerated as $mineRole" "10-d1-tables.json"

    $counts = @{}; $i = 0
    foreach ($t in ($tables | Select-Object -First 20)) {
        $c = ApiPost "groups/$g/datasets/$d/executeQueries" ('{"queries":[{"query":"EVALUATE COUNTROWS(' + (DaxQuote $t) + ')"}]}')
        if ($c.ok) { $j2=$c.data|ConvertFrom-Json; $counts[$t] = FirstVal $j2.results[0].tables[0].rows[0] }
        $i++; if($i % 5 -eq 0){ Write-Host "    counted $i / $(@($tables|Select-Object -First 20).Count)" }
    }
    Save-Json $counts "11-d1-counts.json"
    $nonzero = @($counts.Keys | Where-Object { $counts[$_] -gt 0 })
    if ($nonzero.Count) {
        Add-Finding HIGH VERIFIED "Data rows readable via executeQueries" "$($nonzero.Count)/$($tables.Count) sampled tables non-empty (counts in evidence)" "11-d1-counts.json"

        $sensRx = '(?i)salar|employ|payroll|human|hr|claim|policy|premium|customer|client|invoice|payment|financ|revenue|loss|account'
        $target = ($nonzero | Where-Object { $_ -match $sensRx } | Select-Object -First 1)
        if (-not $target) { $target = $nonzero | Sort-Object { $counts[$_] } -Descending | Select-Object -First 1 }
        if (-not $NoSample) {
            $s = ApiPost "groups/$g/datasets/$d/executeQueries" ('{"queries":[{"query":"EVALUATE TOPN(3,' + (DaxQuote $target) + ')"}]}')
            if ($s.ok) {
                $js = $s.data | ConvertFrom-Json
                Save-Json $js.results[0].tables[0].rows "12-d1-sample.json"
                $first = $js.results[0].tables[0].rows | Select-Object -First 1
                $ncol  = $first.PSObject.Properties.Count
                Add-Finding HIGH VERIFIED "Actual data extracted from D1 dataset" "table '$target': 3 rows x $ncol columns sampled (rows kept local in evidence ONLY)" "12-d1-sample.json"
            }
        }
    }

    # TC-34 impersonation
    $other = ($d1Users.data | Where-Object { $_.emailAddress -and $_.emailAddress -ine $me } | Select-Object -First 1).emailAddress
    if ($other -and $target -and $counts[$target]) {
        $body = '{"queries":[{"query":"EVALUATE COUNTROWS(' + (DaxQuote $target) + ')"}],"impersonatedUserName":"' + $other + '"}'
        $ic = ApiPost "groups/$g/datasets/$d/executeQueries" $body
        if ($ic.ok) {
            $ji = $ic.data | ConvertFrom-Json
            $icount = FirstVal $ji.results[0].tables[0].rows[0]
            Save-Json @{ own=$counts[$target]; impersonatedAs=(Mask-Email $other); impersonated=$icount } "13-impersonation.json"
            if ($icount -eq $counts[$target]) {
                Add-Finding MEDIUM NEEDS-CONFIRM "Dataset appears to have NO RLS" "same count as self and as $(Mask-Email $other) -> confirm table sensitivity + who are Viewers ($viewers)" "13-impersonation.json"
            } else {
                Add-Finding HIGH VERIFIED "Impersonation works (RLS slices readable)" "own=$($counts[$target]) vs impersonated=$icount as $(Mask-Email $other)" "13-impersonation.json"
            }
        } else {
            Add-Finding SECURE VERIFIED "Impersonated query blocked" $ic.err "13-impersonation.txt"; $ic.err | Out-File (Join-Path $E "13-impersonation.txt")
        }
    }

    # TC-35 embed token mint
    $gtBody = @{ accessLevel='View'; datasetId=$d; identities=@(@{ username=$other; datasets=@($d) }) } | ConvertTo-Json -Depth 6
    $gt = ApiPost "groups/$g/reports/$r/GenerateToken" $gtBody
    if ($gt.ok) { Add-Finding HIGH VERIFIED "Embed token minted with another user identity" "identity=$(Mask-Email $other) on report $r" "14-embedtoken.json"; Save-Json $gt.data "14-embedtoken.json" }
    else { Add-Finding SECURE VERIFIED "Embed token mint blocked" $gt.err "14-embedtoken.txt"; $gt.err | Out-File (Join-Path $E "14-embedtoken.txt") }
}

# refresh history (TC-09) + subscriptions (TC-11) on D1
$rf = ApiGet "groups/$g/datasets/$d/refreshes?`$top=10"
Save-Json $rf.data "15-d1-refreshes.json"
$failed = @($rf.data | Where-Object { $_.status -match 'Failed|NotConfigured' })
if ($failed.Count) { Add-Finding LOW INFO "Failed refreshes on D1" "$($failed.Count) - error bodies may leak paths/accounts" "15-d1-refreshes.json" }
$sub = ApiGet "groups/$g/reports/$r/subscriptions"
Save-Json $sub.data "16-d1-subscriptions.json"

# ================= PHASE 5 — D2/D3 app reports (TC-24..26) ===================
Write-Host "`nPHASE 5/6 : D2 / D3 app reports" -ForegroundColor White
foreach ($pair in @(@{n="D2";a=$D2App}, @{n="D3";a=$D3App})) {
    $ar = ApiGet "apps/$($pair.a)/reports"
    Save-Json $ar.data ("17-{0}-app-reports.json" -f $pair.n)
    if (-not $ar.ok) { Add-Finding INFO INFO "$($pair.n) app reports not listable" $ar.err "17-$($pair.n)-app-reports.json"; continue }
    $rid  = if ($pair.n -eq 'D2') { $D2Report } else { $D3Report }
    $dset = ($ar.data | Where-Object { $_.Id -eq $rid }).datasetId
    if (-not $dset -and $ar.data) { $dset = ($ar.data | Select-Object -First 1).datasetId }
    Write-Host ("  {0}: {1} report(s), datasetId={2}" -f $pair.n,@($ar.data).Count,$dset)
    if ($dset) {
        $p = ApiPost "datasets/$dset/executeQueries" '{"queries":[{"query":"EVALUATE INFO.VIEW.TABLES()"}]}'
        if ($p.ok) { Save-Json $p.data "18-$($pair.n)-appprobe.json"
            Add-Finding HIGH VERIFIED "$($pair.n) app dataset queryable by app consumer" "executeQueries succeeded on $dset" "18-$($pair.n)-appprobe.json" }
        else { Add-Finding SECURE VERIFIED "$($pair.n) app dataset NOT queryable" ($p.err.Substring(0,[Math]::Min(100,$p.err.Length))) "18-$($pair.n)-appprobe.txt"; $p.err | Out-File (Join-Path $E "18-$($pair.n)-appprobe.txt") }
    }
}

# ================= PHASE 6 — local artifacts (TC-40..42) =====================
Write-Host "`nPHASE 6/6 : local workstation artifacts" -ForegroundColor White
$pbix = Get-ChildItem "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads" -Recurse -Include *.pbix,*.pbit,*.pbip -ErrorAction SilentlyContinue
$pbix | Select FullName,Length,LastWriteTime | Out-File (Join-Path $E "19-local-pbix.txt")
if ($pbix) { Add-Finding LOW INFO "Local .pbix/.pbit files present" "$(@($pbix).Count) files (full cached data inside each)" "19-local-pbix.txt" }
$svc = Get-Service | Where-Object { $_.DisplayName -match 'gateway|power\s*bi' }
if ($svc) { Add-Finding MEDIUM INFO "Gateway/Power BI services on YOUR machine" (($svc|ForEach-Object{$_.DisplayName}) -join '; ') "20-services.txt" }
$svc | Out-File (Join-Path $E "20-services.txt")
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Power BI Desktop" -Recurse -ErrorAction SilentlyContinue |
    Select FullName,Length | Out-File (Join-Path $E "21-desktop-artifacts.txt")

# ================= SUMMARY ====================================================
$score = $Findings | Group-Object Sev | ForEach-Object { "$($_.Name)=$($_.Count)" }
$manual = @"
MANUAL BROWSER TESTS (cannot be automated - run by hand, record results):
D1 : https://app.powerbi.com/groups/$D1Workspace/reports/$D1Report/d6ad6132c0ae19b64abe?experience=power-bi
D1e: https://app.powerbi.com/groups/$D1Workspace/reports/$D1Report/edit?experience=power-bi   (Viewer must land read-only)
D2 : https://app.powerbi.com/groups/me/apps/$D2App/reports/54c492fd-7994-496d-8255-2de536f335fa/ReportSection9e9d6b77273fc73e3584?experience=power-bi
D3 : https://app.powerbi.com/groups/me/apps/$D3App/reports/0ba00849-7e2b-4e20-a23d-41299c664e33/c38c2b21e667d0470005?experience=power-bi
B1 baseline rows seen per dashboard | B2 /edit test | B3 visual Export data (level+rowcount)
B4 Share dialog options (record only) | B5 File->Download report (.pbix)
B6 [ROE] File->Embed->Website or portal (publish-to-web) - DELETE embed after screenshot
B7 [ROE] forward a specific-people link to internal test account | B8 [ROE] external share attempt
"@

$summary = @"
POWER BI AUDIT SUMMARY  ($stamp)
tenant=$($claims.tid)  user=$(Mask-Email $me)  scope=D1+D2+D3+platform
scoreboard: $($score -join ' | ')

FINDINGS:
$($Findings | ForEach-Object { "[{0}][{1}] {2} {3} :: {4} (ev: {5})" -f $_.Sev,$_.Status,$_.ID,$_.Title,$_.Detail,$_.Evidence } | Out-String -Width 220)

$manual
full evidence in: $E
"@
$summary | Out-File (Join-Path $E "SUMMARY.txt") -Encoding utf8

Write-Host "`n================ DONE ================" -ForegroundColor Green
$Findings | Sort-Object @{Expression={ ('CRITICAL','HIGH','MEDIUM','LOW','INFO','SECURE').IndexOf($_.Sev) }} |
    Format-Table ID,Sev,Status,Title -AutoSize | Out-String -Width 200 | Write-Host -ForegroundColor White
Write-Host "SUMMARY (paste this back): $E\SUMMARY.txt" -ForegroundColor Yellow
try { Stop-Transcript | Out-Null } catch {}
Invoke-Item $E
