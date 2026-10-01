# Power BI Pentest Runbook — Complete Test Catalog (v4)

> **Scope**: 3 dashboards (D1–D3 below) + the Power BI platform itself as reachable by your account.
> **Copy-paste friendly.** Run blocks in order inside ONE PowerShell window (session lives in the window).
> Every test has an ID (TC-xx) — report results by ID.
> `[ROE]` = get client approval first (the action creates an artifact/notification/email).
> **Redact tokens as `eyJ…<SNIP>` in everything you export or share.**

---

## STEP 0 — Setup (run once per session)

```powershell
cd $env:USERPROFILE\Desktop
New-Item -ItemType Directory -Force -Path .\pbi-evidence | Out-Null
cd .\pbi-evidence
Start-Transcript -Path .\session-$(Get-Date -Format yyyyMMdd-HHmm).txt   # auto-records everything you run
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module MicrosoftPowerBIMgmt -Scope CurrentUser -Force -ErrorAction SilentlyContinue
Connect-PowerBIServiceAccount
```

Helpers (paste all three):
```powershell
function pbi($u){try{(Invoke-PowerBIRestMethod -Method Get -Url $u|ConvertFrom-Json).value}catch{}}
function dax($q){Invoke-PowerBIRestMethod -Method Post -Url "groups/$g/datasets/$d/executeQueries" -Body ('{"queries":[{"query":"'+$q+'"}]}')}
function Get-JWTPayload([string]$t){$p=$t.Split('.')[1].Replace('-','+').Replace('_','/');switch($p.Length%4){2{$p+='=='}3{$p+='='}};[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))|ConvertFrom-Json}
```
End of session: `Stop-Transcript` — the txt file is your evidence log.

---

## TARGETS (pre-filled)

| # | Dashboard | Shape | IDs |
|---|-----------|-------|-----|
| D1 | Executive Scorecard – Axiom MI – Monthly | workspace report | WS `26471425-5fcd-4f48-b7dc-284b57edab98` · RPT `efdcac53-a136-43e8-a860-a3da6954e142` · DS (verify) `abb04290-49f1-4cea-b62c-cd6a432bf063` |
| D2 | XLRe Data Warehouse (RDW) | app report | APP `b99fcdf7-1ab8-496e-9cc2-629c52d7876c` · RPT `54c492fd-7994-496d-8255-2de536f335fa` |
| D3 | Global Data Quality (DQD) | app report | APP `d923e468-c642-48cb-a4d1-e057a39aaaba` · RPT `0ba00849-7e2b-4e20-a23d-41299c664e33` |

---

# SECTION 1 — PLATFORM: Power BI itself

## 1A — Identity & session

**TC-01 token claims (who are you in this tenant?)**
```powershell
$t = (Get-PowerBIAccessToken)['Authorization'] -replace '^Bearer '
$c = Get-JWTPayload $t
$c | Select aud, upn, tid, appid | fl
"ROLES:"; $c.roles; "WIDS (tenant admin roles):"; $c.wids; "GROUPS: $($c.groups.Count)"
```
Read: `roles` populated = app roles for you. `wids` containing `62e90394-69f5-4237-9190-012177145e10` = Global Admin (Critical if you're not supposed to be).

## 1B — Enumeration

**TC-02 workspaces (individual scope — what you can see)**
```powershell
Get-PowerBIWorkspace | Sort Name | ft Id,Name,Type,State
```

**TC-03 admin boundary probe (expect an ERROR — a table = CRITICAL)**
```powershell
Get-PowerBIWorkspace -Scope Organization -First 10 | ft Name,Type
pbi 'admin/groups?$top=500' | ft id,name | measure
```
Record the exact error text for the report.

**TC-04 all reports/dashboards/imports/apps reachable across workspaces**
```powershell
pbi reports    | ft Id,Name,DatasetId,WebUrl
pbi dashboards | ft Id,Name,WebUrl
Get-PowerBIImport | ft Id,Name,Created,Updated      # .pbix uploads visible to you
pbi apps       | ft Id,Name,PublishToDate
```

**TC-05 per-workspace users & roles (over-provisioning register)** — loop every workspace from TC-02:
```powershell
foreach ($w in (Get-PowerBIWorkspace)) {
  "== $($w.Name) [$($w.Id)]"
  pbi "groups/$($w.Id)/users" | ft displayName,emailAddress,groupUserAccessRight
}
```
Find: your own row per workspace; anyone with Admin/Member/Contributor on finance/HR/exec data who shouldn't have it; contractors/vendors/guests.

**TC-06 per-workspace inventory**
```powershell
foreach ($w in (Get-PowerBIWorkspace)) {
  "== $($w.Name)"
  foreach ($ep in 'reports','dashboards','datasets','dataflows') {
    $items = pbi "groups/$($w.Id)/$ep"
    if ($items) { "  {0,-10} {1}" -f $ep,$items.Count }
  }
}
```

**TC-07 datasource disclosure per dataset (internal hosts/DBs/gateways)**
```powershell
foreach ($w in (Get-PowerBIWorkspace)) {
  foreach ($ds in (pbi "groups/$($w.Id)/datasets")) {
    $src = pbi "groups/$($w.Id)/datasets/$($ds.Id)/datasources"
    if ($src) { [pscustomobject]@{
        ws=$w.Name; dataset=$ds.Name; srcType=($src.datasourceType -join ',')
        server=($src.connectionDetails.server -join ','); db=($src.connectionDetails.database -join ',')
        url=($src.connectionDetails.url -join ','); creds=($src.credentialType -join ',')
        sso=($src.singleSignOnType -join ','); gateway=($src.gatewayId -join ',') } }
  }
}
```
Read: internal hostnames/IPs = recon intel. `creds=Basic` = stored username+password (decryptable only on the gateway host — escalation path). `sso=Kerberos` = delegation surface.

**TC-08 dataset parameters (plain-text secrets)**
```powershell
foreach ($w in (Get-PowerBIWorkspace)) {
  foreach ($ds in (pbi "groups/$($w.Id)/datasets")) {
    $p = pbi "groups/$($w.Id)/datasets/$($ds.Id)/parameters"
    if ($p) { "[$($w.Name)] $($ds.Name)"; $p | ft name,type,currentValue }
  }
}
```
Look for: API keys, tokens, passwords, internal URLs as parameter values.

**TC-09 refresh history (error messages leak paths/accounts)**
```powershell
pbi "groups/$g/datasets/$d/refreshes?`$top=10" | ft refreshType,status,startTime,endTime
```
(a) run after setting $g/$d; (b) also spot-check others' datasets. Failed refreshes often contain full file paths, SQL errors, service account names.

**TC-10 gateways**
```powershell
pbi gateways | fl Id,Name,Type
foreach ($gw in (pbi gateways)) { pbi "gateways/$($gw.Id)/datasources" | fl datasourceType,connectionDetails,credentialType,singleSignOnType }
```

**TC-11 subscriptions (who emails what to whom)**
```powershell
foreach ($r in (pbi "groups/$g/reports")) { pbi "groups/$g/reports/$($r.id)/subscriptions" | fl }
```

**TC-12 dataset/report permission probes (boundary mapping)**
```powershell
pbi "groups/$g/datasets/$d/users"    # may 403/404 — record which
pbi "groups/$g/reports/$r/users"
```

**TC-13 dataflow datasource disclosure**
```powershell
foreach ($df in (pbi "groups/$g/dataflows")) { pbi "groups/$g/dataflows/$($df.ObjectId)/datasources" | fl datasourceType,connectionDetails }
```

**TC-14 Fabric probe (if tenant has Fabric — separate token needed)**
Browse any Fabric item → F12 → Network → copy Authorization header → then:
```powershell
$h2=@{Authorization='Bearer <paste>'}
(irm "https://api.fabric.microsoft.com/v1/workspaces" -Headers $h2).value | ft Id,DisplayName
```

---

# SECTION 2 — THE 3 DASHBOARDS

## 2A — D1: Executive Scorecard (workspace report)

**TC-20 resolve & verify IDs**
```powershell
$g="26471425-5fcd-4f48-b7dc-284b57edab98"; $r="efdcac53-a136-43e8-a860-a3da6954e142"
Get-PowerBIReport -WorkspaceId $g | ft Id,Name,DatasetId
$d = (Get-PowerBIReport -WorkspaceId $g | ? Id -eq $r).DatasetId; $d
```
If `$d` ≠ `abb04290-49f1-4cea-b62c-cd6a432bf063`, use whatever it prints (correct linkage for evidence).

**TC-21 D1 roles**
```powershell
pbi "groups/$g/users" | ft displayName,emailAddress,groupUserAccessRight
```
Find your row (role = Admin/Member/Contributor ⇒ RLS never applies to you) and count Viewers (impacted population).

**TC-22 D1 datasource / parameters / refreshes**
```powershell
pbi "groups/$g/datasets/$d/datasources" | fl
pbi "groups/$g/datasets/$d/parameters"  | ft name,currentValue
pbi "groups/$g/datasets/$d/refreshes?`$top=5" | ft refreshType,status,startTime
```

**TC-23 D1 .pbix export via API (full model download test)**
```powershell
Export-PowerBIReport -Id $r -WorkspaceId $g -OutFile .\d1-report.pbix
```
Succeeded → open in Power BI Desktop: EVERY table readable (not your filtered view). Screenshot.

## 2B — D2 & D3: app-distributed reports

**TC-24 D2 resolve / TC-25 D3 resolve**
```powershell
pbi "apps/b99fcdf7-1ab8-496e-9cc2-629c52d7876c/reports" | fl id,name,datasetId
pbi "apps/d923e468-c642-48cb-a4d1-e057a39aaaba/reports" | fl id,name,datasetId
pbi "apps/b99fcdf7-1ab8-496e-9cc2-629c52d7876c" | fl *      # app metadata incl. audiences visible to you
```

**TC-26 app-dataset executeQueries probe (expect 403 — record it)**
```powershell
$d="<datasetId from TC-24>"
Invoke-PowerBIRestMethod -Method Post -Url "datasets/$d/executeQueries" -Body '{"queries":[{"query":"EVALUATE INFO.VIEW.TABLES()"}]}'
```

## 2C — Browser test card — run for D1, D2, D3 (record per dashboard)

**B1 baseline** — open the dashboard URL → note exactly which rows/regions/business units you can see.
**B2 edit test** — append `/edit` to the URL → Viewer must land read-only; editor loads = misconfig.
**B3 export test** — any visual → `⋯` → Export data → note allowed level (Summary/Underlying) + row count.
**B4 share options** — Share button → record offered link types ("Anyone with the link" = finding; DON'T send).
**B5 download test** — File → Download report (.pbix) → if it downloads, open in Desktop → full model readable.
**B6 [ROE] publish-to-web** — File → Embed report → Website or portal → public link = anonymous/no-RLS exposure → screenshot → DELETE embed immediately.
**B7 [ROE] link forwarding** — send a "specific people" link to internal test account B → does B get access?
**B8 [ROE] external share** — attempt sharing to an external email → succeeds = guest-sharing exposure.

---

# SECTION 3 — DATA MODEL & RLS (D1 first; then app datasets if TC-26 opened them)

**TC-30 table discovery**
```powershell
dax "EVALUATE INFO.VIEW.TABLES()"
# fallbacks: dax "EVALUATE INFO.TABLES()"  or read names from the report's field list (Data pane)
```

**TC-31 schema disclosure**
```powershell
dax "EVALUATE FILTER(INFO.VIEW.COLUMNS(), [Table] = 'RealTableName')"
dax "EVALUATE INFO.VIEW.MEASURES()"
```

**TC-32 row counts as yourself**
```powershell
dax "EVALUATE COUNTROWS(RealTable)"
```
Compare with what the report visuals show → API count >> visual rows = you read beyond report filters.

**TC-33 actual data sample (THE money shot — screenshot with URL/context)**
```powershell
dax "EVALUATE TOPN(5, RealTable)"
dax "EVALUATE TOPN(5, 'Table Name With Spaces')"
```

**TC-34 impersonation (RLS as another user — put a real colleague UPN)**
```powershell
Invoke-PowerBIRestMethod -Method Post -Url "groups/$g/datasets/$d/executeQueries" -Body '{"queries":[{"query":"EVALUATE COUNTROWS(RealTable)"}],"impersonatedUserName":"other.user@contractor.axaxl.com"}'
```
Own count = impersonated count → dataset has no RLS at all (finding: every Viewer sees everything).
Different → impersonation WORKS = you can read any user's data slice (finding).

**TC-35 embed-token identity mint (expected 403; success = finding)**
```powershell
$body = @{ accessLevel='View'; datasetId=$d; identities=@(@{ username='other.user@contractor.axaxl.com'; datasets=@($d) }) } | ConvertTo-Json -Depth 6
Invoke-PowerBIRestMethod -Method Post -Url "groups/$g/reports/$r/GenerateToken" -Body $body
```

**TC-36 Analyze in Excel** (browser, report `⋯` → Analyze in Excel) → pivot ALL tables → compare rows to visuals.

**TC-37 partial-RLS test** (browser, needs Build permission): dataset → Create new report → add fields from EVERY table → tables with no RLS role render in full.

---

# SECTION 4 — LOCAL & ON-PREM (Power BI itself, from your workstation)

**TC-40 PBIX hunt (your machine + any share you can read)**
```powershell
Get-ChildItem "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads" -Recurse -Include *.pbix,*.pbit,*.pbip -ea SilentlyContinue | Select FullName,Length,LastWriteTime
# add file servers you legitimately can read: \\server\share
```
Plus SharePoint/Teams UI search: `*.pbix`.

**TC-41 PBIX autopsy (any .pbix you obtained)**
```powershell
Copy-Item .\target.pbix .\t.zip -Force; Expand-Archive .\t.zip .\pbix -Force
Get-ChildItem .\pbix -Recurse | Select FullName
Copy-Item .\pbix\DataMashup .\dm.zip -Force -ea SilentlyContinue
Expand-Archive .\dm.zip .\dm -Force -ea SilentlyContinue
Get-Content .\dm\Formulas\Section1.m -ea SilentlyContinue        # M code: creds, hosts, keys
$raw = Get-Content .\pbix\Report\Layout -Encoding Unicode -Raw
[regex]::Matches($raw,'https?://[^\\"\s]+') | % {$_.Value} | Sort -Unique
[regex]::Matches($raw,'(?i)(passw|secret|token|apikey|bearer)[^,}\]]{0,60}') | % {$_.Value} | Select -Unique -First 40
Get-Content .\pbix\Connections -ea SilentlyContinue
```

**TC-42 Desktop artifacts**
```powershell
Get-Service | ? { $_.DisplayName -match 'gateway|power\s*bi' } | ft Name,DisplayName,Status
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Power BI Desktop" -Recurse -ea SilentlyContinue | Select FullName,Length | Out-File desktop-artifacts.txt
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Filter *.lnk | ? { $_.Name -match '\.pb' } | Select Name
```

**TC-43 gateway host (only if you can log on to one)**
```powershell
Get-CimInstance Win32_Service | ? { $_.PathName -match 'gateway|PBIEgw|PowerBI' } | Select Name,StartName,State,PathName | fl
Get-ChildItem 'C:\Program Files\On-premises data gateway' -ea SilentlyContinue | Select Name,Length,LastWriteTime
net user <svc-account> /domain ; setspn -L <svc-account>
```
Copy out (read-only): `GatewayInfo.json`, `GatewayConfig.json`, `Microsoft.PowerBI.DataMovement.Pipeline.GatewayCore.dll`.
Gateway host admin = treat as ALL stored datasource credentials (documented architecture).

**TC-44 Report Server probe (only if one exists in the environment)**
```text
https://<host>/reports                       unauth check (expect 401)
https://<host>/reports/api/v2.0/Me
https://<host>/reports/api/v2.0/PowerBIReports
https://<host>/reportserver?/<Path>/Report&rs:Command=Render&rs:Format=CSV
https://<host>/reportserver?/<Path>/Source&rs:Command=GetDataSourceDefinition
```

---

# SECTION 5 — RESULTS SHEET (fill per TC, paste back)

```text
TC-01 claims: aud/upn/roles/wids/groups = ___
TC-02 workspaces: name|id (one per line)          TC-03 admin probe: error/table?
TC-04 counts: reports __ dashboards __ apps __ imports __
TC-05 my role per workspace: ___   |  suspicious roles seen: ___
TC-07 datasources: ws|dataset|type|server|creds|sso|gateway
TC-08 parameters with secrets: ___               TC-10 gateways: ___
TC-20/24/25 resolved IDs: ___
D1: TC-21 my role=__ viewers=__ | TC-22 server=__ | TC-23 pbix y/n
D2: TC-24 dataset=__ | B1..B8: ___ | TC-26 error=__
D3: TC-25 dataset=__ | B1..B8: ___ | TC-26 error=__
D1: TC-30 tables=___ | TC-32 count=___ | TC-34 impersonated=___ | TC-35 =__
Browser card: per dashboard B1-B8 results
Errors seen verbatim: ___
```

# SECTION 6 — SEVERITY ANCHORS (for the findings register)

| Pattern | Anchor |
|---|---|
| Non-admin gets a table on TC-03 | Critical |
| Publish-to-web link obtainable (B6) | Critical |
| Gateway host admin / stored-cred recovery path (TC-43 + TC-10 Basic) | Critical |
| Impersonation returns other user's data (TC-34/35) | High–Critical |
| Contractor/low-priv holds Admin/Member/Contributor on exec/finance data (TC-21) | High |
| Viewer downloads .pbix of filtered report (B5/TC-23) | High |
| Dataset has no RLS but holds sensitive data (TC-32/34 equal counts + sensitive) | High |
| Plain-text secrets in parameters (TC-08) or M code (TC-41) | Medium–High |
| Internal hostnames via datasource API (TC-07) | Medium (recon value) |
| "Anyone with the link" sharing offered (B4) | Medium |
| Export controls missing (B3/B5) | Low–Medium |

> Remember: a permission ERROR is a result too — the 200/403 map IS the authorization boundary of your account. Record everything; Stop-Transcript at the end.
