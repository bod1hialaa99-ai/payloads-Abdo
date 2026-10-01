# Power BI Pentest — Simple Runbook (fixed, v3)

> Run everything in ONE PowerShell window (the session lives in the window).
> Commands kept short for hand-typing. Redact tokens as `eyJ…<SNIP>` when reporting.
> [ROE] = get client approval first (creates an artifact/notification).

---

## STEP 0 — always first

```powershell
cd $env:USERPROFILE\Desktop
Connect-PowerBIServiceAccount
```

(Only re-run Connect if you open a new window or start getting auth errors.)

## STEP 1 — the helper (FIXED: needs -Method Get)

```powershell
function pbi($u){try{(Invoke-PowerBIRestMethod -Method Get -Url $u|ConvertFrom-Json).value}catch{}}
```

## STEP 2 — enumeration (short lines)

```powershell
Get-PowerBIWorkspace | ft Id,Name,Type
pbi gateways | ft Id,Name,Type
pbi reports | ft Id,Name,DatasetId
pbi apps | ft Id,Name
```

Per workspace (replace `<WS>`):
```powershell
pbi "groups/<WS>/users" | ft displayName,groupUserAccessRight
Get-PowerBIDataset -WorkspaceId <WS> | ft Id,Name
Get-PowerBIReport  -WorkspaceId <WS> | ft Id,Name,DatasetId
Get-PowerBIDatasource -WorkspaceId <WS> -DatasetId <DS> | fl datasourceType,connectionDetails,credentialType,singleSignOnType
```

Admin probe (a table instead of an error = Critical finding):
```powershell
Get-PowerBIWorkspace -Scope Organization -First 10 | ft Name
```

## STEP 3 — testing a dashboard you only have a URL for

### 3a. Read the URL

| URL shape | What it is | What to do |
|---|---|---|
| `app.powerbi.com/groups/<WS>/reports/<RID>/…` | Workspace report | You have both GUIDs — use 3b directly |
| `app.powerbi.com/groups/me/apps/<APP>/reports/<RID>/…` | Report inside an **app** | `pbi "apps/<APP>/reports" \| fl id,name,datasetId` → get dataset GUID |
| `app.powerbi.com/links/<code>?p=<guid>` | Share link | Open it, watch the address bar change into one of the shapes above |
| `app.powerbi.com/view?r=eyJ…` | **Publish-to-web (anonymous, no RLS, public internet)** | That alone is a Critical-class finding — screenshot it |
| `app.powerbi.com/groups/<WS>/rdlreports/<RID>` | Paginated report | Same tests, browser + Export |
| `app.powerbi.com/groups/me/dashboards/<DID>` | Classic dashboard (tiles) | Open a tile → drill to underlying report, then 3b |

If IDs are hidden (app/share-link), open the report in the browser → F12 → Network → Ctrl+F search
`datasets` or `semanticModel` — the dataset GUID appears in the API calls.

### 3b. Test card — run for EVERY dashboard in scope

**Browser (as yourself):**
1. Baseline: open report → note exactly which rows/regions/tenants you can see.
2. Append `/edit` to the URL → you must land read-only as Viewer; editor = misconfig finding.
3. Any visual → `⋯` → **Export data** → allowed? which level? how many rows?
4. **Share** button → which link types are offered ("Anyone with the link" = finding; don't send).
5. File → **Download report (.pbix)** → if the file downloads, open it in Power BI Desktop → every table of the model is readable (not just the filtered view you see). Strongest common finding.
6. [ROE] File → Embed report → *Website or portal* → public link = publish-to-web enabled → screenshot → **delete the embed** immediately.

**PowerShell (with `<WS>`/`<RID>` from the URL, `<DS>` from Get-PowerBIReport):**
```powershell
Get-PowerBIReport -WorkspaceId <WS> | ft Id,Name,DatasetId
Get-PowerBIDatasource -WorkspaceId <WS> -DatasetId <DS> | fl
Export-PowerBIReport -Id <RID> -WorkspaceId <WS> -OutFile test.pbix
```

**RLS test (needs a real table name from the report's field list):**
```powershell
$g="<WS>";$d="<DS>";$t="TableName"
$q=@{queries=@(@{query="EVALUATE ROW(`"n`", COUNTROWS('$t'))"})}|ConvertTo-Json -Depth 5
Invoke-PowerBIRestMethod -Method Post -Url "groups/$g/datasets/$d/executeQueries" -Body $q
$q=@{queries=@(@{query="EVALUATE ROW(`"n`", COUNTROWS('$t'))"});impersonatedUserName="other.user@tenant.com"}|ConvertTo-Json -Depth 5
Invoke-PowerBIRestMethod -Method Post -Url "groups/$g/datasets/$d/executeQueries" -Body $q
```
- First count = your visibility. Second = as another user (403 with an error is also a result — note the text).
- Count >> what the report shows you = RLS is filtering you (good) — then the finding hunt is role over-provisioning: `pbi "groups/<WS>/users"` and see who holds Admin/Member/Contributor (those roles **bypass RLS by design**).

## STEP 4 — send back

```text
WORKSPACES: name | id | my role | #datasets        (from Get-PowerBIWorkspace + users call)
GATEWAYS:   any listed? y/n | datasources: type/server/credType
ADMIN PROBE: error text OR "returned a table"
PER DASHBOARD: URL shape (A–F) | /edit result | export rows | share options | pbix download y/n | RLS count mine/impersonated
ERRORS: any red error text you saw (photo/OCR is fine)
```

---

## Fallback (no module): browser token + 2 lines

F12 → Network → any `api.powerbi.com` request → copy Authorization header value:
```powershell
$h=@{Authorization="Bearer <paste>"};$base="https://api.powerbi.com/v1.0/myorg"
# replace  pbi X  with:  (irm "$base/X" -Headers $h).value
```
