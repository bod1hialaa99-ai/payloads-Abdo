# Power BI Pentest — Simple Runbook (module edition)

> Everything below runs in a normal PowerShell window on your work PC.
> Token redaction rule: never paste full tokens back — `eyJ…<SNIP>`.
> [ROE] = ask client approval first (the action creates an artifact/notification).

---

## STEP 1 — Install & login (once, ~2 min)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module MicrosoftPowerBIMgmt -Scope CurrentUser -Force
Connect-PowerBIServiceAccount
```

- Sign-in popup = your normal work account (AD/Entra SSO). No tokens to copy.
- If popups are blocked: `Connect-PowerBIServiceAccount -LoginType DeviceCode`
- If `Install-Module` is blocked by policy → use the **Fallback** at the bottom.
- Token expired / weird errors later → re-run `Connect-PowerBIServiceAccount`.

## STEP 2 — The one helper to remember

```powershell
function pbi($u){ try { (Invoke-PowerBIRestMethod -Url $u | ConvertFrom-Json).value } catch { $null } }
```

Now every Power BI API is just `pbi <url>`. That's the whole runbook.

## STEP 3 — The tests (run top to bottom, note results)

**T1 — Workspaces you can see**
```powershell
pbi groups | Format-Table id, name, type, state
```

**T2 — Who has what role (per workspace — over-provisioning evidence)**
```powershell
pbi "groups/<ws-id>/users" | Format-Table displayName, groupUserAccessRight
```

**T3 — ONE BLOCK: dump everything to CSV (workspaces, users, datasets, datasources, gateways)**
```powershell
$all = pbi groups
$all | Select id,name,type | Export-Csv ws.csv -NoTypeInformation
Remove-Item datasources.csv -ErrorAction SilentlyContinue
foreach ($w in $all) {
  "== $($w.name)"
  foreach ($d in (pbi "groups/$($w.id)/datasets")) {
    $s = pbi "groups/$($w.id)/datasets/$($d.id)/datasources"
    [pscustomobject]@{
      workspace=$w.name; dataset=$d.name; datasetId=$d.id
      srcType  = ($s.datasourceType -join ',')
      server   = ($s.connectionDetails.server -join ',')
      database = ($s.connectionDetails.database -join ',')
      creds    = ($s.credentialType -join ',')
      sso      = ($s.singleSignOnType -join ',')
      gateway  = ($s.gatewayId -join ',')
    } | Export-Csv datasources.csv -Append -NoTypeInformation
  }
}
Import-Csv datasources.csv | Format-Table          # <-- internal server names live here
```

**T4 — Gateways + stored credentials**
```powershell
pbi gateways | Format-List
pbi "gateways/<gw-id>/datasources" | Format-List datasourceType, connectionDetails, credentialType, singleSignOnType
```
Signal: `credentialType = Basic` → creds stored; only decryptable on the gateway host → escalation path.

**T5 — Admin probe (are you accidentally tenant-wide?)**
```powershell
Get-PowerBIWorkspace -Scope Organization -First 10 | Format-Table Name, Type
```
Non-admin should get an error. If a normal account **gets a table** → Critical finding.

**T6 — RLS test: row counts as you, then as someone else**
```powershell
$gid='<ws-guid>'; $did='<dataset-guid>'
$q = @{queries=@(@{query='EVALUATE ROW("n", COUNTROWS(''TableName''))'})} | ConvertTo-Json -Depth 5
Invoke-PowerBIRestMethod -Method Post -Url "groups/$gid/datasets/$did/executeQueries" -Body $q
# as another user (the RLS bypass test):
$q2 = @{queries=@(@{query='EVALUATE ROW("n", COUNTROWS(''TableName''))'}); impersonatedUserName='other.user@tenant.com'} | ConvertTo-Json -Depth 5
Invoke-PowerBIRestMethod -Method Post -Url "groups/$gid/datasets/$did/executeQueries" -Body $q2
```
Compare the two numbers vs what the report shows you. (403 = also record it; the error text is intel.)

**T7 — .pbix download as low-priv user (gets FULL model, not the filtered view)**
```powershell
Export-PowerBIReport -Id <report-guid> -WorkspaceId <ws-guid> -OutFile .\stolen.pbix
```
Then open `stolen.pbix` in Power BI Desktop → every table is readable. Strongest common finding.

**T8 — Everything else via the same helper** (reports, dashboards, imports, apps, dataflows)
```powershell
pbi reports      | Format-Table id, name, datasetId, webUrl
pbi dashboards   | Format-Table id, name, webUrl
pbi imports      | Format-Table id, name, created  # .pbix uploads incl. by others in My Workspace area
pbi apps         | Format-Table id, name
pbi "groups/<ws-id>/dataflows" | Format-Table id, name
```

## STEP 4 — Browser checks (no PowerShell)

1. **RLS baseline:** open a sensitive report → note visible rows → visual `⋯` → *Export data* → note row count.
2. **Edit as Viewer:** append `/edit` to a report URL → Viewer must land in read-only; editor = misconfig.
3. **Share dialog:** click *Share* → record options. "Anyone with the link" or "People in org" offered to a low-priv user = finding (don't send).
4. **[ROE] Publish-to-web:** report → File → Embed report → *Website or portal*. Public `view?r=` link = Critical-class exposure → screenshot → **delete immediately**.
5. **Partial RLS:** with Build permission → *Create new report* on the dataset → drag fields from **every** table → tables with no RLS role render fully.

## STEP 5 — Local quick sweep (optional, 2 min)

```powershell
Get-ChildItem "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop" -Recurse -Include *.pbix,*.pbit -ea SilentlyContinue | Select FullName,Length,LastWriteTime
Get-Service | ? { $_.DisplayName -match 'gateway|power\s*bi' } | ft Name,DisplayName,Status
```
(Found a .pbix anywhere = open in Desktop = full cached data. Autopsy commands: METHODOLOGY.md §5.2.)

## STEP 6 — Paste this back (fill what you ran)

```text
ENV:        Service? y/n | Report Server? y/n | Gateway? y/n/? | My license: ___
LOGIN:      module worked? y/n | admin? y/n
WORKSPACES: name | id | my role | #datasets   (one line each)
DATASOURCES: workspace | dataset | srcType | server/database | creds | sso | gateway
GATEWAYS:   name | id | datasource types | any Basic creds?
T5 admin probe: error text or row count
RLS T6:     my count = ___ | impersonated count = ___ | error = ___
T7:         download worked? y/n | could open? y/n
BROWSER:    1..5 results
```

---

## Fallback — no module allowed (2 lines + same T-numbers)

Browser: app.powerbi.com → F12 → Network → reload → any `api.powerbi.com` request → copy the `Authorization: Bearer …` value. Then:

```powershell
$h = @{ Authorization = "Bearer <paste>" }; $base = 'https://api.powerbi.com/v1.0/myorg'
# now replace  pbi X  with:  (irm "$base/X" -Headers $h).value    — everything else identical
```

Token dies after ~1h → re-grab from DevTools when you get 401s.
