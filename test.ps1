# Save as DomainMapper.ps1
# Authorized AD Enumeration Tool - For Security Assessment Only

param(
    [string]$Target,
    [string]$SaveTo = "domain_map.json",
    [switch]$Quick,
    [switch]$Stealth,
    [int]$Delay = 100
)

# ==================== OBFUSCATED STRINGS ====================
$s1 = [char]76 + [char]68 + [char]65 + [char]80  # LDAP
$s2 = [char]82 + [char]111 + [char]111 + [char]116 + [char]68 + [char]83 + [char]69  # RootDSE
$s3 = [char]111 + [char]98 + [char]106 + [char]101 + [char]99 + [char]116 + [char]67 + [char]108 + [char]97 + [char]115 + [char]115  # objectClass
$s4 = [char]100 + [char]105 + [char]115 + [char]116 + [char]105 + [char]110 + [char]103 + [char]117 + [char]105 + [char]115 + [char]104 + [char]101 + [char]100 + [char]78 + [char]97 + [char]109 + [char]101  # distinguishedName
$s5 = [char]110 + [char]97 + [char]109 + [char]101  # name
$s6 = [char]115 + [char]97 + [char]109 + [char]65 + [char]99 + [char]99 + [char]111 + [char]117 + [char]110 + [char]116 + [char]78 + [char]97 + [char]109 + [char]101  # samAccountName
$s7 = [char]111 + [char]98 + [char]106 + [char]101 + [char]99 + [char]116 + [char]83 + [char]105 + [char]100  # objectSid
$s8 = [char]109 + [char]101 + [char]109 + [char]98 + [char]101 + [char]114 + [char]79 + [char]102  # memberOf
$s9 = [char]109 + [char]101 + [char]109 + [char]98 + [char]101 + [char]114  # member
$s10 = [char]117 + [char]115 + [char]101 + [char]114 + [char]65 + [char]99 + [char]99 + [char]111 + [char]117 + [char]110 + [char]116 + [char]67 + [char]111 + [char]110 + [char]116 + [char]114 + [char]111 + [char]108  # userAccountControl

# ==================== EVASION TECHNIQUES ====================
function Invoke-SleepIfNeeded {
    if ($Stealth) {
        $sleepTime = Get-Random -Minimum 50 -Maximum 500
        Start-Sleep -Milliseconds $sleepTime
    }
}

function Get-ObfuscatedPath {
    param([string]$server)
    
    if ($server) {
        return "$([char]76)$([char]68)$([char]65)$([char]80)://$server/$([char]82)$([char]111)$([char]111)$([char]116)$([char]68)$([char]83)$([char]69)"
    }
    return "$([char]76)$([char]68)$([char]65)$([char]80)://$([char]82)$([char]111)$([char]111)$([char]116)$([char]68)$([char]83)$([char]69)"
}

function Invoke-LDAPQuery {
    param(
        [string]$Filter,
        [string]$BaseDN,
        [string[]]$Properties,
        [int]$Limit = 1000
    )
    
    try {
        $path = "LDAP://"
        if ($Target) { $path += "$Target/" }
        if ($BaseDN) { $path += $BaseDN } else { $path += $domainInfo.DistinguishedName }
        
        $de = New-Object System.DirectoryServices.DirectoryEntry($path)
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
        $ds.Filter = $Filter
        $ds.PageSize = 1000
        $ds.SizeLimit = $Limit
        
        foreach ($prop in $Properties) {
            $ds.PropertiesToLoad.Add($prop) | Out-Null
        }
        
        Invoke-SleepIfNeeded
        return $ds.FindAll()
    }
    catch {
        return $null
    }
}

# ==================== DOMAIN DISCOVERY ====================
function Get-DomainInfoStealth {
    Write-Output "[*] Discovering domain..."
    
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry(Get-ObfuscatedPath -server $Target)
        
        $info = @{
            DomainName = ($root.defaultNamingContext -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
            DistinguishedName = $root.defaultNamingContext
            ForestName = ($root.rootDomainNamingContext -replace 'DC=','' -replace ',','.' -replace 'DC=','')
            DomainSID = ""
            DomainControllers = @()
        }
        
        # Get domain SID
        $domainQuery = Invoke-LDAPQuery -Filter "(objectClass=domain)" -Properties @("objectSid", "name")
        if ($domainQuery -and $domainQuery.Count -gt 0) {
            $domainResult = $domainQuery[0]
            $sidBytes = $domainResult.Properties["objectSid"][0]
            $info.DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
        }
        
        # Get DCs
        $dcQuery = Invoke-LDAPQuery -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("name", "dNSHostName")
        foreach ($dc in $dcQuery) {
            $info.DomainControllers += @{
                Name = $dc.Properties["name"][0]
                DNSHostName = if ($dc.Properties["dNSHostName"]) { $dc.Properties["dNSHostName"][0] } else { $dc.Properties["name"][0] }
            }
        }
        
        return $info
    }
    catch {
        Write-Output "[-] Domain discovery failed: $_"
        return $null
    }
}

# ==================== FOCUSED ENUMERATION ====================
function Get-AdminGroups {
    $adminGroups = @()
    $criticalGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    
    foreach ($groupName in $criticalGroups) {
        $query = Invoke-LDAPQuery -Filter "(&(objectClass=group)(name=$groupName))" -Properties @("objectSid", "name", "distinguishedName", "member", "description")
        
        if ($query -and $query.Count -gt 0) {
            $group = $query[0]
            $sid = (New-Object System.Security.Principal.SecurityIdentifier($group.Properties["objectSid"][0], 0)).Value
            
            $adminGroups += @{
                Name = $groupName
                SID = $sid
                DistinguishedName = $group.Properties["distinguishedName"][0]
                MemberCount = if ($group.Properties["member"]) { $group.Properties["member"].Count } else { 0 }
                Members = if ($group.Properties["member"]) { $group.Properties["member"] } else { @() }
                IsCritical = $true
            }
        }
    }
    
    return $adminGroups
}

function Get-AdminUsers {
    param([array]$AdminGroups)
    
    $adminUsers = @()
    $userMap = @{}
    
    foreach ($group in $AdminGroups) {
        if ($group.Members) {
            foreach ($memberDN in $group.Members) {
                if (-not $userMap.ContainsKey($memberDN)) {
                    $userQuery = Invoke-LDAPQuery -Filter "(distinguishedName=$memberDN)" -Properties @("samAccountName", "objectSid", "userAccountControl")
                    
                    if ($userQuery -and $userQuery.Count -gt 0) {
                        $user = $userQuery[0]
                        $sid = (New-Object System.Security.Principal.SecurityIdentifier($user.Properties["objectSid"][0], 0)).Value
                        
                        $adminUsers += @{
                            Username = $user.Properties["samAccountName"][0]
                            SID = $sid
                            DistinguishedName = $memberDN
                            IsEnabled = (($user.Properties["userAccountControl"][0] -band 2) -eq 0)
                            MemberOf = @($group.Name)
                        }
                        
                        $userMap[$memberDN] = $true
                    }
                }
            }
        }
    }
    
    return $adminUsers
}

function Get-ServiceAccounts {
    # Look for service accounts (end with $)
    $serviceAccounts = @()
    
    $query = Invoke-LDAPQuery -Filter "(&(objectClass=user)(samAccountName=*$))" -Properties @("samAccountName", "distinguishedName", "description") -Limit 100
    
    foreach ($result in $query) {
        $samName = $result.Properties["samAccountName"][0]
        # Skip computer accounts (single $) and gMSA ($$)
        if ($samName -match '^[^$]+\$$' -and $samName -notmatch '\$\$$') {
            $serviceAccounts += @{
                Username = $samName
                DistinguishedName = $result.Properties["distinguishedName"][0]
                Description = if ($result.Properties["description"]) { $result.Properties["description"][0] } else { "" }
            }
        }
    }
    
    return $serviceAccounts
}

function Get-DomainTrusts {
    $trusts = @()
    
    $query = Invoke-LDAPQuery -Filter "(objectClass=trustedDomain)" -Properties @("name", "trustDirection", "trustType")
    
    foreach ($trust in $query) {
        $trusts += @{
            Name = $trust.Properties["name"][0]
            Direction = switch ($trust.Properties["trustDirection"][0]) {
                1 { "Inbound" }
                2 { "Outbound" }
                3 { "Bidirectional" }
                default { "Unknown" }
            }
        }
    }
    
    return $trusts
}

function Get-GPOBrief {
    # Quick GPO enumeration - just count and get some names
    $gpos = @()
    
    try {
        $configContext = (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Target/RootDSE")).configurationNamingContext
        $policiesPath = "CN=Policies,CN=System,$configContext"
        
        $query = Invoke-LDAPQuery -Filter "(objectClass=groupPolicyContainer)" -BaseDN $policiesPath -Properties @("displayName") -Limit 50
        
        foreach ($gpo in $query) {
            if ($gpo.Properties["displayName"]) {
                $gpos += $gpo.Properties["displayName"][0]
            }
        }
    }
    catch {
        # Silently continue
    }
    
    return $gpos
}

# ==================== OUTPUT GENERATION ====================
function ConvertTo-BloodHoundFormat {
    param(
        $DomainInfo,
        $AdminGroups,
        $AdminUsers,
        $ServiceAccounts,
        $Trusts,
        $GPOs
    )
    
    $bhData = @{
        meta = @{
            type = "domainmap"
            version = "1.0"
            generated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        data = @{
            domain = @{
                Name = $DomainInfo.DomainName
                SID = $DomainInfo.DomainSID
                Forest = $DomainInfo.ForestName
                DomainControllers = $DomainInfo.DomainControllers.Count
            }
            administration = @{
                CriticalGroups = @($AdminGroups | Where-Object { $_.IsCritical })
                AdminUsers = $AdminUsers.Count
                ServiceAccounts = $ServiceAccounts.Count
            }
            relationships = @{
                Trusts = $Trusts.Count
                GPOs = $GPOs.Count
            }
            details = @{
                AdminGroups = $AdminGroups
                AdminUsers = $AdminUsers
                ServiceAccounts = $ServiceAccounts
                Trusts = $Trusts
                GPOs = $GPOs
                DomainControllers = $DomainInfo.DomainControllers
            }
        }
    }
    
    return $bhData
}

# ==================== MAIN EXECUTION ====================
Write-Output @"
===============================================================================
   _____                      _   _                     _                      
  / ____|                    | | | |                   | |                     
 | (___  _ __ ___   __ _ _ __| |_| |__   ___  _ __   __| |                     
  \___ \| '_ ' _ \ / _' | '__| __| '_ \ / _ \| '_ \ / _' |                     
  ____) | | | | | | (_| | |  | |_| | | | (_) | | | | (_| |                     
 |_____/|_| |_| |_|\__,_|_|   \__|_| |_|\___/|_| |_|\__,_|                     
                                                                               
                     Stealth Domain Mapper - For Authorized Use Only           
===============================================================================
"@

# Check if we have connectivity
Write-Output "[*] Testing connectivity to: $(if($Target){$Target}else{"current domain"})"

$domainInfo = Get-DomainInfoStealth
if (-not $domainInfo) {
    Write-Output "[-] Failed to connect to domain"
    Write-Output "[*] Try specifying a domain controller: .\DomainMapper.ps1 -Target DC01.domain.local"
    exit 1
}

Write-Output "[+] Connected to domain: $($domainInfo.DomainName)"
Write-Output "[+] Forest: $($domainInfo.ForestName)"
Write-Output "[+] Domain Controllers: $($domainInfo.DomainControllers.Count)"
Write-Output ""

# Start enumeration
Write-Output "[*] Starting focused enumeration..."

# 1. Get admin groups
Write-Output "[*] Enumerating administrative groups..."
$adminGroups = Get-AdminGroups
Write-Output "[+] Found $($adminGroups.Count) critical admin groups"

# 2. Get admin users from those groups
Write-Output "[*] Finding administrative users..."
$adminUsers = Get-AdminUsers -AdminGroups $adminGroups
Write-Output "[+] Found $($adminUsers.Count) administrative users"

# 3. Get service accounts
Write-Output "[*] Looking for service accounts..."
$serviceAccounts = Get-ServiceAccounts
Write-Output "[+] Found $($serviceAccounts.Count) service accounts"

# 4. Get domain trusts
Write-Output "[*] Enumerating domain trusts..."
$trusts = Get-DomainTrusts
Write-Output "[+] Found $($trusts.Count) domain trusts"

# 5. Quick GPO check
Write-Output "[*] Checking for GPOs..."
$gpos = Get-GPOBrief
Write-Output "[+] Found $($gpos.Count) GPOs"

# Generate output
Write-Output "`n[*] Generating report..."
$outputData = ConvertTo-BloodHoundFormat -DomainInfo $domainInfo -AdminGroups $adminGroups `
    -AdminUsers $adminUsers -ServiceAccounts $serviceAccounts -Trusts $trusts -GPOs $gpos

# Save to JSON
$outputData | ConvertTo-Json -Depth 10 | Out-File -FilePath $SaveTo -Encoding UTF8

# Create summary
Write-Output @"

===============================================================================
ENUMERATION COMPLETE
===============================================================================
Domain: $($domainInfo.DomainName)
Report Saved To: $SaveTo

Summary:
- Critical Admin Groups: $($adminGroups.Count)
- Administrative Users: $($adminUsers.Count)
- Service Accounts: $($serviceAccounts.Count)
- Domain Trusts: $($trusts.Count)
- Group Policy Objects: $($gpos.Count)
- Domain Controllers: $($domainInfo.DomainControllers.Count)

Top Administrative Groups:
$($adminGroups | ForEach-Object { "  • $($_.Name) - $($_.MemberCount) members" } | Out-String)

Administrative Users Found:
$($adminUsers | Select-Object -First 5 | ForEach-Object { "  • $($_.Username)" } | Out-String)
$(if ($adminUsers.Count -gt 5) { "  ... and $($adminUsers.Count - 5) more" })

===============================================================================
This report is ready for import into security analysis tools.
===============================================================================
"@

# Additional stealth: Clean up memory
[System.GC]::Collect()
