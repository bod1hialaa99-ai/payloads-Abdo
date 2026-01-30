# Save as ADTargetedMapper.ps1
param(
    [string]$DomainController,
    [string]$OutputPath = "targeted_ad_map.json",
    [switch]$Force,
    [int]$Timeout = 180
)

$ErrorActionPreference = "Continue"
$startTime = Get-Date

# ==================== BANNER ====================
Write-Host @"
===============================================================
   _____         _                    _____          _        
  / ____|       | |                  |  __ \        | |       
 | |  __  __ _  | |_ __ _  __ _ ___  | |__) | __ ___| |_ __ _ 
 | | |_ |/ _' | | __/ _' |/ _' / __| |  ___/ '__/ _ \ __/ _' |
 | |__| | (_| | | || (_| | (_| \__ \ | |   | | |  __/ || (_| |
  \_____|\__,_|  \__\__,_|\__,_|___/ |_|   |_|  \___|\__\__,_|
                                                              
           Targeted AD Mapper with DC Specification
===============================================================
"@ -ForegroundColor Cyan

# ==================== FORCEFUL CONNECTION FUNCTION ====================
function Connect-ToDomainController {
    param([string]$DCName)
    
    Write-Host "[*] Attempting to connect to specified Domain Controller: $DCName" -ForegroundColor Green
    
    $connectionResults = @{
        Success = $false
        DomainDN = $null
        DomainName = $null
        DCName = $DCName
        MethodsTried = @()
        Error = $null
    }
    
    # Try multiple connection methods in order
    $methods = @(
        @{Name="ADSI RootDSE"; Script={ [ADSI]"LDAP://$DCName/RootDSE" }},
        @{Name="LDAP with GC"; Script={ [ADSI]"LDAP://$DCName:3268/RootDSE" }},
        @{Name="LDAPS (SSL)"; Script={ [ADSI]"LDAPS://$DCName:636/RootDSE" }},
        @{Name="ADSI without port"; Script={ [ADSI]"LDAP://$DCName" }}
    )
    
    foreach ($method in $methods) {
        try {
            Write-Host "  [*] Trying $($method.Name)..." -ForegroundColor Gray
            $rootDSE = & $method.Script
            
            $domainDN = $rootDSE.defaultNamingContext
            $domainName = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
            
            $connectionResults.Success = $true
            $connectionResults.DomainDN = $domainDN
            $connectionResults.DomainName = $domainName
            $connectionResults.MethodsTried += "$($method.Name): SUCCESS"
            
            Write-Host "  [+] Connected successfully!" -ForegroundColor Green
            Write-Host "  [+] Domain: $domainName" -ForegroundColor Green
            Write-Host "  [+] Domain DN: $domainDN" -ForegroundColor Gray
            
            return $connectionResults
        }
        catch {
            $connectionResults.MethodsTried += "$($method.Name): FAILED - $_"
            Write-Host "  [-] $($method.Name) failed: $_" -ForegroundColor DarkYellow
        }
    }
    
    # If all methods fail, try to extract domain from DC name
    if (-not $connectionResults.Success) {
        Write-Host "[!] All direct connection methods failed" -ForegroundColor Red
        
        # Try to infer domain from DC name (e.g., DC01.domain.com -> DOMAIN.COM)
        if ($DCName -match '\.') {
            $parts = $DCName -split '\.'
            if ($parts.Count -ge 2) {
                $inferredDomain = ($parts[1..($parts.Count-1)] -join '.').ToUpper()
                $connectionResults.DomainName = $inferredDomain
                $connectionResults.DomainDN = "DC=" + ($inferredDomain -replace '\.', ',DC=')
                $connectionResults.MethodsTried += "Inferred from DC name: $inferredDomain"
                
                Write-Host "[*] Inferred domain from DC name: $inferredDomain" -ForegroundColor Yellow
            }
        }
    }
    
    return $connectionResults
}

# ==================== TARGETED ENUMERATION FUNCTIONS ====================
function Get-TargetedDomainInfo {
    param([string]$DCName, [string]$DomainDN)
    
    Write-Host "`n[*] Getting targeted domain information from $DCName..." -ForegroundColor Green
    
    $domainInfo = @{
        Name = "UNKNOWN"
        DistinguishedName = $DomainDN
        DCName = $DCName
        FunctionalLevel = "Unknown"
        PasswordPolicy = @{}
        DomainControllers = @()
    }
    
    try {
        # Try to get domain object directly
        $domainPath = "LDAP://$DCName/$DomainDN"
        Write-Host "  [*] Querying: $domainPath" -ForegroundColor Gray
        
        $domainEntry = [ADSI]$domainPath
        $searcher = New-Object DirectoryServices.DirectorySearcher($domainEntry)
        $searcher.Filter = "(objectClass=domain)"
        $searcher.PropertiesToLoad.AddRange(@(
            "name", "objectSid", "domainFunctionality", "msDS-MinimumPasswordLength",
            "msDS-PasswordComplexityEnabled", "msDS-LockoutThreshold"
        ))
        
        $result = $searcher.FindOne()
        
        if ($result) {
            $domainInfo.Name = if ($result.Properties["name"]) { $result.Properties["name"][0].ToUpper() } else { "UNKNOWN" }
            
            if ($result.Properties["objectSid"]) {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($result.Properties["objectSid"][0], 0)
                $domainInfo.SID = $sid.Value
            }
            
            if ($result.Properties["domainFunctionality"]) {
                $domainInfo.FunctionalLevel = switch ($result.Properties["domainFunctionality"][0]) {
                    0 { "Windows 2000" }
                    1 { "Windows Server 2003 Interim" }
                    2 { "Windows Server 2003" }
                    3 { "Windows Server 2008" }
                    4 { "Windows Server 2008 R2" }
                    5 { "Windows Server 2012" }
                    6 { "Windows Server 2012 R2" }
                    7 { "Windows Server 2016" }
                    8 { "Windows Server 2022" }
                    default { "Unknown" }
                }
            }
            
            $domainInfo.PasswordPolicy = @{
                MinLength = if ($result.Properties["msDS-MinimumPasswordLength"]) { $result.Properties["msDS-MinimumPasswordLength"][0] } else { 7 }
                Complexity = if ($result.Properties["msDS-PasswordComplexityEnabled"]) { [bool]$result.Properties["msDS-PasswordComplexityEnabled"][0] } else { $true }
                LockoutThreshold = if ($result.Properties["msDS-LockoutThreshold"]) { $result.Properties["msDS-LockoutThreshold"][0] } else { 0 }
            }
            
            Write-Host "  [+] Domain: $($domainInfo.Name)" -ForegroundColor Green
            Write-Host "  [+] Functional Level: $($domainInfo.FunctionalLevel)" -ForegroundColor Green
        }
        else {
            Write-Host "  [-] Could not find domain object" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [!] Error getting domain info: $_" -ForegroundColor Red
    }
    
    # Try to find domain controllers in this domain
    Write-Host "  [*] Looking for domain controllers..." -ForegroundColor Gray
    try {
        $dcSearcher = New-Object DirectoryServices.DirectorySearcher
        $dcSearcher.SearchRoot = [ADSI]"LDAP://$DCName/$DomainDN"
        $dcSearcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $dcSearcher.PropertiesToLoad.AddRange(@("name", "dNSHostName", "operatingSystem"))
        $dcSearcher.PageSize = 100
        
        $dcResults = $dcSearcher.FindAll()
        foreach ($dc in $dcResults) {
            $domainInfo.DomainControllers += @{
                Name = $dc.Properties["name"][0]
                DNSHostName = if ($dc.Properties["dNSHostName"]) { $dc.Properties["dNSHostName"][0] } else { $dc.Properties["name"][0] }
                OS = if ($dc.Properties["operatingSystem"]) { $dc.Properties["operatingSystem"][0] } else { "Unknown" }
            }
        }
        
        Write-Host "  [+] Found $($domainInfo.DomainControllers.Count) domain controllers" -ForegroundColor Green
    }
    catch {
        Write-Host "  [-] Could not enumerate domain controllers" -ForegroundColor Yellow
    }
    
    return $domainInfo
}

function Get-TargetedGroups {
    param([string]$DCName, [string]$DomainDN)
    
    Write-Host "`n[*] Enumerating groups from $DCName..." -ForegroundColor Green
    
    $groups = @{
        HighValue = @()
        AdminCount = @()
        AllGroups = @()
    }
    
    $highValueGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Print Operators", "Server Operators", "Domain Controllers",
        "Group Policy Creator Owners", "DNS Admins", "DnsAdmins",
        "Remote Desktop Users", "Hyper-V Administrators",
        "Certificate Service DCOM Access", "Windows Authorization Access Group"
    )
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$DCName/$DomainDN"
        $searcher.Filter = "(objectClass=group)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("name", "description", "adminCount", "member", "groupType"))
        
        Write-Host "  [*] Executing group search..." -ForegroundColor Gray
        $results = $searcher.FindAll()
        
        $totalGroups = 0
        $highValueFound = 0
        $adminCountFound = 0
        
        foreach ($result in $results) {
            $groupName = $result.Properties["name"][0]
            $adminCount = if ($result.Properties["adminCount"]) { $result.Properties["adminCount"][0] } else { 0 }
            
            $groupInfo = @{
                Name = $groupName
                Description = if ($result.Properties["description"]) { $result.Properties["description"][0] } else { "" }
                AdminCount = $adminCount
                MemberCount = if ($result.Properties["member"]) { $result.Properties["member"].Count } else { 0 }
            }
            
            $groups.AllGroups += $groupInfo
            
            if ($highValueGroups -contains $groupName) {
                $groups.HighValue += $groupInfo
                $highValueFound++
            }
            
            if ($adminCount -eq 1) {
                $groups.AdminCount += $groupInfo
                $adminCountFound++
            }
            
            $totalGroups++
            
            if ($totalGroups % 500 -eq 0) {
                Write-Host "    [+] Processed $totalGroups groups..." -ForegroundColor Gray
            }
        }
        
        Write-Host "  [+] Total groups: $totalGroups" -ForegroundColor Green
        Write-Host "  [+] High-value groups: $highValueFound" -ForegroundColor $(if($highValueFound -gt 0){"Yellow"}else{"Green"})
        Write-Host "  [+] AdminCount=1 groups: $adminCountFound" -ForegroundColor $(if($adminCountFound -gt 0){"Yellow"}else{"Green"})
        
    }
    catch {
        Write-Host "  [!] Error enumerating groups: $_" -ForegroundColor Red
    }
    
    return $groups
}

function Get-TargetedOUs {
    param([string]$DCName, [string]$DomainDN)
    
    Write-Host "`n[*] Enumerating OUs from $DCName..." -ForegroundColor Green
    
    $ous = @()
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$DCName/$DomainDN"
        $searcher.Filter = "(objectClass=organizationalUnit)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("name", "distinguishedName", "description", "gPLink"))
        
        Write-Host "  [*] Executing OU search..." -ForegroundColor Gray
        $results = $searcher.FindAll()
        
        $ouCount = 0
        $gpoLinkedCount = 0
        
        foreach ($result in $results) {
            $ouInfo = @{
                Name = $result.Properties["name"][0]
                DistinguishedName = $result.Properties["distinguishedName"][0]
                Description = if ($result.Properties["description"]) { $result.Properties["description"][0] } else { "" }
                HasGPOLink = $false
            }
            
            if ($result.Properties["gPLink"]) {
                $ouInfo.HasGPOLink = $true
                $gpoLinkedCount++
            }
            
            $ous += $ouInfo
            $ouCount++
            
            if ($ouCount % 100 -eq 0) {
                Write-Host "    [+] Processed $ouCount OUs..." -ForegroundColor Gray
            }
        }
        
        Write-Host "  [+] Total OUs: $ouCount" -ForegroundColor Green
        Write-Host "  [+] OUs with GPO links: $gpoLinkedCount" -ForegroundColor Green
        
    }
    catch {
        Write-Host "  [!] Error enumerating OUs: $_" -ForegroundColor Red
    }
    
    return $ous
}

function Get-TargetedComputers {
    param([string]$DCName, [string]$DomainDN)
    
    Write-Host "`n[*] Enumerating computers from $DCName..." -ForegroundColor Green
    
    $computers = @{
        DomainControllers = @()
        Servers = @()
        Workstations = @()
        Total = 0
    }
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$DCName/$DomainDN"
        $searcher.Filter = "(objectClass=computer)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("name", "operatingSystem", "operatingSystemVersion", "dNSHostName"))
        
        Write-Host "  [*] Executing computer search..." -ForegroundColor Gray
        $results = $searcher.FindAll()
        
        $computerCount = 0
        $dcCount = 0
        $serverCount = 0
        $workstationCount = 0
        
        foreach ($result in $results) {
            $computerName = $result.Properties["name"][0]
            $os = if ($result.Properties["operatingSystem"]) { $result.Properties["operatingSystem"][0] } else { "" }
            
            $computerInfo = @{
                Name = $computerName
                OperatingSystem = $os
                OSVersion = if ($result.Properties["operatingSystemVersion"]) { $result.Properties["operatingSystemVersion"][0] } else { "" }
                DNSHostName = if ($result.Properties["dNSHostName"]) { $result.Properties["dNSHostName"][0] } else { $computerName }
            }
            
            if ($os -like "*Server*" -or $computerName -like "*DC*" -or $computerName -like "*SRV*") {
                if ($os -like "*Server*" -or $computerName -like "*DC*") {
                    $computers.DomainControllers += $computerInfo
                    $dcCount++
                } else {
                    $computers.Servers += $computerInfo
                    $serverCount++
                }
            } else {
                $computers.Workstations += $computerInfo
                $workstationCount++
            }
            
            $computerCount++
            
            if ($computerCount % 500 -eq 0) {
                Write-Host "    [+] Processed $computerCount computers..." -ForegroundColor Gray
            }
        }
        
        $computers.Total = $computerCount
        
        Write-Host "  [+] Total computers: $computerCount" -ForegroundColor Green
        Write-Host "  [+] Domain controllers: $dcCount" -ForegroundColor $(if($dcCount -gt 0){"Yellow"}else{"White"})
        Write-Host "  [+] Servers: $serverCount" -ForegroundColor White
        Write-Host "  [+] Workstations: $workstationCount" -ForegroundColor White
        
    }
    catch {
        Write-Host "  [!] Error enumerating computers: $_" -ForegroundColor Red
    }
    
    return $computers
}

function Get-TargetedGPOs {
    param([string]$DCName, [string]$DomainDN)
    
    Write-Host "`n[*] Enumerating GPOs from $DCName..." -ForegroundColor Green
    
    $gpos = @()
    
    try {
        # GPOs are stored in the Policies container
        $policiesDN = "CN=Policies,CN=System,$DomainDN"
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$DCName/$policiesDN"
        $searcher.Filter = "(objectClass=groupPolicyContainer)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.AddRange(@("displayName", "name", "gPCFileSysPath", "versionNumber", "flags"))
        
        Write-Host "  [*] Executing GPO search..." -ForegroundColor Gray
        $results = $searcher.FindAll()
        
        $gpoCount = 0
        $enabledCount = 0
        
        foreach ($result in $results) {
            $gpoInfo = @{
                Name = if ($result.Properties["displayName"]) { $result.Properties["displayName"][0] } else { "Unnamed GPO" }
                GUID = $result.Properties["name"][0]
                SysvolPath = if ($result.Properties["gPCFileSysPath"]) { $result.Properties["gPCFileSysPath"][0] } else { "" }
                Version = if ($result.Properties["versionNumber"]) { $result.Properties["versionNumber"][0] } else { 0 }
                Status = if ($result.Properties["flags"] -and $result.Properties["flags"][0] -eq 1) { "Disabled" } else { "Enabled" }
            }
            
            if ($gpoInfo.Status -eq "Enabled") {
                $enabledCount++
            }
            
            $gpos += $gpoInfo
            $gpoCount++
        }
        
        Write-Host "  [+] Total GPOs: $gpoCount" -ForegroundColor Green
        Write-Host "  [+] Enabled GPOs: $enabledCount" -ForegroundColor Green
        
    }
    catch {
        Write-Host "  [!] Error enumerating GPOs: $_" -ForegroundColor Red
        Write-Host "  [*] Note: GPO enumeration requires access to the Policies container" -ForegroundColor Yellow
    }
    
    return $gpos
}

function Get-TargetedTrusts {
    param([string]$DCName, [string]$DomainDN)
    
    Write-Host "`n[*] Enumerating trusts from $DCName..." -ForegroundColor Green
    
    $trusts = @()
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$DCName/$DomainDN"
        $searcher.Filter = "(objectClass=trustedDomain)"
        $searcher.PropertiesToLoad.AddRange(@("name", "trustDirection", "trustType", "trustPartner"))
        
        Write-Host "  [*] Executing trust search..." -ForegroundColor Gray
        $results = $searcher.FindAll()
        
        $trustCount = 0
        
        foreach ($result in $results) {
            $trustInfo = @{
                Name = $result.Properties["name"][0]
                TrustPartner = if ($result.Properties["trustPartner"]) { $result.Properties["trustPartner"][0] } else { "" }
                Direction = switch ($result.Properties["trustDirection"][0]) {
                    1 { "Inbound" }
                    2 { "Outbound" }
                    3 { "Bidirectional" }
                    default { "Unknown" }
                }
                Type = switch ($result.Properties["trustType"][0]) {
                    1 { "Downlevel (NT4)" }
                    2 { "Uplevel (AD)" }
                    3 { "MIT" }
                    default { "Unknown" }
                }
            }
            
            $trusts += $trustInfo
            $trustCount++
        }
        
        Write-Host "  [+] Total trusts: $trustCount" -ForegroundColor Green
        
    }
    catch {
        Write-Host "  [!] Error enumerating trusts: $_" -ForegroundColor Red
    }
    
    return $trusts
}

# ==================== MAIN EXECUTION ====================
try {
    Write-Host "[*] Starting Targeted AD Mapper" -ForegroundColor Green
    Write-Host "[*] Target Domain Controller: $(if($DomainController){$DomainController}else{'Not specified, will use current domain'})" -ForegroundColor Green
    
    if (-not $DomainController) {
        Write-Host "[!] No domain controller specified. Please provide -DomainController parameter." -ForegroundColor Red
        Write-Host "    Example: .\ADTargetedMapper.ps1 -DomainController 'DC01.domain.com'" -ForegroundColor Yellow
        exit 1
    }
    
    # Step 1: Connect to the specified domain controller
    $connection = Connect-ToDomainController -DCName $DomainController
    
    if (-not $connection.Success -and -not $Force) {
        Write-Host "`n[!] Failed to connect to $DomainController" -ForegroundColor Red
        Write-Host "[!] Connection methods tried:" -ForegroundColor Yellow
        foreach ($method in $connection.MethodsTried) {
            Write-Host "    - $method" -ForegroundColor Gray
        }
        
        if ($connection.DomainName) {
            Write-Host "`n[*] Would you like to continue with inferred domain: $($connection.DomainName)?" -ForegroundColor Yellow
            Write-Host "[*] Use -Force flag to continue anyway: .\ADTargetedMapper.ps1 -DomainController '$DomainController' -Force" -ForegroundColor Yellow
        }
        exit 1
    }
    
    Write-Host "`n[+] Successfully connected to target domain" -ForegroundColor Green
    Write-Host "    Domain: $($connection.DomainName)" -ForegroundColor White
    Write-Host "    Domain DN: $($connection.DomainDN)" -ForegroundColor White
    Write-Host "    DC: $($connection.DCName)" -ForegroundColor White
    
    # Step 2: Collect targeted information
    $domainInfo = Get-TargetedDomainInfo -DCName $DomainController -DomainDN $connection.DomainDN
    $groups = Get-TargetedGroups -DCName $DomainController -DomainDN $connection.DomainDN
    $ous = Get-TargetedOUs -DCName $DomainController -DomainDN $connection.DomainDN
    $computers = Get-TargetedComputers -DCName $DomainController -DomainDN $connection.DomainDN
    $gpos = Get-TargetedGPOs -DCName $DomainController -DomainDN $connection.DomainDN
    $trusts = Get-TargetedTrusts -DCName $DomainController -DomainDN $connection.DomainDN
    
    # Step 3: Build results structure
    $results = @{
        Metadata = @{
            CollectionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Script = "ADTargetedMapper"
            Version = "1.0"
            TargetDomainController = $DomainController
            ConnectionStatus = if ($connection.Success) { "Successful" } else { "Inferred" }
            CollectionDuration = ""
        }
        Connection = $connection
        Domain = $domainInfo
        Groups = $groups
        OUs = $ous
        Computers = $computers
        GPOs = $gpos
        Trusts = $trusts
        Statistics = @{}
    }
    
    # Step 4: Calculate statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $results.Metadata.CollectionDuration = $duration.ToString("hh\:mm\:ss")
    
    $results.Statistics = @{
        TotalGroups = $groups.AllGroups.Count
        HighValueGroups = $groups.HighValue.Count
        AdminCountGroups = $groups.AdminCount.Count
        TotalOUs = $ous.Count
        TotalComputers = $computers.Total
        DomainControllers = $computers.DomainControllers.Count
        Servers = $computers.Servers.Count
        Workstations = $computers.Workstations.Count
        TotalGPOs = $gpos.Count
        EnabledGPOs = ($gpos | Where-Object { $_.Status -eq "Enabled" }).Count
        TotalTrusts = $trusts.Count
    }
    
    # Step 5: Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    
    $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Step 6: Create summary
    $summaryPath = $OutputPath -replace "\.json$", "_summary.txt"
    
    $summary = @"
TARGETED AD MAPPING - SUMMARY REPORT
===============================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Target Domain Controller: $DomainController
Domain: $($domainInfo.Name)
Collection Duration: $($results.Metadata.CollectionDuration)

CONNECTION STATUS:
  Target DC: $DomainController
  Connection: $(if($connection.Success){"Direct"}else{"Inferred"})
  Domain Found: $($domainInfo.Name)
  Domain Functional Level: $($domainInfo.FunctionalLevel)

SUMMARY STATISTICS:
  Domain Controllers in Domain: $($domainInfo.DomainControllers.Count)
  
  Groups:
    - Total Groups: $($results.Statistics.TotalGroups)
    - High-Value Groups: $($results.Statistics.HighValueGroups)
    - AdminCount=1 Groups: $($results.Statistics.AdminCountGroups)
  
  Organizational Units:
    - Total OUs: $($results.Statistics.TotalOUs)
    - OUs with GPO Links: $(($ous | Where-Object { $_.HasGPOLink }).Count)
  
  Computers:
    - Total Computers: $($results.Statistics.TotalComputers)
    - Domain Controllers: $($results.Statistics.DomainControllers)
    - Servers: $($results.Statistics.Servers)
    - Workstations: $($results.Statistics.Workstations)
  
  Group Policy Objects:
    - Total GPOs: $($results.Statistics.TotalGPOs)
    - Enabled GPOs: $($results.Statistics.EnabledGPOs)
  
  Domain Trusts:
    - Total Trusts: $($results.Statistics.TotalTrusts)

HIGH-VALUE GROUPS FOUND:
$(
    if ($groups.HighValue.Count -gt 0) {
        foreach ($group in $groups.HighValue) {
            "  - $($group.Name) ($($group.MemberCount) members)"
        }
    } else {
        "  None found or accessible"
    }
)

DOMAIN CONTROLLERS FOUND:
$(
    if ($domainInfo.DomainControllers.Count -gt 0) {
        foreach ($dc in $domainInfo.DomainControllers) {
            "  - $($dc.Name) ($($dc.OS))"
        }
    } else {
        "  None found or accessible"
    }
)

NOTES:
- This report was generated by directly querying: $DomainController
- Results are specific to the targeted domain controller
- Some data may be limited by permissions or accessibility
- Complete data saved to: $OutputPath

SECURITY RECOMMENDATIONS:
1. Review high-value group memberships
2. Check GPO configurations on critical OUs
3. Review trust relationships
4. Verify Domain Controller security configurations
"@
    
    $summary | Out-File -FilePath $summaryPath -Encoding UTF8
    
    # Step 7: Display final summary
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host " TARGETED AD MAPPING COMPLETE" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    Write-Host "Target Domain Controller: $DomainController" -ForegroundColor White
    Write-Host "Domain: $($domainInfo.Name)" -ForegroundColor White
    Write-Host "Collection Time: $($results.Metadata.CollectionDuration)" -ForegroundColor White
    
    Write-Host "`nRESULTS SUMMARY:" -ForegroundColor Yellow
    Write-Host "  High-Value Groups: $($results.Statistics.HighValueGroups)" -ForegroundColor $(if($results.Statistics.HighValueGroups -gt 0){"Red"}else{"Green"})
    Write-Host "  Domain Controllers: $($results.Statistics.DomainControllers)" -ForegroundColor $(if($results.Statistics.DomainControllers -gt 0){"Yellow"}else{"White"})
    Write-Host "  Total OUs: $($results.Statistics.TotalOUs)" -ForegroundColor White
    Write-Host "  Total Groups: $($results.Statistics.TotalGroups)" -ForegroundColor White
    Write-Host "  Total Computers: $($results.Statistics.TotalComputers)" -ForegroundColor White
    Write-Host "  GPOs: $($results.Statistics.TotalGPOs)" -ForegroundColor White
    Write-Host "  Trusts: $($results.Statistics.TotalTrusts)" -ForegroundColor White
    
    Write-Host "`nOUTPUT FILES:" -ForegroundColor Green
    Write-Host "  Complete Data: $OutputPath" -ForegroundColor White
    Write-Host "  Summary Report: $summaryPath" -ForegroundColor White
    
    if ($groups.HighValue.Count -gt 0) {
        Write-Host "`n[!] SECURITY ALERT: High-value groups found!" -ForegroundColor Red
        foreach ($group in $groups.HighValue) {
            Write-Host "    - $($group.Name): $($group.MemberCount) members" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Targeted enumeration completed successfully!" -ForegroundColor Green
    
}
catch {
    Write-Host "`n[!] FATAL ERROR: $_" -ForegroundColor Red
    Write-Host "[!] Error occurred at line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor DarkRed
    Write-Host "[!] Command: $($_.InvocationInfo.Line)" -ForegroundColor DarkRed
}
