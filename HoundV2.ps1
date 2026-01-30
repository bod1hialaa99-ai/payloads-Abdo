# Save as ADMapper.ps1
param(
    [string]$DomainController,
    [string]$OutputPath = "ad_complete_map.json",
    [switch]$SkipUsers,
    [switch]$SkipComputers,
    [switch]$NoACLs,
    [int]$Timeout = 180  # 3 minutes max
)

$ErrorActionPreference = "Stop"
$startTime = Get-Date
$global:timeoutReached = $false

# ==================== TIMEOUT HANDLER ====================
$timeoutTimer = New-Object System.Timers.Timer
$timeoutTimer.Interval = $Timeout * 1000
$timeoutTimer.Enabled = $true
$timeoutTimer.AutoReset = $false
Register-ObjectEvent -InputObject $timeoutTimer -EventName Elapsed -SourceIdentifier TimeoutReached -Action {
    $global:timeoutReached = $true
    Write-Host "[!] Timeout reached! Finishing current operations..." -ForegroundColor Red
}

# ==================== BANNER ====================
Write-Host @"
===============================================================
    ___    ____  __  __                            
   /   |  / __ \/ / / /___  ____  ____ _____ ___ 
  / /| | / / / / /_/ / __ \/ __ \/ __ '/ __ '__ \
 / ___ |/ /_/ / __  / /_/ / /_/ / /_/ / / / / / /
/_/  |_/_____/_/ /_/\____/ .___/\__,_/_/ /_/ /_/ 
                        /_/                        

           Complete AD Structure Mapper
           (Excluding User Details for Speed)
===============================================================
"@ -ForegroundColor Cyan

# ==================== CONFIGURATION ====================
$config = @{
    CollectOUs = $true
    CollectGroups = $true
    CollectGPOs = $true
    CollectComputers = (-not $SkipComputers)
    CollectTrusts = $true
    CollectSites = $true
    CollectSubnets = $true
    CollectSchema = $true
    CollectACLs = (-not $NoACLs)
    CollectDelegation = $true
    CollectServiceAccounts = $true
    CollectLAPS = $true
    CollectCertTemplates = $true
}

# ==================== DATA STRUCTURE ====================
$adMap = @{
    Meta = @{
        ScriptVersion = "2.0"
        CollectionTime = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        DomainController = $DomainController
        Parameters = @{
            SkipUsers = $SkipUsers
            SkipComputers = $SkipComputers
            NoACLs = $NoACLs
        }
    }
    Domain = @{}
    Forest = @{}
    OUs = @()
    Groups = @{
        Builtin = @()
        Security = @()
        Distribution = @()
        HighValue = @()
        AdminCount = @()
        NestedGroups = @()
    }
    GPOs = @()
    Computers = @{
        DomainControllers = @()
        Servers = @()
        Workstations = @()
        LAPSEnabled = @()
    }
    Sites = @()
    Subnets = @()
    Trusts = @()
    Schema = @{}
    Delegation = @()
    ServiceAccounts = @()
    CertificateTemplates = @()
    ACLs = @{
        CriticalPaths = @()
        GPODelegation = @()
    }
    Statistics = @{}
}

# ==================== CONNECTION ====================
function Test-Connection {
    Write-Host "[*] Testing connection..." -ForegroundColor Yellow
    
    try {
        if ($DomainController) {
            $ldapPath = "LDAP://$DomainController/RootDSE"
        } else {
            $ldapPath = "LDAP://RootDSE"
        }
        
        $rootDSE = [ADSI]$ldapPath
        
        $domainDN = $rootDSE.defaultNamingContext
        $configDN = $rootDSE.configurationNamingContext
        $schemaDN = $rootDSE.schemaNamingContext
        $domainName = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
        
        Write-Host "[+] Connected to domain: $domainName" -ForegroundColor Green
        Write-Host "[+] Domain DN: $domainDN" -ForegroundColor Gray
        Write-Host "[+] Configuration DN: $configDN" -ForegroundColor Gray
        
        return @{
            RootDSE = $rootDSE
            DomainDN = $domainDN
            ConfigDN = $configDN
            SchemaDN = $schemaDN
            DomainName = $domainName
            Server = $DomainController
        }
    }
    catch {
        Write-Host "[!] Connection failed: $_" -ForegroundColor Red
        Write-Host "[!] Try specifying -DomainController parameter" -ForegroundColor Yellow
        exit 1
    }
}

# ==================== DOMAIN INFO ====================
function Get-DomainInfo {
    param($Connection)
    
    Write-Host "`n[*] Getting domain information..." -ForegroundColor Green
    
    try {
        $domainSearch = [ADSISearcher]"(objectClass=domain)"
        $domainSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $domainSearch.PropertiesToLoad.AddRange(@(
            "objectSid", "name", "distinguishedName", "whenCreated", "whenChanged",
            "domainFunctionality", "msDS-Behavior-Version", "msDS-MinimumPasswordLength",
            "msDS-PasswordComplexityEnabled", "msDS-LockoutThreshold", "msDS-LockoutDuration",
            "msDS-LockoutObservationWindow", "msDS-PasswordHistoryLength"
        ))
        
        $domainResult = $domainSearch.FindOne()
        
        if ($domainResult) {
            $domainSid = [System.Security.Principal.SecurityIdentifier]::new($domainResult.Properties.objectsid[0], 0).Value
            
            $adMap.Domain = @{
                Name = $Connection.DomainName
                DistinguishedName = $domainResult.Properties.distinguishedname[0]
                NetBIOSName = $domainResult.Properties.name[0]
                SID = $domainSid
                Created = $domainResult.Properties.whenCreated[0]
                Modified = $domainResult.Properties.whenChanged[0]
                FunctionalLevel = switch ($domainResult.Properties.domainFunctionality[0]) {
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
                PasswordPolicy = @{
                    MinLength = if ($domainResult.Properties."msDS-MinimumPasswordLength") { $domainResult.Properties."msDS-MinimumPasswordLength"[0] } else { 7 }
                    Complexity = if ($domainResult.Properties."msDS-PasswordComplexityEnabled") { [bool]$domainResult.Properties."msDS-PasswordComplexityEnabled"[0] } else { $true }
                    HistoryLength = if ($domainResult.Properties."msDS-PasswordHistoryLength") { $domainResult.Properties."msDS-PasswordHistoryLength"[0] } else { 24 }
                    LockoutThreshold = if ($domainResult.Properties."msDS-LockoutThreshold") { $domainResult.Properties."msDS-LockoutThreshold"[0] } else { 0 }
                    LockoutDuration = if ($domainResult.Properties."msDS-LockoutDuration") { $domainResult.Properties."msDS-LockoutDuration"[0] } else { $null }
                    LockoutWindow = if ($domainResult.Properties."msDS-LockoutObservationWindow") { $domainResult.Properties."msDS-LockoutObservationWindow"[0] } else { $null }
                }
            }
            
            Write-Host "[+] Domain: $($adMap.Domain.Name)" -ForegroundColor Green
            Write-Host "[+] Functional Level: $($adMap.Domain.FunctionalLevel)" -ForegroundColor Green
            Write-Host "[+] Password Policy:" -ForegroundColor Gray
            Write-Host "    - Min Length: $($adMap.Domain.PasswordPolicy.MinLength)" -ForegroundColor Gray
            Write-Host "    - Complexity: $($adMap.Domain.PasswordPolicy.Complexity)" -ForegroundColor Gray
            Write-Host "    - Lockout Threshold: $($adMap.Domain.PasswordPolicy.LockoutThreshold)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[-] Error getting domain info: $_" -ForegroundColor Yellow
    }
}

# ==================== FOREST INFO ====================
function Get-ForestInfo {
    param($Connection)
    
    Write-Host "`n[*] Getting forest information..." -ForegroundColor Green
    
    try {
        $forestSearch = [ADSISearcher]"(objectClass=crossRefContainer)"
        $forestSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/CN=Partitions,$($Connection.ConfigDN)"
        $forestSearch.PropertiesToLoad.AddRange(@("cn", "dnsRoot", "msDS-NC-Replica-Locations"))
        
        $forestResults = $forestSearch.FindAll()
        
        $forestDomains = @()
        $forestSites = @()
        
        foreach ($result in $forestResults) {
            if ($result.Properties.dnsRoot) {
                $forestDomains += @{
                    Name = $result.Properties.cn[0]
                    DNSRoot = $result.Properties.dnsRoot[0]
                }
            }
        }
        
        # Get forest functional level
        $forestRootSearch = [ADSISearcher]"(objectClass=crossRef)"
        $forestRootSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/CN=Partitions,$($Connection.ConfigDN)"
        $forestRootSearch.Filter = "(netbiosname=*)"
        $forestRootSearch.PropertiesToLoad.AddRange(@("msDS-Behavior-Version", "name"))
        
        $forestRootResult = $forestRootSearch.FindOne()
        
        $adMap.Forest = @{
            Domains = $forestDomains
            DomainCount = $forestDomains.Count
            FunctionalLevel = if ($forestRootResult -and $forestRootResult.Properties."msDS-Behavior-Version") {
                switch ($forestRootResult.Properties."msDS-Behavior-Version"[0]) {
                    0 { "Windows 2000" }
                    1 { "Windows Server 2003" }
                    2 { "Windows Server 2008" }
                    3 { "Windows Server 2008 R2" }
                    4 { "Windows Server 2012" }
                    5 { "Windows Server 2012 R2" }
                    6 { "Windows Server 2016" }
                    7 { "Windows Server 2022" }
                    default { "Unknown" }
                }
            } else { "Unknown" }
        }
        
        Write-Host "[+] Forest has $($forestDomains.Count) domains" -ForegroundColor Green
        Write-Host "[+] Forest Functional Level: $($adMap.Forest.FunctionalLevel)" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error getting forest info: $_" -ForegroundColor Yellow
    }
}

# ==================== OUS ====================
function Get-OUs {
    param($Connection)
    
    if (-not $config.CollectOUs) { return }
    
    Write-Host "`n[*] Enumerating Organizational Units..." -ForegroundColor Green
    
    try {
        $ouSearch = [ADSISearcher]"(objectClass=organizationalUnit)"
        $ouSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $ouSearch.PageSize = 1000
        $ouSearch.PropertiesToLoad.AddRange(@(
            "distinguishedName", "name", "description", "gPLink",
            "whenCreated", "whenChanged", "objectGUID"
        ))
        
        $ouResults = $ouSearch.FindAll()
        $count = 0
        
        foreach ($result in $ouResults) {
            if ($global:timeoutReached) { break }
            
            $ouInfo = @{
                Name = $result.Properties.name[0]
                DistinguishedName = $result.Properties.distinguishedname[0]
                Description = if ($result.Properties.description) { $result.Properties.description[0] } else { "" }
                GUID = [System.BitConverter]::ToString($result.Properties.objectguid[0]).Replace("-", "").ToLower()
                Created = $result.Properties.whenCreated[0]
                Modified = $result.Properties.whenChanged[0]
                GPOLinks = @()
            }
            
            # Parse GPO Links
            if ($result.Properties.gPLink) {
                $gplink = $result.Properties.gPLink[0]
                $gpoLinks = $gplink -split '\]\[' | ForEach-Object {
                    if ($_ -match 'LDAP://CN=({[^}]+}),CN=Policies,CN=System') {
                        $gpoGuid = $matches[1]
                        @{
                            GUID = $gpoGuid
                            Link = $_
                        }
                    }
                }
                $ouInfo.GPOLinks = $gpoLinks
            }
            
            $adMap.OUs += $ouInfo
            $count++
            
            if ($count % 100 -eq 0) {
                Write-Host "  [+] Found $count OUs..." -ForegroundColor Gray
            }
        }
        
        Write-Host "[+] Total OUs: $count" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error enumerating OUs: $_" -ForegroundColor Yellow
    }
}

# ==================== GROUPS ====================
function Get-Groups {
    param($Connection)
    
    if (-not $config.CollectGroups) { return }
    
    Write-Host "`n[*] Enumerating groups..." -ForegroundColor Green
    
    # High-value groups to check
    $highValueGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Print Operators", "Server Operators", "Domain Controllers",
        "Group Policy Creator Owners", "DNS Admins", "DnsAdmins",
        "Remote Desktop Users", "Hyper-V Administrators",
        "Certificate Service DCOM Access", "Windows Authorization Access Group",
        "Pre-Windows 2000 Compatible Access", "Exchange Organization Administrators",
        "Exchange Server Administrators", "Exchange View-Only Administrators",
        "SQL Server Administrators", "Azure Admins", "Cloud App Admins"
    )
    
    # Built-in groups
    $builtinGroups = @(
        "Administrators", "Users", "Guests", "Backup Operators",
        "Replicator", "Power Users", "Network Configuration Operators",
        "Remote Desktop Users", "Print Operators", "Account Operators",
        "Server Operators", "Certificate Service DCOM Access",
        "Cryptographic Operators", "Distributed COM Users", "Event Log Readers",
        "IIS_IUSRS", "Performance Log Users", "Performance Monitor Users",
        "Pre-Windows 2000 Compatible Access", "RAS and IAS Servers",
        "Terminal Server License Servers", "Windows Authorization Access Group"
    )
    
    try {
        # Get all groups
        $groupSearch = [ADSISearcher]"(objectClass=group)"
        $groupSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $groupSearch.PageSize = 1000
        $groupSearch.PropertiesToLoad.AddRange(@(
            "distinguishedName", "name", "description", "objectSid",
            "groupType", "adminCount", "member", "whenCreated", "whenChanged"
        ))
        
        $groupResults = $groupSearch.FindAll()
        $totalGroups = 0
        $highValueCount = 0
        $adminCountGroups = 0
        
        foreach ($result in $groupResults) {
            if ($global:timeoutReached) { break }
            
            $groupSid = [System.Security.Principal.SecurityIdentifier]::new($result.Properties.objectsid[0], 0).Value
            $groupType = $result.Properties.groupType[0]
            
            $groupInfo = @{
                Name = $result.Properties.name[0]
                DistinguishedName = $result.Properties.distinguishedname[0]
                Description = if ($result.Properties.description) { $result.Properties.description[0] } else { "" }
                SID = $groupSid
                GroupType = switch ($groupType) {
                    { $_ -band 0x80000000 } { "Security" }
                    { $_ -band 0x80000001 } { "Global Security" }
                    { $_ -band 0x80000002 } { "Domain Local Security" }
                    { $_ -band 0x80000004 } { "Universal Security" }
                    default { "Distribution" }
                }
                Scope = switch ($groupType) {
                    { $_ -band 0x00000002 } { "Global" }
                    { $_ -band 0x00000004 } { "Universal" }
                    { $_ -band 0x00000008 } { "Domain Local" }
                    default { "Unknown" }
                }
                AdminCount = if ($result.Properties.adminCount) { [int]$result.Properties.adminCount[0] } else { 0 }
                MemberCount = if ($result.Properties.member) { $result.Properties.member.Count } else { 0 }
                Created = $result.Properties.whenCreated[0]
                Modified = $result.Properties.whenChanged[0]
            }
            
            # Categorize groups
            if ($highValueGroups -contains $groupInfo.Name) {
                $adMap.Groups.HighValue += $groupInfo
                $highValueCount++
            }
            elseif ($builtinGroups -contains $groupInfo.Name) {
                $adMap.Groups.Builtin += $groupInfo
            }
            elseif ($groupInfo.AdminCount -eq 1) {
                $adMap.Groups.AdminCount += $groupInfo
                $adminCountGroups++
            }
            elseif ($groupInfo.GroupType -eq "Security") {
                $adMap.Groups.Security += $groupInfo
            }
            else {
                $adMap.Groups.Distribution += $groupInfo
            }
            
            $totalGroups++
            
            if ($totalGroups % 500 -eq 0) {
                Write-Host "  [+] Processed $totalGroups groups..." -ForegroundColor Gray
            }
        }
        
        Write-Host "[+] Total Groups: $totalGroups" -ForegroundColor Green
        Write-Host "[+] High-Value Groups: $highValueCount" -ForegroundColor $(if($highValueCount -gt 0){"Yellow"}else{"Green"})
        Write-Host "[+] AdminCount=1 Groups: $adminCountGroups" -ForegroundColor $(if($adminCountGroups -gt 0){"Yellow"}else{"Green"})
        
        # Get nested group relationships
        if ($config.CollectACLs) {
            Get-NestedGroups -Connection $Connection
        }
    }
    catch {
        Write-Host "[-] Error enumerating groups: $_" -ForegroundColor Yellow
    }
}

# ==================== NESTED GROUPS ====================
function Get-NestedGroups {
    param($Connection)
    
    Write-Host "[*] Analyzing nested group relationships..." -ForegroundColor Green
    
    try {
        $nestedSearch = [ADSISearcher]"(member=*)"
        $nestedSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $nestedSearch.PageSize = 500
        $nestedSearch.PropertiesToLoad.AddRange(@("distinguishedName", "name", "member"))
        
        $nestedResults = $nestedSearch.FindAll()
        $nestedCount = 0
        
        foreach ($result in $nestedResults) {
            if ($global:timeoutReached) { break }
            
            $groupDN = $result.Properties.distinguishedname[0]
            $groupName = $result.Properties.name[0]
            
            foreach ($member in $result.Properties.member) {
                # Check if member is a group (not user)
                try {
                    $memberSearch = [ADSISearcher]"(distinguishedName=$member)"
                    $memberSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
                    $memberSearch.PropertiesToLoad.Add("objectClass")
                    
                    $memberResult = $memberSearch.FindOne()
                    if ($memberResult -and $memberResult.Properties.objectclass -contains "group") {
                        $nestedCount++
                        $adMap.Groups.NestedGroups += @{
                            ParentGroup = $groupName
                            ParentDN = $groupDN
                            ChildGroup = $member
                        }
                    }
                }
                catch {
                    # Skip if can't resolve
                }
            }
        }
        
        Write-Host "[+] Nested Group Relationships: $nestedCount" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error analyzing nested groups: $_" -ForegroundColor Yellow
    }
}

# ==================== GPOS ====================
function Get-GPOs {
    param($Connection)
    
    if (-not $config.CollectGPOs) { return }
    
    Write-Host "`n[*] Enumerating Group Policy Objects..." -ForegroundColor Green
    
    try {
        $gpoSearch = [ADSISearcher]"(objectClass=groupPolicyContainer)"
        $gpoSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/CN=Policies,CN=System,$($Connection.DomainDN)"
        $gpoSearch.PageSize = 500
        $gpoSearch.PropertiesToLoad.AddRange(@(
            "displayName", "name", "gPCFileSysPath", "gPCFunctionalityVersion",
            "gPCMachineExtensionNames", "gPCUserExtensionNames", "whenCreated", "whenChanged",
            "versionNumber", "flags"
        ))
        
        $gpoResults = $gpoSearch.FindAll()
        $gpoCount = 0
        
        foreach ($result in $gpoResults) {
            if ($global:timeoutReached) { break }
            
            $gpoInfo = @{
                Name = if ($result.Properties.displayName) { $result.Properties.displayName[0] } else { "Unnamed GPO" }
                GUID = $result.Properties.name[0]
                SysvolPath = if ($result.Properties.gPCFileSysPath) { $result.Properties.gPCFileSysPath[0] } else { "" }
                Version = if ($result.Properties.versionNumber) { $result.Properties.versionNumber[0] } else { 0 }
                Created = $result.Properties.whenCreated[0]
                Modified = $result.Properties.whenChanged[0]
                Status = if ($result.Properties.flags -and $result.Properties.flags[0] -eq 1) { "Disabled" } else { "Enabled" }
                Extensions = @{
                    Machine = if ($result.Properties.gPCMachineExtensionNames) { $result.Properties.gPCMachineExtensionNames[0] } else { "" }
                    User = if ($result.Properties.gPCUserExtensionNames) { $result.Properties.gPCUserExtensionNames[0] } else { "" }
                }
            }
            
            $adMap.GPOs += $gpoInfo
            $gpoCount++
            
            if ($gpoCount % 50 -eq 0) {
                Write-Host "  [+] Found $gpoCount GPOs..." -ForegroundColor Gray
            }
        }
        
        Write-Host "[+] Total GPOs: $gpoCount" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error enumerating GPOs: $_" -ForegroundColor Yellow
    }
}

# ==================== COMPUTERS ====================
function Get-Computers {
    param($Connection)
    
    if (-not $config.CollectComputers) { return }
    
    Write-Host "`n[*] Enumerating computers..." -ForegroundColor Green
    
    try {
        $computerSearch = [ADSISearcher]"(objectClass=computer)"
        $computerSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $computerSearch.PageSize = 1000
        $computerSearch.PropertiesToLoad.AddRange(@(
            "name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
            "operatingSystemServicePack", "lastLogonTimestamp", "userAccountControl",
            "description", "managedBy", "ms-MCS-AdmPwd", "ms-MCS-AdmPwdExpirationTime"
        ))
        
        $computerResults = $computerSearch.FindAll()
        $totalComputers = 0
        $dcCount = 0
        $serverCount = 0
        $lapsCount = 0
        
        foreach ($result in $computerResults) {
            if ($global:timeoutReached) { break }
            
            $computerName = $result.Properties.name[0]
            $os = if ($result.Properties.operatingSystem) { $result.Properties.operatingSystem[0] } else { "" }
            $uac = if ($result.Properties.userAccountControl) { $result.Properties.userAccountControl[0] } else { 0 }
            
            $computerInfo = @{
                Name = $computerName
                DNSHostName = if ($result.Properties.dNSHostName) { $result.Properties.dNSHostName[0] } else { $computerName }
                OperatingSystem = $os
                OSVersion = if ($result.Properties.operatingSystemVersion) { $result.Properties.operatingSystemVersion[0] } else { "" }
                LastLogon = if ($result.Properties.lastLogonTimestamp) { $result.Properties.lastLogonTimestamp[0] } else { $null }
                Description = if ($result.Properties.description) { $result.Properties.description[0] } else { "" }
                ManagedBy = if ($result.Properties.managedBy) { $result.Properties.managedBy[0] } else { "" }
                IsDomainController = (($uac -band 0x2000) -eq 0x2000)  # SERVER_TRUST_ACCOUNT
                IsServer = $os -like "*Server*"
                LAPS = @{
                    HasLAPS = [bool]($result.Properties."ms-MCS-AdmPwd")
                    PasswordExpiration = if ($result.Properties."ms-MCS-AdmPwdExpirationTime") { 
                        [datetime]::FromFileTime([int64]$result.Properties."ms-MCS-AdmPwdExpirationTime"[0])
                    } else { $null }
                }
            }
            
            # Categorize
            if ($computerInfo.IsDomainController) {
                $adMap.Computers.DomainControllers += $computerInfo
                $dcCount++
            }
            elseif ($computerInfo.IsServer) {
                $adMap.Computers.Servers += $computerInfo
                $serverCount++
            }
            else {
                $adMap.Computers.Workstations += $computerInfo
            }
            
            if ($computerInfo.LAPS.HasLAPS) {
                $adMap.Computers.LAPSEnabled += $computerInfo
                $lapsCount++
            }
            
            $totalComputers++
            
            if ($totalComputers % 500 -eq 0) {
                Write-Host "  [+] Processed $totalComputers computers..." -ForegroundColor Gray
            }
        }
        
        Write-Host "[+] Total Computers: $totalComputers" -ForegroundColor Green
        Write-Host "[+] Domain Controllers: $dcCount" -ForegroundColor $(if($dcCount -gt 0){"Yellow"}else{"White"})
        Write-Host "[+] Servers: $serverCount" -ForegroundColor White
        Write-Host "[+] LAPS Enabled: $lapsCount" -ForegroundColor $(if($lapsCount -gt 0){"Green"}else{"White"})
    }
    catch {
        Write-Host "[-] Error enumerating computers: $_" -ForegroundColor Yellow
    }
}

# ==================== TRUSTS ====================
function Get-Trusts {
    param($Connection)
    
    if (-not $config.CollectTrusts) { return }
    
    Write-Host "`n[*] Enumerating domain trusts..." -ForegroundColor Green
    
    try {
        $trustSearch = [ADSISearcher]"(objectClass=trustedDomain)"
        $trustSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $trustSearch.PropertiesToLoad.AddRange(@(
            "name", "trustDirection", "trustType", "trustAttributes",
            "trustPartner", "flatName", "securityIdentifier"
        ))
        
        $trustResults = $trustSearch.FindAll()
        
        foreach ($result in $trustResults) {
            $trustInfo = @{
                Name = $result.Properties.name[0]
                TrustPartner = if ($result.Properties.trustPartner) { $result.Properties.trustPartner[0] } else { "" }
                Direction = switch ($result.Properties.trustDirection[0]) {
                    1 { "Inbound" }
                    2 { "Outbound" }
                    3 { "Bidirectional" }
                    default { "Unknown" }
                }
                Type = switch ($result.Properties.trustType[0]) {
                    1 { "Downlevel (NT4)" }
                    2 { "Uplevel (AD)" }
                    3 { "MIT" }
                    default { "Unknown" }
                }
                Attributes = @{
                    IsForestTrust = [bool]($result.Properties.trustAttributes[0] -band 0x00000020)
                    IsTransitive = [bool]($result.Properties.trustAttributes[0] -band 0x00000040)
                    IsQuarantined = [bool]($result.Properties.trustAttributes[0] -band 0x00000004)
                    UsesRC4 = [bool]($result.Properties.trustAttributes[0] -band 0x00000080)
                }
                FlatName = if ($result.Properties.flatName) { $result.Properties.flatName[0] } else { "" }
                SID = if ($result.Properties.securityIdentifier) { 
                    [System.Security.Principal.SecurityIdentifier]::new($result.Properties.securityIdentifier[0], 0).Value 
                } else { "" }
            }
            
            $adMap.Trusts += $trustInfo
        }
        
        Write-Host "[+] Total Trusts: $($adMap.Trusts.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error enumerating trusts: $_" -ForegroundColor Yellow
    }
}

# ==================== SITES & SUBNETS ====================
function Get-SitesAndSubnets {
    param($Connection)
    
    if (-not $config.CollectSites) { return }
    
    Write-Host "`n[*] Enumerating AD Sites and Subnets..." -ForegroundColor Green
    
    try {
        # Get Sites
        $siteSearch = [ADSISearcher]"(objectClass=site)"
        $siteSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/CN=Sites,$($Connection.ConfigDN)"
        $siteSearch.PropertiesToLoad.AddRange(@("name", "description", "location"))
        
        $siteResults = $siteSearch.FindAll()
        
        foreach ($result in $siteResults) {
            $siteInfo = @{
                Name = $result.Properties.name[0]
                Description = if ($result.Properties.description) { $result.Properties.description[0] } else { "" }
                Location = if ($result.Properties.location) { $result.Properties.location[0] } else { "" }
                Subnets = @()
            }
            
            # Get Subnets for this site
            $subnetSearch = [ADSISearcher]"(objectClass=subnet)"
            $subnetSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/CN=Subnets,CN=Sites,$($Connection.ConfigDN)"
            $subnetSearch.Filter = "(siteObject=CN=$($siteInfo.Name),CN=Sites,$($Connection.ConfigDN))"
            $subnetSearch.PropertiesToLoad.AddRange(@("name", "description", "location"))
            
            $subnetResults = $subnetSearch.FindAll()
            
            foreach ($subnet in $subnetResults) {
                $subnetInfo = @{
                    Name = $subnet.Properties.name[0]  # CIDR notation
                    Description = if ($subnet.Properties.description) { $subnet.Properties.description[0] } else { "" }
                    Location = if ($subnet.Properties.location) { $subnet.Properties.location[0] } else { "" }
                }
                $siteInfo.Subnets += $subnetInfo
                $adMap.Subnets += $subnetInfo
            }
            
            $adMap.Sites += $siteInfo
        }
        
        Write-Host "[+] Sites: $($adMap.Sites.Count)" -ForegroundColor Green
        Write-Host "[+] Subnets: $($adMap.Subnets.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error enumerating sites/subnets: $_" -ForegroundColor Yellow
    }
}

# ==================== CERTIFICATE TEMPLATES ====================
function Get-CertificateTemplates {
    param($Connection)
    
    if (-not $config.CollectCertTemplates) { return }
    
    Write-Host "`n[*] Enumerating Certificate Templates..." -ForegroundColor Green
    
    try {
        $certSearch = [ADSISearcher]"(objectClass=pKICertificateTemplate)"
        $certSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/CN=Certificate Templates,CN=Public Key Services,CN=Services,$($Connection.ConfigDN)"
        $certSearch.PageSize = 100
        $certSearch.PropertiesToLoad.AddRange(@(
            "name", "displayName", "pKIExpirationPeriod", "pKIOverlapPeriod",
            "pKIDefaultKeySpec", "pKIKeyUsage", "pKIMaxIssuingDepth",
            "pKICriticalExtensions", "pKIExtendedKeyUsage", "flags"
        ))
        
        $certResults = $certSearch.FindAll()
        
        foreach ($result in $certResults) {
            $certInfo = @{
                Name = $result.Properties.name[0]
                DisplayName = if ($result.Properties.displayName) { $result.Properties.displayName[0] } else { "" }
                ExpirationPeriod = if ($result.Properties.pKIExpirationPeriod) { 
                    [System.BitConverter]::ToUInt64($result.Properties.pKIExpirationPeriod[0], 0)
                } else { 0 }
                KeyUsage = if ($result.Properties.pKIKeyUsage) { $result.Properties.pKIKeyUsage[0] } else { 0 }
                Flags = if ($result.Properties.flags) { $result.Properties.flags[0] } else { 0 }
                IsEnrollmentEnabled = [bool]($result.Properties.flags[0] -band 0x00000001)
                IsAutoEnrollmentEnabled = [bool]($result.Properties.flags[0] -band 0x00000002)
                IsMachineType = [bool]($result.Properties.flags[0] -band 0x00000004)
                IsCA = [bool]($result.Properties.flags[0] -band 0x00000008)
                ExtendedKeyUsage = if ($result.Properties.pKIExtendedKeyUsage) { $result.Properties.pKIExtendedKeyUsage } else { @() }
            }
            
            $adMap.CertificateTemplates += $certInfo
        }
        
        Write-Host "[+] Certificate Templates: $($adMap.CertificateTemplates.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error enumerating certificate templates: $_" -ForegroundColor Yellow
    }
}

# ==================== SERVICE ACCOUNTS ====================
function Get-ServiceAccounts {
    param($Connection)
    
    if (-not $config.CollectServiceAccounts) { return }
    
    Write-Host "`n[*] Looking for service accounts..." -ForegroundColor Green
    
    try {
        # gMSA accounts
        $gmsaSearch = [ADSISearcher]"(objectClass=msDS-GroupManagedServiceAccount)"
        $gmsaSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $gmsaSearch.PropertiesToLoad.AddRange(@(
            "samAccountName", "distinguishedName", "msDS-ManagedPasswordInterval",
            "msDS-GroupMSAMembership", "msDS-HostServiceAccountBL"
        ))
        
        $gmsaResults = $gmsaSearch.FindAll()
        
        foreach ($gmsa in $gmsaResults) {
            $adMap.ServiceAccounts += @{
                Type = "gMSA"
                Name = $gmsa.Properties.samAccountName[0]
                DistinguishedName = $gmsa.Properties.distinguishedName[0]
                PasswordInterval = if ($gmsa.Properties."msDS-ManagedPasswordInterval") { 
                    $gmsa.Properties."msDS-ManagedPasswordInterval"[0] 
                } else { 30 }
                AllowedPrincipals = if ($gmsa.Properties."msDS-GroupMSAMembership") { 
                    $gmsa.Properties."msDS-GroupMSAMembership"
                } else { @() }
            }
        }
        
        # Regular service accounts (names ending with $ but not computers)
        $svcSearch = [ADSISearcher]"(samAccountName=*$)"
        $svcSearch.SearchRoot = [ADSI]"LDAP://$($Connection.Server)/$($Connection.DomainDN)"
        $svcSearch.PageSize = 500
        $svcSearch.PropertiesToLoad.AddRange(@("samAccountName", "distinguishedName", "description", "servicePrincipalName"))
        
        $svcResults = $svcSearch.FindAll()
        
        foreach ($svc in $svcResults) {
            $name = $svc.Properties.samAccountName[0]
            # Filter out computer accounts
            if ($name -notmatch "^[A-Za-z0-9]+$$" -or $name -match "\$\$$") {
                $adMap.ServiceAccounts += @{
                    Type = "ServiceAccount"
                    Name = $name
                    DistinguishedName = $svc.Properties.distinguishedName[0]
                    Description = if ($svc.Properties.description) { $svc.Properties.description[0] } else { "" }
                    SPNs = if ($svc.Properties.servicePrincipalName) { $svc.Properties.servicePrincipalName } else { @() }
                }
            }
        }
        
        Write-Host "[+] Service Accounts: $($adMap.ServiceAccounts.Count)" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error enumerating service accounts: $_" -ForegroundColor Yellow
    }
}

# ==================== MAIN EXECUTION ====================
try {
    Write-Host "[*] Starting AD Mapper..." -ForegroundColor Green
    Write-Host "[*] Timeout set to: $Timeout seconds" -ForegroundColor Gray
    
    # Test connection
    $connection = Test-Connection
    
    # Start collection
    Get-DomainInfo -Connection $connection
    Get-ForestInfo -Connection $connection
    Get-OUs -Connection $connection
    Get-Groups -Connection $connection
    Get-GPOs -Connection $connection
    Get-Computers -Connection $connection
    Get-Trusts -Connection $connection
    Get-SitesAndSubnets -Connection $connection
    Get-CertificateTemplates -Connection $connection
    Get-ServiceAccounts -Connection $connection
    
    # Stop timeout timer
    $timeoutTimer.Stop()
    Unregister-Event -SourceIdentifier TimeoutReached -ErrorAction SilentlyContinue
    
    # Calculate statistics
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    $adMap.Statistics = @{
        CollectionDuration = $duration.ToString("hh\:mm\:ss")
        OUs = $adMap.OUs.Count
        Groups = @{
            Total = $adMap.Groups.Builtin.Count + $adMap.Groups.Security.Count + $adMap.Groups.Distribution.Count
            HighValue = $adMap.Groups.HighValue.Count
            AdminCount = $adMap.Groups.AdminCount.Count
            Nested = $adMap.Groups.NestedGroups.Count
        }
        GPOs = $adMap.GPOs.Count
        Computers = @{
            Total = $adMap.Computers.DomainControllers.Count + $adMap.Computers.Servers.Count + $adMap.Computers.Workstations.Count
            DomainControllers = $adMap.Computers.DomainControllers.Count
            Servers = $adMap.Computers.Servers.Count
            LAPSEnabled = $adMap.Computers.LAPSEnabled.Count
        }
        Trusts = $adMap.Trusts.Count
        Sites = $adMap.Sites.Count
        Subnets = $adMap.Subnets.Count
        CertificateTemplates = $adMap.CertificateTemplates.Count
        ServiceAccounts = $adMap.ServiceAccounts.Count
        TimeoutReached = $global:timeoutReached
    }
    
    # Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    $adMap | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Create summary report
    $summaryPath = $OutputPath -replace "\.json$", "_summary.txt"
    Create-SummaryReport -Map $adMap -Path $summaryPath
    
    # Display summary
    Display-Summary -Map $adMap -Duration $duration
    
}
catch {
    Write-Host "`n[!] FATAL ERROR: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.Exception.StackTrace)" -ForegroundColor DarkRed
}
finally {
    # Cleanup
    $timeoutTimer.Stop()
    $timeoutTimer.Dispose()
}

# ==================== HELPER FUNCTIONS ====================
function Create-SummaryReport {
    param($Map, $Path)
    
    $report = @"
Active Directory Complete Map - Summary Report
===============================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $($Map.Domain.Name)
Domain Controller: $($Map.Meta.DomainController)
Collection Duration: $($Map.Statistics.CollectionDuration)

DOMAIN INFORMATION:
  Domain Name: $($Map.Domain.Name)
  Domain SID: $($Map.Domain.SID)
  Functional Level: $($Map.Domain.FunctionalLevel)
  Password Policy:
    - Minimum Length: $($Map.Domain.PasswordPolicy.MinLength)
    - Complexity Required: $($Map.Domain.PasswordPolicy.Complexity)
    - Lockout Threshold: $($Map.Domain.PasswordPolicy.LockoutThreshold)

FOREST INFORMATION:
  Forest Functional Level: $($Map.Forest.FunctionalLevel)
  Total Domains in Forest: $($Map.Forest.DomainCount)

ORGANIZATIONAL UNITS:
  Total OUs: $($Map.Statistics.OUs)
  OUs with GPO Links: $(($Map.OUs | Where-Object { $_.GPOLinks.Count -gt 0 }).Count)

GROUPS:
  Total Groups: $($Map.Statistics.Groups.Total)
  High-Value Groups: $($Map.Statistics.Groups.HighValue)
  AdminCount=1 Groups: $($Map.Statistics.Groups.AdminCount)
  Nested Group Relationships: $($Map.Statistics.Groups.Nested)

GROUP POLICY OBJECTS:
  Total GPOs: $($Map.Statistics.GPOs)
  Enabled GPOs: $(($Map.GPOs | Where-Object { $_.Status -eq "Enabled" }).Count)

COMPUTERS:
  Total Computers: $($Map.Statistics.Computers.Total)
  Domain Controllers: $($Map.Statistics.Computers.DomainControllers)
  Servers: $($Map.Statistics.Computers.Servers)
  Computers with LAPS: $($Map.Statistics.Computers.LAPSEnabled)

TRUSTS:
  Total Trusts: $($Map.Statistics.Trusts)
  Bidirectional: $(($Map.Trusts | Where-Object { $_.Direction -eq "Bidirectional" }).Count)
  Forest Trusts: $(($Map.Trusts | Where-Object { $_.Attributes.IsForestTrust }).Count)

SITES & SUBNETS:
  Sites: $($Map.Statistics.Sites)
  Subnets: $($Map.Statistics.Subnets)

CERTIFICATE TEMPLATES:
  Total Templates: $($Map.Statistics.CertificateTemplates)
  Enrollment Enabled: $(($Map.CertificateTemplates | Where-Object { $_.IsEnrollmentEnabled }).Count)

SERVICE ACCOUNTS:
  Total Service Accounts: $($Map.Statistics.ServiceAccounts)
  gMSA Accounts: $(($Map.ServiceAccounts | Where-Object { $_.Type -eq "gMSA" }).Count)

CRITICAL FINDINGS:
$($(if ($Map.Statistics.Groups.HighValue -gt 0) {
  "  - Found $($Map.Statistics.Groups.HighValue) high-value groups (Domain Admins, etc.)"
}))
$($(if ($Map.Statistics.Computers.DomainControllers -gt 0) {
  "  - Found $($Map.Statistics.Computers.DomainControllers) domain controllers"
}))
$($(if ($Map.Statistics.Computers.LAPSEnabled -gt 0) {
  "  - Found $($Map.Statistics.Computers.LAPSEnabled) computers with LAPS enabled"
}))

NOTES:
- Complete data saved to: $OutputPath
- This report includes structure and configuration only (no user details)
- Use for authorized penetration testing and security assessments only
"@
    
    $report | Out-File -FilePath $Path -Encoding UTF8
}

function Display-Summary {
    param($Map, $Duration)
    
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host " AD MAPPING COMPLETE" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    Write-Host "Collection Time: $($Duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
    Write-Host "Domain: $($Map.Domain.Name)" -ForegroundColor White
    Write-Host "Output File: $OutputPath" -ForegroundColor Green
    
    Write-Host "`nSUMMARY STATISTICS:" -ForegroundColor Yellow
    Write-Host "  OUs: $($Map.Statistics.OUs)" -ForegroundColor White
    Write-Host "  Groups: $($Map.Statistics.Groups.Total)" -ForegroundColor White
    Write-Host "  High-Value Groups: $($Map.Statistics.Groups.HighValue)" -ForegroundColor $(if($Map.Statistics.Groups.HighValue -gt 0){"Red"}else{"Green"})
    Write-Host "  GPOs: $($Map.Statistics.GPOs)" -ForegroundColor White
    Write-Host "  Computers: $($Map.Statistics.Computers.Total)" -ForegroundColor White
    Write-Host "  Domain Controllers: $($Map.Statistics.Computers.DomainControllers)" -ForegroundColor $(if($Map.Statistics.Computers.DomainControllers -gt 0){"Yellow"}else{"White"})
    Write-Host "  Trusts: $($Map.Statistics.Trusts)" -ForegroundColor White
    Write-Host "  Sites: $($Map.Statistics.Sites)" -ForegroundColor White
    Write-Host "  Subnets: $($Map.Statistics.Subnets)" -ForegroundColor White
    Write-Host "  Certificate Templates: $($Map.Statistics.CertificateTemplates)" -ForegroundColor White
    Write-Host "  Service Accounts: $($Map.Statistics.ServiceAccounts)" -ForegroundColor White
    
    if ($Map.Statistics.TimeoutReached) {
        Write-Host "`n[!] WARNING: Timeout reached! Some data may be incomplete." -ForegroundColor Red
        Write-Host "    Consider increasing timeout with -Timeout parameter." -ForegroundColor Yellow
    }
    
    Write-Host "`n[+] Summary report saved to: $($OutputPath -replace '\.json$', '_summary.txt')" -ForegroundColor Green
    Write-Host "[+] Complete JSON data saved to: $OutputPath" -ForegroundColor Green
    Write-Host "`n[+] You can now analyze the AD structure for security assessment." -ForegroundColor Cyan
}
