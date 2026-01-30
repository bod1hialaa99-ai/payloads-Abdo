# Save this as SmartADEnum.ps1
param(
    [Parameter(Mandatory=$false)]
    [string]$DomainController,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "ad_enum_results.json",
    
    [Parameter(Mandatory=$false)]
    [switch]$TestOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose,
    
    [Parameter(Mandatory=$false)]
    [pscredential]$Credential
)

# ==================== BANNER ====================
Write-Host @"
===============================================================
   _____                      _   _____  _____                 
  / ____|                    | | |  __ \|  __ \                
 | (___  _ __ ___   __ _ _ __| |_| |  | | |  | | ___ _ __ ___  
  \___ \| '_ ' _ \ / _' | '__| __| |  | | |  | |/ _ \ '_ ' _ \ 
  ____) | | | | | | (_| | |  | |_| |__| | |__| |  __/ | | | | |
 |_____/|_| |_| |_|\__,_|_|   \__|_____/|_____/ \___|_| |_| |_|
                                                               
                Smart AD Enumeration Tool
          Focused Enumeration for Authorized Testing
===============================================================
"@ -ForegroundColor Cyan

# ==================== TEST CONNECTION FUNCTION ====================
function Test-ADConnection {
    param($Server, $Credential)
    
    Write-Host "[*] Testing connection to domain..." -ForegroundColor Yellow
    
    try {
        if ($Server) {
            Write-Host "  [*] Attempting to connect to: $Server" -ForegroundColor Gray
        } else {
            Write-Host "  [*] Attempting to connect to current domain..." -ForegroundColor Gray
        }
        
        # Try multiple methods to connect
        $methods = @()
        
        # Method 1: Try ADSI
        try {
            if ($Server) {
                $root = [ADSI]"LDAP://$Server/RootDSE"
            } else {
                $root = [ADSI]"LDAP://RootDSE"
            }
            $methods += "ADSI Connection: SUCCESS"
            $methods += "  Default Naming Context: $($root.defaultNamingContext)"
            $methods += "  Domain: $($root.defaultNamingContext -replace 'DC=','' -replace ',','.' -replace 'DC=','')"
            $methods += "  DNS Hostname: $($root.dnsHostName)"
            $methods += "  Forest: $($root.rootDomainNamingContext)"
        } catch {
            $methods += "ADSI Connection: FAILED - $_"
        }
        
        # Method 2: Try System.DirectoryServices
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry
            if ($Server) {
                $de.Path = "LDAP://$Server"
            }
            $de.RefreshCache()
            $methods += "DirectoryServices: SUCCESS"
            $methods += "  Schema: $($de.SchemaClassName)"
        } catch {
            $methods += "DirectoryServices: FAILED"
        }
        
        # Method 3: Try .NET Domain
        try {
            if ($Server) {
                $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer
                $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType, $Server)
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            } else {
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            $methods += ".NET Domain API: SUCCESS"
            $methods += "  Domain Name: $($domain.Name)"
            $methods += "  Forest Name: $($domain.Forest.Name)"
            $methods += "  Domain Controllers: $($domain.DomainControllers.Count)"
        } catch {
            $methods += ".NET Domain API: FAILED"
        }
        
        return @{
            Success = $true
            Methods = $methods
        }
    }
    catch {
        Write-Host "  [!] Connection test failed completely" -ForegroundColor Red
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

# ==================== MAIN ENUMERATION FUNCTION ====================
function Invoke-SmartEnumeration {
    param($Server, $Credential, $OutputPath)
    
    $startTime = Get-Date
    $results = @{
        CollectionTime = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
        DomainController = $Server
        Status = "Running"
        Data = @{
            DomainInfo = @{}
            HighValueGroups = @()
            AdminUsers = @()
            ServiceAccounts = @()
            Computers = @()
            Trusts = @()
            OUs = @()
            GPOs = @()
            ACLs = @()
            Findings = @()
        }
    }
    
    # Get domain information
    Write-Host "`n[*] Collecting domain information..." -ForegroundColor Green
    try {
        $rootDSE = [ADSI]"LDAP://$Server/RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        $domainName = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
        
        $results.Data.DomainInfo = @{
            Name = $domainName
            DistinguishedName = $domainDN
            DNSHostName = $rootDSE.dnsHostName
            Forest = ($rootDSE.rootDomainNamingContext -replace 'DC=','' -replace ',','.' -replace 'DC=','')
            DomainFunctionality = $rootDSE.domainFunctionality
            ForestFunctionality = $rootDSE.forestFunctionality
        }
        
        Write-Host "  [+] Domain: $domainName" -ForegroundColor Green
        Write-Host "  [+] Forest: $($results.Data.DomainInfo.Forest)" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed to get domain info: $_" -ForegroundColor Red
    }
    
    # Get domain SID
    Write-Host "[*] Getting domain SID..." -ForegroundColor Yellow
    try {
        $domainSearch = [ADSISearcher]"(objectClass=domain)"
        $domainSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
        $domainResult = $domainSearch.FindOne()
        
        if ($domainResult) {
            $domainSid = [System.Security.Principal.SecurityIdentifier]::new($domainResult.Properties.objectsid[0], 0).Value
            $results.Data.DomainInfo.DomainSID = $domainSid
            Write-Host "  [+] Domain SID: $domainSid" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Failed to get domain SID" -ForegroundColor Yellow
    }
    
    # ==================== ENUMERATE HIGH-VALUE GROUPS ====================
    Write-Host "`n[*] Enumerating high-value groups..." -ForegroundColor Green
    
    $highValueGroups = @(
        @{Name="Domain Admins"; Risk="Critical"},
        @{Name="Enterprise Admins"; Risk="Critical"},
        @{Name="Schema Admins"; Risk="Critical"},
        @{Name="Administrators"; Risk="High"},
        @{Name="Account Operators"; Risk="High"},
        @{Name="Backup Operators"; Risk="High"},
        @{Name="Print Operators"; Risk="Medium"},
        @{Name="Server Operators"; Risk="High"},
        @{Name="Domain Controllers"; Risk="High"},
        @{Name="Group Policy Creator Owners"; Risk="High"},
        @{Name="DNS Admins"; Risk="High"},
        @{Name="Remote Desktop Users"; Risk="Medium"},
        @{Name="Hyper-V Administrators"; Risk="Medium"},
        @{Name="Certificate Service DCOM Access"; Risk="High"},
        @{Name="Protected Users"; Risk="Info"},
        @{Name="Windows Authorization Access Group"; Risk="Info"}
    )
    
    foreach ($group in $highValueGroups) {
        try {
            $groupSearch = [ADSISearcher]"(name=$($group.Name))"
            $groupSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
            $groupSearch.PropertiesToLoad.AddRange(@("distinguishedName", "name", "objectSid", "description", "adminCount", "member", "whenCreated", "whenChanged"))
            
            $groupResult = $groupSearch.FindOne()
            
            if ($groupResult) {
                $groupSid = [System.Security.Principal.SecurityIdentifier]::new($groupResult.Properties.objectsid[0], 0).Value
                
                $groupInfo = @{
                    Name = $group.Name
                    SID = $groupSid
                    RiskLevel = $group.Risk
                    DistinguishedName = $groupResult.Properties.distinguishedname[0]
                    AdminCount = if ($groupResult.Properties.adminCount) { $groupResult.Properties.adminCount[0] } else { 0 }
                    MemberCount = if ($groupResult.Properties.member) { $groupResult.Properties.member.Count } else { 0 }
                    Created = if ($groupResult.Properties.whenCreated) { $groupResult.Properties.whenCreated[0] } else { $null }
                    Description = if ($groupResult.Properties.description) { $groupResult.Properties.description[0] } else { "" }
                }
                
                $results.Data.HighValueGroups += $groupInfo
                Write-Host "  [+] $($group.Name) ($($group.Risk)) - $($groupInfo.MemberCount) members" -ForegroundColor $(if($group.Risk -eq "Critical"){"Red"}elseif($group.Risk -eq "High"){"Yellow"}else{"White"})
                
                # Get members if not too many
                if ($groupInfo.MemberCount -gt 0 -and $groupInfo.MemberCount -lt 100) {
                    $members = @()
                    foreach ($memberDN in $groupResult.Properties.member) {
                        try {
                            $memberSearch = [ADSISearcher]"(distinguishedName=$memberDN)"
                            $memberSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
                            $memberSearch.PropertiesToLoad.AddRange(@("samAccountName", "name", "objectClass", "userAccountControl"))
                            
                            $memberResult = $memberSearch.FindOne()
                            if ($memberResult) {
                                $memberType = $memberResult.Properties.objectclass[-1].ToString()
                                $members += @{
                                    Name = if ($memberResult.Properties.samAccountName) { $memberResult.Properties.samAccountName[0] } else { $memberResult.Properties.name[0] }
                                    Type = $memberType
                                    DN = $memberDN
                                }
                                
                                # Add to admin users list if it's a user
                                if ($memberType -eq "user") {
                                    $userExists = $results.Data.AdminUsers | Where-Object { $_.DN -eq $memberDN }
                                    if (-not $userExists) {
                                        $results.Data.AdminUsers += @{
                                            Username = $memberResult.Properties.samAccountName[0]
                                            DistinguishedName = $memberDN
                                            Groups = @($group.Name)
                                        }
                                    }
                                }
                            }
                        } catch {
                            # Skip if member can't be resolved
                        }
                    }
                    $groupInfo.Members = $members
                }
            } else {
                if ($Verbose) {
                    Write-Host "  [-] $($group.Name) - Not found" -ForegroundColor Gray
                }
            }
        } catch {
            if ($Verbose) {
                Write-Host "  [!] Error enumerating $($group.Name): $_" -ForegroundColor DarkYellow
            }
        }
    }
    
    # ==================== ENUMERATE ADMIN-COUNT=1 GROUPS ====================
    Write-Host "`n[*] Looking for groups with adminCount=1..." -ForegroundColor Green
    try {
        $adminCountSearch = [ADSISearcher]"(adminCount=1)"
        $adminCountSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
        $adminCountSearch.PageSize = 1000
        $adminCountSearch.Filter = "(&(objectClass=group)(adminCount=1))"
        $adminCountSearch.PropertiesToLoad.AddRange(@("name", "distinguishedName", "objectSid", "description"))
        
        $adminCountResults = $adminCountSearch.FindAll()
        $adminCountGroups = @()
        
        foreach ($result in $adminCountResults) {
            $groupName = $result.Properties.name[0]
            
            # Check if already in high-value groups
            $exists = $results.Data.HighValueGroups | Where-Object { $_.Name -eq $groupName }
            if (-not $exists) {
                $groupSid = [System.Security.Principal.SecurityIdentifier]::new($result.Properties.objectsid[0], 0).Value
                $adminCountGroups += @{
                    Name = $groupName
                    SID = $groupSid
                    DistinguishedName = $result.Properties.distinguishedname[0]
                    Description = if ($result.Properties.description) { $result.Properties.description[0] } else { "" }
                }
            }
        }
        
        if ($adminCountGroups.Count -gt 0) {
            Write-Host "  [+] Found $($adminCountGroups.Count) additional adminCount=1 groups" -ForegroundColor Yellow
            $results.Data.Findings += @{
                Type = "AdminCountGroups"
                Count = $adminCountGroups.Count
                Groups = $adminCountGroups
            }
        }
    } catch {
        Write-Host "  [!] Failed to enumerate adminCount groups" -ForegroundColor Yellow
    }
    
    # ==================== ENUMERATE TRUSTS ====================
    Write-Host "`n[*] Enumerating domain trusts..." -ForegroundColor Green
    try {
        $trustsSearch = [ADSISearcher]"(objectClass=trustedDomain)"
        $trustsSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
        $trustsSearch.PropertiesToLoad.AddRange(@("name", "trustDirection", "trustType", "trustAttributes"))
        
        $trustsResults = $trustsSearch.FindAll()
        $trusts = @()
        
        foreach ($trust in $trustsResults) {
            $trustInfo = @{
                Name = $trust.Properties.name[0]
                Direction = switch ($trust.Properties.trustDirection[0]) {
                    1 { "Inbound" }
                    2 { "Outbound" }
                    3 { "Bidirectional" }
                    default { "Unknown" }
                }
                Type = switch ($trust.Properties.trustType[0]) {
                    1 { "Downlevel (NT4)" }
                    2 { "Uplevel (AD)" }
                    3 { "MIT" }
                    default { "Unknown" }
                }
            }
            $trusts += $trustInfo
        }
        
        if ($trusts.Count -gt 0) {
            Write-Host "  [+] Found $($trusts.Count) domain trusts" -ForegroundColor Green
            $results.Data.Trusts = $trusts
        }
    } catch {
        Write-Host "  [!] Failed to enumerate trusts" -ForegroundColor Yellow
    }
    
    # ==================== ENUMERATE DOMAIN CONTROLLERS ====================
    Write-Host "`n[*] Finding domain controllers..." -ForegroundColor Green
    try {
        $dcsSearch = [ADSISearcher]"(userAccountControl:1.2.840.113556.1.4.803:=8192)"  # SERVER_TRUST_ACCOUNT
        $dcsSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
        $dcsSearch.PropertiesToLoad.AddRange(@("name", "dNSHostName", "operatingSystem", "operatingSystemVersion"))
        
        $dcsResults = $dcsSearch.FindAll()
        $domainControllers = @()
        
        foreach ($dc in $dcsResults) {
            $dcInfo = @{
                Name = $dc.Properties.name[0]
                DNSHostName = if ($dc.Properties.dNSHostName) { $dc.Properties.dNSHostName[0] } else { $dc.Properties.name[0] }
                OS = if ($dc.Properties.operatingSystem) { $dc.Properties.operatingSystem[0] } else { "Unknown" }
                OSVersion = if ($dc.Properties.operatingSystemVersion) { $dc.Properties.operatingSystemVersion[0] } else { "Unknown" }
            }
            $domainControllers += $dcInfo
        }
        
        if ($domainControllers.Count -gt 0) {
            Write-Host "  [+] Found $($domainControllers.Count) domain controllers" -ForegroundColor Green
            $results.Data.Computers = $domainControllers
        }
    } catch {
        Write-Host "  [!] Failed to enumerate domain controllers" -ForegroundColor Yellow
    }
    
    # ==================== ENUMERATE SERVICE ACCOUNTS ====================
    Write-Host "`n[*] Looking for service accounts..." -ForegroundColor Green
    try {
        # Look for gMSA accounts
        $gmsaSearch = [ADSISearcher]"(objectClass=msDS-GroupManagedServiceAccount)"
        $gmsaSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
        $gmsaSearch.PropertiesToLoad.AddRange(@("samAccountName", "distinguishedName", "msDS-ManagedPasswordInterval"))
        
        $gmsaResults = $gmsaSearch.FindAll()
        
        foreach ($gmsa in $gmsaResults) {
            $results.Data.ServiceAccounts += @{
                Type = "gMSA"
                Username = $gmsa.Properties.samAccountName[0]
                DistinguishedName = $gmsa.Properties.distinguishedName[0]
                PasswordInterval = if ($gmsa.Properties."msDS-ManagedPasswordInterval") { $gmsa.Properties."msDS-ManagedPasswordInterval"[0] } else { 30 }
            }
        }
        
        # Look for regular service accounts (often end with $)
        $svcSearch = [ADSISearcher]"(samAccountName=*$)"
        $svcSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
        $svcSearch.PageSize = 100
        $svcSearch.PropertiesToLoad.AddRange(@("samAccountName", "distinguishedName", "description"))
        
        $svcResults = $svcSearch.FindAll()
        
        foreach ($svc in $svcResults) {
            $username = $svc.Properties.samAccountName[0]
            # Skip computer accounts (they also end with $)
            if ($username -notmatch ".*\$$" -or $username -match ".*\$\$$") {
                $results.Data.ServiceAccounts += @{
                    Type = "ServiceAccount"
                    Username = $username
                    DistinguishedName = $svc.Properties.distinguishedName[0]
                    Description = if ($svc.Properties.description) { $svc.Properties.description[0] } else { "" }
                }
            }
        }
        
        if ($results.Data.ServiceAccounts.Count -gt 0) {
            Write-Host "  [+] Found $($results.Data.ServiceAccounts.Count) service accounts" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Failed to enumerate service accounts" -ForegroundColor Yellow
    }
    
    # ==================== CHECK FOR COMMON MISCONFIGURATIONS ====================
    Write-Host "`n[*] Checking for common misconfigurations..." -ForegroundColor Green
    
    $findings = @()
    
    # Check if Guests account is enabled
    try {
        $guestSearch = [ADSISearcher]"(samAccountName=Guest)"
        $guestSearch.SearchRoot = [ADSI]"LDAP://$Server/$domainDN"
        $guestSearch.PropertiesToLoad.Add("userAccountControl")
        $guestResult = $guestSearch.FindOne()
        
        if ($guestResult) {
            $uac = $guestResult.Properties.userAccountControl[0]
            if (($uac -band 2) -eq 0) {  # Account is not disabled
                $findings += @{
                    Severity = "Medium"
                    Type = "GuestAccountEnabled"
                    Description = "Guest account is enabled"
                    Recommendation = "Disable the Guest account"
                }
            }
        }
    } catch { }
    
    # Check for empty password on AdminCount=1 accounts (simplified check)
    if ($results.Data.HighValueGroups.Count -gt 0) {
        $findings += @{
            Severity = "Info"
            Type = "AdminGroupsFound"
            Description = "Found $($results.Data.HighValueGroups.Count) high-value groups"
            Details = $results.Data.HighValueGroups | ForEach-Object { "$($_.Name): $($_.MemberCount) members" }
        }
    }
    
    # Check for AD recycle bin
    try {
        $featuresSearch = [ADSISearcher]"(objectClass=msDS-OptionalFeature)"
        $featuresSearch.SearchRoot = [ADSI]"LDAP://$Server/CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($rootDSE.configurationNamingContext)"
        $featuresSearch.PropertiesToLoad.Add("name")
        $featuresResults = $featuresSearch.FindAll()
        
        $recycleBinEnabled = $false
        foreach ($feature in $featuresResults) {
            if ($feature.Properties.name[0] -like "*Recycle Bin*") {
                $recycleBinEnabled = $true
                break
            }
        }
        
        if (-not $recycleBinEnabled) {
            $findings += @{
                Severity = "Low"
                Type = "RecycleBinDisabled"
                Description = "AD Recycle Bin is not enabled"
                Recommendation = "Enable AD Recycle Bin for object recovery"
            }
        }
    } catch { }
    
    $results.Data.Findings += $findings
    
    # ==================== CALCULATE STATISTICS ====================
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    $stats = @{
        Duration = $duration.ToString("hh\:mm\:ss")
        HighValueGroups = $results.Data.HighValueGroups.Count
        AdminUsers = $results.Data.AdminUsers.Count
        ServiceAccounts = $results.Data.ServiceAccounts.Count
        DomainControllers = $results.Data.Computers.Count
        Trusts = $results.Data.Trusts.Count
        Findings = $results.Data.Findings.Count
    }
    
    $results.Stats = $stats
    $results.Status = "Completed"
    $results.CompletionTime = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
    
    # ==================== SAVE RESULTS ====================
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # ==================== DISPLAY SUMMARY ====================
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host " ENUMERATION COMPLETE" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "Domain: $($results.Data.DomainInfo.Name)" -ForegroundColor White
    Write-Host "Duration: $($stats.Duration)" -ForegroundColor White
    Write-Host "High-Value Groups: $($stats.HighValueGroups)" -ForegroundColor Yellow
    Write-Host "Admin Users Found: $($stats.AdminUsers)" -ForegroundColor $(if($stats.AdminUsers -gt 0){"Red"}else{"Green"})
    Write-Host "Domain Controllers: $($stats.DomainControllers)" -ForegroundColor White
    Write-Host "Service Accounts: $($stats.ServiceAccounts)" -ForegroundColor $(if($stats.ServiceAccounts -gt 0){"Yellow"}else{"White"})
    Write-Host "Domain Trusts: $($stats.Trusts)" -ForegroundColor White
    Write-Host "Findings: $($stats.Findings)" -ForegroundColor $(if($stats.Findings -gt 0){"Yellow"}else{"White"})
    Write-Host "Output File: $OutputPath" -ForegroundColor Green
    
    # Show critical findings
    $criticalFindings = $results.Data.Findings | Where-Object { $_.Severity -eq "Critical" -or $_.Severity -eq "High" }
    if ($criticalFindings) {
        Write-Host "`n[!] CRITICAL FINDINGS:" -ForegroundColor Red
        foreach ($finding in $criticalFindings) {
            Write-Host "  • $($finding.Description)" -ForegroundColor Red
        }
    }
    
    return $results
}

# ==================== MAIN EXECUTION ====================
try {
    # Test connection first
    $connectionTest = Test-ADConnection -Server $DomainController -Credential $Credential
    
    if (-not $connectionTest.Success) {
        Write-Host "`n[!] FAILED TO CONNECT TO DOMAIN" -ForegroundColor Red
        Write-Host "Error: $($connectionTest.Error)" -ForegroundColor Red
        Write-Host "`nPossible solutions:" -ForegroundColor Yellow
        Write-Host "1. Check if domain controller is reachable" -ForegroundColor White
        Write-Host "2. Verify DNS resolution" -ForegroundColor White
        Write-Host "3. Check firewall settings (LDAP 389/636)" -ForegroundColor White
        Write-Host "4. Ensure you have domain credentials" -ForegroundColor White
        Write-Host "5. Try using IP address instead of hostname" -ForegroundColor White
        exit 1
    }
    
    Write-Host "`n[+] CONNECTION SUCCESSFUL" -ForegroundColor Green
    foreach ($method in $connectionTest.Methods) {
        Write-Host "  $method" -ForegroundColor Gray
    }
    
    if ($TestOnly) {
        Write-Host "`n[+] Test completed successfully. Use without -TestOnly to run full enumeration." -ForegroundColor Green
        exit 0
    }
    
    # Run full enumeration
    Write-Host "`n[*] Starting full enumeration..." -ForegroundColor Green
    $enumResults = Invoke-SmartEnumeration -Server $DomainController -Credential $Credential -OutputPath $OutputPath
    
    # Also create a BloodHound-compatible JSON if requested
    if ($OutputPath -match "\.json$") {
        $bhPath = $OutputPath -replace "\.json$", "_bloodhound.json"
        Write-Host "`n[*] Creating BloodHound-compatible export..." -ForegroundColor Green
        
        # Create simplified BloodHound data
        $bhData = @{
            meta = @{type="bloodhound"; version="4.1.0"}
            data = @{
                users = @()
                groups = @()
                domains = @()
                relationships = @()
            }
        }
        
        # Add domain
        $bhData.data.domains += @{
            ObjectIdentifier = $enumResults.Data.DomainInfo.DomainSID
            Name = $enumResults.Data.DomainInfo.Name
            Properties = @{
                name = $enumResults.Data.DomainInfo.Name
                domain = $enumResults.Data.DomainInfo.Name
                highvalue = $true
            }
        }
        
        # Add high-value groups
        foreach ($group in $enumResults.Data.HighValueGroups) {
            $bhData.data.groups += @{
                ObjectIdentifier = $group.SID
                Properties = @{
                    name = $group.Name
                    domain = $enumResults.Data.DomainInfo.Name
                    highvalue = $true
                    admincount = $group.AdminCount
                }
            }
        }
        
        # Add admin users and relationships
        $userId = 1000
        foreach ($user in $enumResults.Data.AdminUsers) {
            $userSid = "S-1-5-21-0000000000-0000000000-$userId"
            $userId++
            
            $bhData.data.users += @{
                ObjectIdentifier = $userSid
                Properties = @{
                    name = $user.Username
                    domain = $enumResults.Data.DomainInfo.Name
                    enabled = $true
                    highvalue = $true
                }
            }
            
            # Add relationships
            foreach ($groupName in $user.Groups) {
                $group = $enumResults.Data.HighValueGroups | Where-Object { $_.Name -eq $groupName } | Select-Object -First 1
                if ($group) {
                    $bhData.data.relationships += @{
                        StartNode = $userSid
                        EndNode = $group.SID
                        Relationship = "MemberOf"
                    }
                }
            }
        }
        
        $bhData | ConvertTo-Json -Depth 5 | Out-File -FilePath $bhPath -Encoding UTF8
        Write-Host "[+] BloodHound data saved to: $bhPath" -ForegroundColor Green
    }
    
} catch {
    Write-Host "`n[!] FATAL ERROR: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
    exit 1
}
