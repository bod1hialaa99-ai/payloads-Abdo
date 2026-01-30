# Save this as QuickBloodHound.ps1
param(
    [string]$OutputPath = "bloodhound_quick.json",
    [string]$DomainController,
    [switch]$Stealth
)

Write-Host @"
================================================================================
  ____  _               _   _           _   _               _
 |  _ \| |__   ___  ___| | | |__  _   _| |_| |__   ___   __| |_   _ _ __   ___
 | |_) | '_ \ / _ \/ _ \ | | '_ \| | | | __| '_ \ / _ \ / _' | | | | '_ \ / __|
 |  _ <| | | |  __/  __/ | | | | | |_| | |_| | | | (_) | (_| | |_| | | | | (__
 |_| \_\_| |_|\___|\___|_| |_| |_|\__,_|\__|_| |_|\___/ \__,_|\__,_|_| |_|\___|

                      Quick BloodHound Collector
                      Focused on Domains & Groups
================================================================================
"@ -ForegroundColor Cyan

$startTime = Get-Date
$stats = @{
    Domains = 0
    Groups = 0
    HighValueGroups = 0
    Admins = 0
    Relationships = 0
}

# Initialize JSON structure
$bloodHoundData = @{
    meta = @{
        type = "bloodhound"
        version = "4.1.0"
        count = 0
    }
    data = @{
        users = @()
        computers = @()
        groups = @()
        ous = @()
        domains = @()
        relationships = @()
    }
}

try {
    # ==================== 1. GET DOMAIN INFO ====================
    Write-Host "[*] Getting domain information..." -ForegroundColor Green
    
    # Get domain context
    if ($DomainController) {
        $rootDSE = [ADSI]"LDAP://$DomainController/RootDSE"
    } else {
        $rootDSE = [ADSI]"LDAP://RootDSE"
    }
    
    $domainDN = $rootDSE.defaultNamingContext
    $domainName = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
    
    # Get domain SID
    $domainSearch = [ADSISearcher]"(objectClass=domain)"
    if ($DomainController) {
        $domainSearch.SearchRoot = [ADSI]"LDAP://$DomainController/$domainDN"
    } else {
        $domainSearch.SearchRoot = [ADSI]"LDAP://$domainDN"
    }
    $domainResult = $domainSearch.FindOne()
    
    $domainSid = [System.Security.Principal.SecurityIdentifier]::new($domainResult.Properties.objectsid[0], 0).Value
    
    # Add domain to data
    $bloodHoundData.data.domains += @{
        ObjectIdentifier = $domainSid
        Name = $domainName
        Properties = @{
            name = $domainName
            domain = $domainName
            distinguishedname = $domainDN
            domainsid = $domainSid
            highvalue = $true
        }
    }
    $stats.Domains = 1
    Write-Host "[+] Domain: $domainName" -ForegroundColor Green
    
    # ==================== 2. GET HIGH-VALUE GROUPS ====================
    Write-Host "[*] Getting high-value groups..." -ForegroundColor Green
    
    # Define high-value groups
    $highValueGroupNames = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Print Operators",
        "Server Operators",
        "Domain Controllers",
        "Group Policy Creator Owners",
        "DNS Admins",
        "Enterprise Key Admins",
        "Key Admins",
        "Protected Users",
        "Remote Desktop Users",
        "Hyper-V Administrators",
        "Certificate Service DCOM Access"
    )
    
    foreach ($groupName in $highValueGroupNames) {
        try {
            $groupSearch = [ADSISearcher]"(name=$groupName)"
            if ($DomainController) {
                $groupSearch.SearchRoot = [ADSI]"LDAP://$DomainController/$domainDN"
            } else {
                $groupSearch.SearchRoot = [ADSI]"LDAP://$domainDN"
            }
            $groupSearch.PageSize = 1000
            $groupSearch.PropertiesToLoad.AddRange(@("distinguishedName", "name", "objectSid", "description", "adminCount", "member"))
            
            $groupResult = $groupSearch.FindOne()
            
            if ($groupResult) {
                $groupSid = [System.Security.Principal.SecurityIdentifier]::new($groupResult.Properties.objectsid[0], 0).Value
                
                # Add group to data
                $bloodHoundData.data.groups += @{
                    ObjectIdentifier = $groupSid
                    Properties = @{
                        name = $groupResult.Properties.name[0]
                        distinguishedname = $groupResult.Properties.distinguishedname[0]
                        domain = $domainName
                        domainsid = $domainSid
                        admincount = if ($groupResult.Properties.adminCount) { $groupResult.Properties.adminCount[0] } else { 0 }
                        highvalue = $true
                        description = if ($groupResult.Properties.description) { $groupResult.Properties.description[0] } else { "" }
                    }
                }
                $stats.Groups++
                $stats.HighValueGroups++
                
                Write-Host "  [+] Found: $groupName" -ForegroundColor Yellow
                
                # ==================== 3. GET GROUP MEMBERS ====================
                if ($groupResult.Properties.member) {
                    foreach ($memberDN in $groupResult.Properties.member) {
                        try {
                            $memberSearch = [ADSISearcher]"(distinguishedName=$memberDN)"
                            if ($DomainController) {
                                $memberSearch.SearchRoot = [ADSI]"LDAP://$DomainController/$domainDN"
                            } else {
                                $memberSearch.SearchRoot = [ADSI]"LDAP://$domainDN"
                            }
                            $memberSearch.PropertiesToLoad.AddRange(@("objectSid", "samAccountName", "name", "objectClass"))
                            
                            $memberResult = $memberSearch.FindOne()
                            
                            if ($memberResult) {
                                $memberClass = $memberResult.Properties.objectclass[-1].ToString()
                                $memberSid = [System.Security.Principal.SecurityIdentifier]::new($memberResult.Properties.objectsid[0], 0).Value
                                
                                # Add relationship
                                $bloodHoundData.data.relationships += @{
                                    StartNode = $memberSid
                                    EndNode = $groupSid
                                    Relationship = 'MemberOf'
                                    Properties = @{}
                                }
                                $stats.Relationships++
                                
                                # If member is a user, add to users list
                                if ($memberClass -eq "user") {
                                    $userExists = $bloodHoundData.data.users | Where-Object { $_.ObjectIdentifier -eq $memberSid }
                                    if (-not $userExists) {
                                        $bloodHoundData.data.users += @{
                                            ObjectIdentifier = $memberSid
                                            Properties = @{
                                                name = $memberResult.Properties.samAccountName[0]
                                                domain = $domainName
                                                domainsid = $domainSid
                                                enabled = $true
                                                admincount = 0
                                                highvalue = $true
                                            }
                                        }
                                        $stats.Admins++
                                    }
                                }
                                # If member is a computer
                                elseif ($memberClass -eq "computer") {
                                    $compExists = $bloodHoundData.data.computers | Where-Object { $_.ObjectIdentifier -eq $memberSid }
                                    if (-not $compExists) {
                                        $bloodHoundData.data.computers += @{
                                            ObjectIdentifier = $memberSid
                                            Properties = @{
                                                name = $memberResult.Properties.name[0].ToUpper()
                                                domain = $domainName
                                                domainsid = $domainSid
                                                enabled = $true
                                                highvalue = $false
                                            }
                                        }
                                    }
                                }
                            }
                        } catch {
                            # Skip if member can't be resolved
                        }
                    }
                }
            }
        } catch {
            # Group not found or access denied
        }
    }
    
    # ==================== 4. GET ADMIN-COUNT=1 GROUPS ====================
    if (-not $Stealth) {
        Write-Host "[*] Getting groups with adminCount=1..." -ForegroundColor Green
        
        $adminCountSearch = [ADSISearcher]"(adminCount=1)"
        if ($DomainController) {
            $adminCountSearch.SearchRoot = [ADSI]"LDAP://$DomainController/$domainDN"
        } else {
            $adminCountSearch.SearchRoot = [ADSI]"LDAP://$domainDN"
        }
        $adminCountSearch.PageSize = 1000
        $adminCountSearch.PropertiesToLoad.AddRange(@("distinguishedName", "name", "objectSid", "description", "adminCount"))
        $adminCountSearch.Filter = "(&(objectClass=group)(adminCount=1))"
        
        $adminCountResults = $adminCountSearch.FindAll()
        
        foreach ($groupResult in $adminCountResults) {
            $groupName = $groupResult.Properties.name[0]
            $groupSid = [System.Security.Principal.SecurityIdentifier]::new($groupResult.Properties.objectsid[0], 0).Value
            
            # Skip if already added
            $exists = $bloodHoundData.data.groups | Where-Object { $_.ObjectIdentifier -eq $groupSid }
            if (-not $exists) {
                $bloodHoundData.data.groups += @{
                    ObjectIdentifier = $groupSid
                    Properties = @{
                        name = $groupName
                        distinguishedname = $groupResult.Properties.distinguishedname[0]
                        domain = $domainName
                        domainsid = $domainSid
                        admincount = 1
                        highvalue = $true
                        description = if ($groupResult.Properties.description) { $groupResult.Properties.description[0] } else { "" }
                    }
                }
                $stats.Groups++
                Write-Host "  [+] Admin-Count Group: $groupName" -ForegroundColor Cyan
            }
        }
    }
    
    # ==================== 5. GET DOMAIN CONTROLLERS OU ====================
    Write-Host "[*] Getting Domain Controllers OU..." -ForegroundColor Green
    
    try {
        $dcOUSearch = [ADSISearcher]"(name=Domain Controllers)"
        if ($DomainController) {
            $dcOUSearch.SearchRoot = [ADSI]"LDAP://$DomainController/$domainDN"
        } else {
            $dcOUSearch.SearchRoot = [ADSI]"LDAP://$domainDN"
        }
        $dcOUSearch.Filter = "(objectClass=organizationalUnit)"
        $dcOUSearch.PropertiesToLoad.AddRange(@("distinguishedName", "name", "objectGUID"))
        
        $dcOUResult = $dcOUSearch.FindOne()
        
        if ($dcOUResult) {
            $ouGuid = [System.Guid]::new($dcOUResult.Properties.objectguid[0]).ToString().Replace("-", "").ToLower()
            
            $bloodHoundData.data.ous += @{
                ObjectIdentifier = $ouGuid
                Properties = @{
                    name = $dcOUResult.Properties.name[0]
                    distinguishedname = $dcOUResult.Properties.distinguishedname[0]
                    domain = $domainName
                    domainsid = $domainSid
                    highvalue = $true
                }
            }
            Write-Host "[+] Found Domain Controllers OU" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Could not find Domain Controllers OU" -ForegroundColor Yellow
    }
    
    # ==================== 6. GET ENTERPRISE ADMINS ====================
    # Enterprise Admins are in the forest root domain, might be different from current domain
    Write-Host "[*] Checking for Enterprise Admins..." -ForegroundColor Green
    
    try {
        $enterpriseAdminsSearch = [ADSISearcher]"(name=Enterprise Admins)"
        if ($DomainController) {
            $enterpriseAdminsSearch.SearchRoot = [ADSI]"LDAP://$DomainController/CN=Users,$domainDN"
        } else {
            $enterpriseAdminsSearch.SearchRoot = [ADSI]"LDAP://CN=Users,$domainDN"
        }
        $enterpriseAdminsSearch.PropertiesToLoad.AddRange(@("distinguishedName", "name", "objectSid", "member"))
        
        $eaResult = $enterpriseAdminsSearch.FindOne()
        
        if ($eaResult) {
            $eaSid = [System.Security.Principal.SecurityIdentifier]::new($eaResult.Properties.objectsid[0], 0).Value
            
            # Add if not exists
            $exists = $bloodHoundData.data.groups | Where-Object { $_.ObjectIdentifier -eq $eaSid }
            if (-not $exists) {
                $bloodHoundData.data.groups += @{
                    ObjectIdentifier = $eaSid
                    Properties = @{
                        name = "Enterprise Admins"
                        distinguishedname = $eaResult.Properties.distinguishedname[0]
                        domain = $domainName
                        domainsid = $domainSid
                        admincount = 1
                        highvalue = $true
                        description = "Enterprise Administrators"
                    }
                }
                $stats.Groups++
                Write-Host "[+] Found Enterprise Admins group" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "[-] Enterprise Admins not found in this domain" -ForegroundColor Yellow
    }
    
    # ==================== 7. UPDATE METADATA ====================
    $totalCount = $bloodHoundData.data.users.Count + 
                  $bloodHoundData.data.computers.Count + 
                  $bloodHoundData.data.groups.Count + 
                  $bloodHoundData.data.ous.Count + 
                  $bloodHoundData.data.domains.Count
    
    $bloodHoundData.meta.count = $totalCount
    
    # ==================== 8. SAVE TO JSON ====================
    Write-Host "[*] Saving to JSON file..." -ForegroundColor Green
    $json = $bloodHoundData | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # ==================== 9. DISPLAY SUMMARY ====================
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
    Write-Host "[+] COLLECTION COMPLETE!" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Cyan
    Write-Host "Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor White
    Write-Host "Output File: $OutputPath" -ForegroundColor White
    Write-Host "`nStatistics:" -ForegroundColor Yellow
    Write-Host "  Domains: $($stats.Domains)" -ForegroundColor White
    Write-Host "  Groups (Total): $($stats.Groups)" -ForegroundColor White
    Write-Host "  High-Value Groups: $($stats.HighValueGroups)" -ForegroundColor White
    Write-Host "  Admin Users Found: $($stats.Admins)" -ForegroundColor White
    Write-Host "  Relationships: $($stats.Relationships)" -ForegroundColor White
    Write-Host "  Total Objects: $totalCount" -ForegroundColor White
    Write-Host "`n[+] File ready for BloodHound import!" -ForegroundColor Green
    Write-Host "    Open BloodHound -> Upload Data -> Select $OutputPath" -ForegroundColor Cyan
    
} catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
    Write-Host "[!] Make sure you're running as a domain user" -ForegroundColor Yellow
    Write-Host "[!] Try specifying a domain controller: .\QuickBloodHound.ps1 -DomainController DC01" -ForegroundColor Yellow
}
