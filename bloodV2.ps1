# Advanced AD Bloodhound Enumeration Script
# Version: 3.0 - Official BloodHound JSON Format
# Features: Multi-domain support, correct BloodHound JSON structure
# Requirements: Microsoft.ActiveDirectory.Management.dll only (no RSAT tools)

param(
    [Parameter(Mandatory = $true)]
    [string[]]$Domains,
    
    [string]$OutputPath = ".\Bloodhound_Data",
    
    [switch]$SkipACLs,
    
    [switch]$VerboseOutput,
    
    [string]$SearchBase,
    
    [switch]$FindAttackPaths,
    
    [string]$ADModulePath = $null
)

# Function to create directory if it doesn't exist
function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# Function to load AD module from DLL if not already loaded
function Load-ADModule {
    param([string]$CustomPath = $null)
    
    if (Get-Module -Name ActiveDirectory) {
        Write-Host "[+] ActiveDirectory module already loaded" -ForegroundColor Green
        return $true
    }
    
    if ($CustomPath -and (Test-Path $CustomPath)) {
        try {
            Write-Host "[*] Loading AD module from: $CustomPath" -ForegroundColor Yellow
            Import-Module $CustomPath -ErrorAction Stop
            Write-Host "[+] Successfully loaded AD module from custom path" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning ("[!] Failed to load from custom path: {0}" -f $_)
        }
    }
    
    $possiblePaths = @(
        ".\Microsoft.ActiveDirectory.Management.dll",
        ".\ActiveDirectory\Microsoft.ActiveDirectory.Management.dll",
        "C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\Microsoft.ActiveDirectory.Management.dll"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            try {
                Write-Host "[*] Loading AD module from: $path" -ForegroundColor Yellow
                Add-Type -Path $path -ErrorAction Stop
                Import-Module ActiveDirectory -ErrorAction Stop
                Write-Host "[+] Successfully loaded AD module" -ForegroundColor Green
                return $true
            }
            catch {
                continue
            }
        }
    }
    
    Write-Error "[!] ActiveDirectory module could not be loaded"
    Write-Host "`nDownload AD module files from:" -ForegroundColor Yellow
    Write-Host "https://github.com/samratashok/ADModule" -ForegroundColor Cyan
    return $false
}

# Function to convert DateTime to Bloodhound timestamp format
function ConvertTo-BloodhoundTime {
    param([datetime]$DateTime)
    if ($DateTime -eq $null) { return 0 }
    try {
        return [Math]::Floor([decimal](Get-Date($DateTime).ToUniversalTime().Subtract((Get-Date "1/1/1601").ToUniversalTime()).TotalSeconds))
    }
    catch { return 0 }
}

# Function to get SID string
function Get-SidString {
    param([byte[]]$SidBytes)
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidBytes, 0)
        return $sid.Value
    }
    catch { return $null }
}

# Function to get Domain SID
function Get-DomainSid {
    param([string]$Domain)
    try {
        if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
            $domainObj = Get-ADDomain -Server $Domain
            return $domainObj.DomainSID.Value
        }
        else {
            $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            $searcher = New-Object DirectoryServices.DirectorySearcher($dn)
            $searcher.Filter = "(objectClass=domainDNS)"
            $result = $searcher.FindOne()
            
            if ($result -and $result.Properties["objectSid"]) {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($result.Properties["objectSid"][0], 0)
                return $sid.Value
            }
        }
    }
    catch {
        Write-Warning ("Failed to get domain SID for {0}: {1}" -f $Domain, $_)
    }
    return $null
}

# ==================== DATA COLLECTION FUNCTIONS ====================

# Function to enumerate Domains
function Get-DomainObjects {
    param([string]$Domain)
    
    $domains = @()
    
    Write-Host "[*] Enumerating domain: $Domain" -ForegroundColor Green
    
    try {
        $domainSid = Get-DomainSid -Domain $Domain
        if (-not $domainSid) {
            Write-Warning "[!] Could not get domain SID for $Domain"
            return $domains
        }
        
        $domainInfo = $null
        if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
            $domainInfo = Get-ADDomain -Server $Domain
        }
        else {
            $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            $searcher = New-Object DirectoryServices.DirectorySearcher($dn)
            $searcher.Filter = "(objectClass=domainDNS)"
            $searcher.PropertiesToLoad.Add("dc") | Out-Null
            $result = $searcher.FindOne()
            
            if ($result) {
                $domainInfo = @{
                    DNSRoot = if ($result.Properties["dc"]) { $result.Properties["dc"][0] } else { $Domain }
                    DistinguishedName = $result.Path.Substring($result.Path.IndexOf("DC="))
                }
            }
        }
        
        if ($domainInfo) {
            $domains += @{
                ObjectIdentifier = $domainSid
                Properties = @{
                    name = if ($domainInfo.DNSRoot) { $domainInfo.DNSRoot.ToUpper() } else { $Domain.ToUpper() }
                    domainsid = $domainSid
                    distinguishedname = if ($domainInfo.DistinguishedName) { $domainInfo.DistinguishedName } else { "DC=" + $Domain.Replace(".", ",DC=") }
                    highvalue = $true
                }
            }
        }
    }
    catch {
        Write-Warning ("[!] Failed to enumerate domain {0}: {1}" -f $Domain, $_)
    }
    
    return $domains
}

# Function to enumerate Users
function Get-UserObjects {
    param([string]$Domain, [string]$SearchBase)
    
    $users = @()
    
    Write-Host "[*] Enumerating users in $Domain" -ForegroundColor Cyan
    
    try {
        $userList = @()
        
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
            $params = @{
                Filter = "*"
                Properties = @("SamAccountName", "DistinguishedName", "Enabled", "SID", "AdminCount", 
                             "PasswordNeverExpires", "PasswordLastSet", "LastLogonDate", "LastLogonTimestamp",
                             "ServicePrincipalNames", "EmailAddress", "Description", "DisplayName")
                Server = $Domain
            }
            
            if ($SearchBase) {
                $params.SearchBase = $SearchBase
                Write-Host "  [>] Using SearchBase: $SearchBase" -ForegroundColor DarkGray
            }
            
            $userList = Get-ADUser @params
        }
        else {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
            $searcher.PageSize = 1000
            
            if ($SearchBase) {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/$SearchBase")
            }
            else {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            }
            
            $properties = @("samaccountname", "distinguishedname", "useraccountcontrol", "objectsid", 
                          "admincount", "pwdlastset", "lastlogon", "lastlogontimestamp", 
                          "serviceprincipalname", "mail", "description", "displayname")
            
            foreach ($prop in $properties) {
                $searcher.PropertiesToLoad.Add($prop) | Out-Null
            }
            
            $userList = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($userList.Count) users" -ForegroundColor DarkGray
        
        foreach ($user in $userList) {
            $userId = $null
            $samAccountName = $null
            $distinguishedName = $null
            
            if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
                $userId = $user.SID.Value
                $samAccountName = $user.SamAccountName
                $distinguishedName = $user.DistinguishedName
                $enabled = $user.Enabled
                $adminCount = if ($user.AdminCount) { $true } else { $false }
                $pwdLastSet = $user.PasswordLastSet
                $lastLogon = $user.LastLogonDate
                $lastLogonTimestamp = $user.LastLogonTimestamp
                $spns = @($user.ServicePrincipalNames)
                $description = $user.Description
                $displayName = $user.DisplayName
                $email = $user.EmailAddress
            }
            else {
                $sidBytes = $user.Properties["objectsid"][0]
                $userId = Get-SidString $sidBytes
                $samAccountName = $user.Properties["samaccountname"][0]
                $distinguishedName = $user.Properties["distinguishedname"][0]
                
                $uac = [int]$user.Properties["useraccountcontrol"][0]
                $enabled = (-not ($uac -band 2))
                
                $adminCount = if ($user.Properties["admincount"]) { [int]$user.Properties["admincount"][0] -eq 1 } else { $false }
                $pwdLastSet = if ($user.Properties["pwdlastset"]) { [datetime]::FromFileTime([int64]$user.Properties["pwdlastset"][0]) } else { $null }
                $lastLogon = if ($user.Properties["lastlogon"]) { [datetime]::FromFileTime([int64]$user.Properties["lastlogon"][0]) } else { $null }
                $lastLogonTimestamp = if ($user.Properties["lastlogontimestamp"]) { [datetime]::FromFileTime([int64]$user.Properties["lastlogontimestamp"][0]) } else { $null }
                $spns = if ($user.Properties["serviceprincipalname"]) { @($user.Properties["serviceprincipalname"]) } else { @() }
                $description = if ($user.Properties["description"]) { $user.Properties["description"][0] } else { $null }
                $displayName = if ($user.Properties["displayname"]) { $user.Properties["displayname"][0] } else { $samAccountName }
                $email = if ($user.Properties["mail"]) { $user.Properties["mail"][0] } else { $null }
            }
            
            if (-not $userId) { continue }
            
            $users += @{
                ObjectIdentifier = $userId
                Properties = @{
                    samaccountname = $samAccountName
                    name = $displayName
                    distinguishedname = $distinguishedName
                    domain = $Domain.ToUpper()
                    enabled = $enabled
                    admincount = $adminCount
                    pwdneverexpires = if ($pwdLastSet -eq $null) { $false } else { $true }
                    pwdlastset = ConvertTo-BloodhoundTime $pwdLastSet
                    lastlogon = ConvertTo-BloodhoundTime $lastLogon
                    lastlogontimestamp = ConvertTo-BloodhoundTime $lastLogonTimestamp
                    serviceprincipalnames = $spns
                    email = $email
                    description = $description
                    highvalue = $adminCount -or ($samAccountName -eq "Administrator")
                }
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate users: $_"
    }
    
    return $users
}

# Function to enumerate Computers
function Get-ComputerObjects {
    param([string]$Domain, [string]$SearchBase)
    
    $computers = @()
    
    Write-Host "[*] Enumerating computers in $Domain" -ForegroundColor Cyan
    
    try {
        $computerList = @()
        
        if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
            $params = @{
                Filter = "*"
                Properties = @("Name", "DNSHostName", "DistinguishedName", "Enabled", "SID", 
                             "OperatingSystem", "OperatingSystemVersion", "LastLogonDate", 
                             "LastLogonTimestamp", "PasswordLastSet", "ServicePrincipalNames", 
                             "TrustedForDelegation", "Description")
                Server = $Domain
            }
            
            if ($SearchBase) {
                $params.SearchBase = $SearchBase
            }
            
            $computerList = Get-ADComputer @params
        }
        else {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(objectCategory=computer)"
            $searcher.PageSize = 1000
            
            if ($SearchBase) {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/$SearchBase")
            }
            else {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            }
            
            $properties = @("name", "dnshostname", "distinguishedname", "useraccountcontrol", 
                          "objectsid", "operatingsystem", "operatingsystemversion", 
                          "lastlogon", "lastlogontimestamp", "pwdlastset", 
                          "serviceprincipalname", "trustedfordelegation", "description")
            
            foreach ($prop in $properties) {
                $searcher.PropertiesToLoad.Add($prop) | Out-Null
            }
            
            $computerList = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($computerList.Count) computers" -ForegroundColor DarkGray
        
        foreach ($computer in $computerList) {
            $computerId = $null
            $computerName = $null
            $dnsHostName = $null
            
            if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
                $computerId = $computer.SID.Value
                $computerName = $computer.Name
                $dnsHostName = $computer.DNSHostName
                $distinguishedName = $computer.DistinguishedName
                $enabled = $computer.Enabled
                $unconstrainedDelegation = $computer.TrustedForDelegation
                $os = $computer.OperatingSystem
                $osVersion = $computer.OperatingSystemVersion
                $lastLogon = $computer.LastLogonDate
                $lastLogonTimestamp = $computer.LastLogonTimestamp
                $pwdLastSet = $computer.PasswordLastSet
                $spns = @($computer.ServicePrincipalNames)
                $description = $computer.Description
            }
            else {
                $sidBytes = $computer.Properties["objectsid"][0]
                $computerId = Get-SidString $sidBytes
                $computerName = $computer.Properties["name"][0]
                $dnsHostName = if ($computer.Properties["dnshostname"]) { $computer.Properties["dnshostname"][0] } else { $computerName }
                $distinguishedName = $computer.Properties["distinguishedname"][0]
                
                $uac = if ($computer.Properties["useraccountcontrol"]) { [int]$computer.Properties["useraccountcontrol"][0] } else { 0 }
                $enabled = (-not ($uac -band 2))
                $unconstrainedDelegation = ($uac -band 524288) -eq 524288
                
                $os = if ($computer.Properties["operatingsystem"]) { $computer.Properties["operatingsystem"][0] } else { $null }
                $osVersion = if ($computer.Properties["operatingsystemversion"]) { $computer.Properties["operatingsystemversion"][0] } else { $null }
                $lastLogon = if ($computer.Properties["lastlogon"]) { [datetime]::FromFileTime([int64]$computer.Properties["lastlogon"][0]) } else { $null }
                $lastLogonTimestamp = if ($computer.Properties["lastlogontimestamp"]) { [datetime]::FromFileTime([int64]$computer.Properties["lastlogontimestamp"][0]) } else { $null }
                $pwdLastSet = if ($computer.Properties["pwdlastset"]) { [datetime]::FromFileTime([int64]$computer.Properties["pwdlastset"][0]) } else { $null }
                $spns = if ($computer.Properties["serviceprincipalname"]) { @($computer.Properties["serviceprincipalname"]) } else { @() }
                $description = if ($computer.Properties["description"]) { $computer.Properties["description"][0] } else { $null }
            }
            
            if (-not $computerId) { continue }
            
            $computers += @{
                ObjectIdentifier = $computerId
                Properties = @{
                    name = if ($dnsHostName) { $dnsHostName.ToUpper() } else { $computerName.ToUpper() }
                    distinguishedname = $distinguishedName
                    domain = $Domain.ToUpper()
                    samaccountname = $computerName + "$"
                    enabled = $enabled
                    operatingsystem = $os
                    operatingsystemversion = $osVersion
                    lastlogon = ConvertTo-BloodhoundTime $lastLogon
                    lastlogontimestamp = ConvertTo-BloodhoundTime $lastLogonTimestamp
                    pwdlastset = ConvertTo-BloodhoundTime $pwdLastSet
                    serviceprincipalnames = $spns
                    unconstraineddelegation = $unconstrainedDelegation
                    description = $description
                    highvalue = $unconstrainedDelegation
                }
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate computers: $_"
    }
    
    return $computers
}

# Function to enumerate Groups
function Get-GroupObjects {
    param([string]$Domain, [string]$SearchBase)
    
    $groups = @()
    
    Write-Host "[*] Enumerating groups in $Domain" -ForegroundColor Cyan
    
    try {
        $groupList = @()
        
        if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {
            $params = @{
                Filter = "*"
                Properties = @("SamAccountName", "DistinguishedName", "SID", "AdminCount", "Description")
                Server = $Domain
            }
            
            if ($SearchBase) {
                $params.SearchBase = $SearchBase
            }
            
            $groupList = Get-ADGroup @params
        }
        else {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(objectCategory=group)"
            $searcher.PageSize = 1000
            
            if ($SearchBase) {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/$SearchBase")
            }
            else {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            }
            
            $properties = @("samaccountname", "distinguishedname", "objectsid", "admincount", "description")
            
            foreach ($prop in $properties) {
                $searcher.PropertiesToLoad.Add($prop) | Out-Null
            }
            
            $groupList = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($groupList.Count) groups" -ForegroundColor DarkGray
        
        foreach ($group in $groupList) {
            $groupId = $null
            $groupName = $null
            
            if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {
                $groupId = $group.SID.Value
                $groupName = $group.SamAccountName
                $distinguishedName = $group.DistinguishedName
                $adminCount = if ($group.AdminCount) { $true } else { $false }
                $description = $group.Description
            }
            else {
                $sidBytes = $group.Properties["objectsid"][0]
                $groupId = Get-SidString $sidBytes
                $groupName = $group.Properties["samaccountname"][0]
                $distinguishedName = $group.Properties["distinguishedname"][0]
                $adminCount = if ($group.Properties["admincount"]) { [int]$group.Properties["admincount"][0] -eq 1 } else { $false }
                $description = if ($group.Properties["description"]) { $group.Properties["description"][0] } else { $null }
            }
            
            if (-not $groupId) { continue }
            
            $groups += @{
                ObjectIdentifier = $groupId
                Properties = @{
                    name = $groupName.ToUpper()
                    distinguishedname = $distinguishedName
                    domain = $Domain.ToUpper()
                    samaccountname = $groupName
                    admincount = $adminCount
                    description = $description
                    highvalue = ($groupName -like "*Domain Admins*") -or 
                               ($groupName -like "*Enterprise Admins*") -or
                               ($groupName -like "*Schema Admins*") -or
                               ($adminCount -eq $true)
                }
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate groups: $_"
    }
    
    return $groups
}

# Function to enumerate OUs
function Get-OUObjects {
    param([string]$Domain)
    
    $ous = @()
    
    Write-Host "[*] Enumerating OUs in $Domain" -ForegroundColor Cyan
    
    try {
        $ouList = @()
        
        if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {
            $ouList = Get-ADOrganizationalUnit -Filter * -Properties * -Server $Domain
        }
        else {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(objectCategory=organizationalUnit)"
            $searcher.PageSize = 1000
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            
            $properties = @("name", "distinguishedname", "objectguid", "description")
            
            foreach ($prop in $properties) {
                $searcher.PropertiesToLoad.Add($prop) | Out-Null
            }
            
            $ouList = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($ouList.Count) OUs" -ForegroundColor DarkGray
        
        foreach ($ou in $ouList) {
            $ouGuid = $null
            $ouName = $null
            
            if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {
                $ouGuid = [guid]::Parse($ou.ObjectGUID).ToString()
                $ouName = $ou.Name
                $distinguishedName = $ou.DistinguishedName
                $description = $ou.Description
            }
            else {
                if ($ou.Properties["objectguid"]) {
                    $ouGuid = [guid]::new($ou.Properties["objectguid"][0]).ToString()
                }
                else {
                    $ouGuid = [guid]::NewGuid().ToString()
                }
                $ouName = $ou.Properties["name"][0]
                $distinguishedName = $ou.Properties["distinguishedname"][0]
                $description = if ($ou.Properties["description"]) { $ou.Properties["description"][0] } else { $null }
            }
            
            $ouId = "OU:" + $ouGuid
            
            $ous += @{
                ObjectIdentifier = $ouId
                Properties = @{
                    name = $ouName.ToUpper()
                    distinguishedname = $distinguishedName
                    domain = $Domain.ToUpper()
                    guid = $ouGuid
                    description = $description
                }
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate OUs: $_"
    }
    
    return $ous
}

# Function to create BloodHound JSON files with correct format
function Save-BloodhoundJson {
    param(
        [string]$OutputPath,
        [array]$Data,
        [string]$DataType,
        [int]$Methods = 127999
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "$DataType`_$timestamp.json"
    $filePath = Join-Path $OutputPath $fileName
    
    $output = @{
        data = $Data
        meta = @{
            methods = $Methods
            type = $DataType
            count = $Data.Count
            version = 5
        }
    }
    
    $output | ConvertTo-Json -Depth 10 | Out-File $filePath -Encoding UTF8
    
    return @{
        Path = $filePath
        Count = $Data.Count
    }
}

# ==================== MAIN SCRIPT ====================

function Main {
    # Load AD module
    if (-not (Load-ADModule -CustomPath $ADModulePath)) {
        return
    }
    
    # Create output directory
    Ensure-Directory $OutputPath
    
    # Initialize data arrays
    $allDomains = @()
    $allUsers = @()
    $allComputers = @()
    $allGroups = @()
    $allOUs = @()
    
    $processedDomains = @()
    
    foreach ($domain in $Domains) {
        try {
            Write-Host "`n" + ("=" * 50) -ForegroundColor Green
            Write-Host "PROCESSING DOMAIN: $domain" -ForegroundColor Green
            Write-Host ("=" * 50) -ForegroundColor Green
            
            # Test domain connectivity
            Write-Host "[*] Testing connectivity to $domain..." -ForegroundColor Gray
            try {
                $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain")
                $test = $dn.Name
                Write-Host "[+] Successfully connected to $domain" -ForegroundColor Green
            }
            catch {
                Write-Warning ("[!] Could not connect to {0}: {1}" -f $domain, $_)
                continue
            }
            
            # Collect domain data
            Write-Host "[*] Collecting domain data..." -ForegroundColor Gray
            $domainObjects = Get-DomainObjects -Domain $domain
            $allDomains += $domainObjects
            
            # Collect user data
            Write-Host "[*] Collecting user data..." -ForegroundColor Gray
            $userObjects = Get-UserObjects -Domain $domain -SearchBase $SearchBase
            $allUsers += $userObjects
            
            # Collect computer data
            Write-Host "[*] Collecting computer data..." -ForegroundColor Gray
            $computerObjects = Get-ComputerObjects -Domain $domain -SearchBase $SearchBase
            $allComputers += $computerObjects
            
            # Collect group data
            Write-Host "[*] Collecting group data..." -ForegroundColor Gray
            $groupObjects = Get-GroupObjects -Domain $domain -SearchBase $SearchBase
            $allGroups += $groupObjects
            
            # Collect OU data
            Write-Host "[*] Collecting OU data..." -ForegroundColor Gray
            $ouObjects = Get-OUObjects -Domain $domain
            $allOUs += $ouObjects
            
            $processedDomains += $domain
            Write-Host "[+] Successfully processed domain: $domain" -ForegroundColor Green
            
        }
        catch {
            Write-Error ("[!] Failed to process domain '{0}': {1}" -f $domain, $_)
            continue
        }
    }
    
    if ($processedDomains.Count -eq 0) {
        Write-Error "[!] No domains were successfully processed. Exiting."
        return
    }
    
    # Save all data to BloodHound JSON files
    Write-Host "`n" + ("=" * 50) -ForegroundColor Green
    Write-Host "SAVING BLOODHOUND JSON FILES" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Green
    
    $results = @()
    
    # Save domains
    if ($allDomains.Count -gt 0) {
        $result = Save-BloodhoundJson -OutputPath $OutputPath -Data $allDomains -DataType "domains"
        $results += $result
    }
    
    # Save users
    if ($allUsers.Count -gt 0) {
        $result = Save-BloodhoundJson -OutputPath $OutputPath -Data $allUsers -DataType "users"
        $results += $result
    }
    
    # Save computers
    if ($allComputers.Count -gt 0) {
        $result = Save-BloodhoundJson -OutputPath $OutputPath -Data $allComputers -DataType "computers"
        $results += $result
    }
    
    # Save groups
    if ($allGroups.Count -gt 0) {
        $result = Save-BloodhoundJson -OutputPath $OutputPath -Data $allGroups -DataType "groups"
        $results += $result
    }
    
    # Save OUs
    if ($allOUs.Count -gt 0) {
        $result = Save-BloodhoundJson -OutputPath $OutputPath -Data $allOUs -DataType "ous"
        $results += $result
    }
    
    # Display summary
    Write-Host "`n" + ("=" * 50) -ForegroundColor Green
    Write-Host "ENUMERATION COMPLETE!" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Green
    
    Write-Host "`nSUMMARY:" -ForegroundColor Yellow
    Write-Host "  Domains processed: $($processedDomains -join ', ')" -ForegroundColor Cyan
    Write-Host "`n  Objects enumerated:" -ForegroundColor Cyan
    
    $totalObjects = 0
    foreach ($result in $results) {
        $type = [System.IO.Path]::GetFileNameWithoutExtension($result.Path) -replace '_\d{8}_\d{6}', ''
        Write-Host "    - $($type): $($result.Count)" -ForegroundColor White
        $totalObjects += $result.Count
    }
    
    Write-Host "`n  Total objects: $totalObjects" -ForegroundColor Green
    
    Write-Host "`nOUTPUT FILES:" -ForegroundColor Yellow
    foreach ($result in $results) {
        $fileName = [System.IO.Path]::GetFileName($result.Path)
        Write-Host "  - $fileName" -ForegroundColor Cyan
    }
    
    Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  1. Import JSON files into BloodHound:" -ForegroundColor White
    Write-Host "     - Open BloodHound GUI" -ForegroundColor Cyan
    Write-Host "     - Go to 'Administration' → 'File Ingest'" -ForegroundColor Cyan
    Write-Host "     - Upload ALL generated JSON files" -ForegroundColor Cyan
    
    Write-Host "`n  2. Verify JSON structure:" -ForegroundColor White
    Write-Host "     - Each file should have 'data' and 'meta' objects" -ForegroundColor Cyan
    Write-Host "     - 'meta.type' must match the file content" -ForegroundColor Cyan
    Write-Host "     - 'meta.version' should be 5" -ForegroundColor Cyan
    
    Write-Host "`n  3. Sample JSON structure:" -ForegroundColor White
    Write-Host '     {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-...",
                "Properties": { ... }
            }
        ],
        "meta": {
            "methods": 127999,
            "type": "users",
            "count": 100,
            "version": 5
        }
    }' -ForegroundColor Gray
}

# Execute main function
try {
    Main
}
catch {
    Write-Error ("[!] Script execution failed: {0}" -f $_)
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Check domain connectivity" -ForegroundColor White
    Write-Host "2. Ensure AD module is loaded" -ForegroundColor White
    Write-Host "3. Verify JSON files at: https://jsonlint.com/" -ForegroundColor White
}
