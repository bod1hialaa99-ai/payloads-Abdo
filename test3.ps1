# Advanced AD Bloodhound Enumeration Script
# Version: 2.1 - Native AD Module Only (No RSAT Required)
# Features: Multi-domain support, attack path discovery, trust enumeration
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
    
    # Check if AD module is already loaded
    if (Get-Module -Name ActiveDirectory) {
        Write-Host "[+] ActiveDirectory module already loaded" -ForegroundColor Green
        return $true
    }
    
    # Try to load from custom path if provided
    if ($CustomPath -and (Test-Path $CustomPath)) {
        try {
            Write-Host "[*] Loading AD module from: $CustomPath" -ForegroundColor Yellow
            Import-Module $CustomPath -ErrorAction Stop
            Write-Host "[+] Successfully loaded AD module from custom path" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Warning "[!] Failed to load from custom path: $_"
        }
    }
    
    # Try default locations
    $possiblePaths = @(
        ".\Microsoft.ActiveDirectory.Management.dll",
        ".\ActiveDirectory\Microsoft.ActiveDirectory.Management.dll",
        "C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management\Microsoft.ActiveDirectory.Management.dll",
        "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\Microsoft.ActiveDirectory.Management\Microsoft.ActiveDirectory.Management.dll",
        "C:\Windows\assembly\GAC_64\Microsoft.ActiveDirectory.Management\Microsoft.ActiveDirectory.Management.dll"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            try {
                Write-Host "[*] Loading AD module from: $path" -ForegroundColor Yellow
                Add-Type -Path $path -ErrorAction Stop
                
                # Try to import the module
                Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
                Write-Host "[+] Successfully loaded AD module" -ForegroundColor Green
                return $true
            }
            catch {
                Write-Warning "[!] Failed to load from $path : $_"
                continue
            }
        }
    }
    
    # Last attempt - create minimal module
    Write-Host "[*] Creating minimal AD module wrapper..." -ForegroundColor Yellow
    try {
        # Try to find the DLL in common locations
        $dllPath = $null
        $searchPaths = @(
            ".\",
            ".\ActiveDirectory\",
            "C:\Temp\",
            "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory\"
        )
        
        foreach ($searchPath in $searchPaths) {
            $testPath = Join-Path $searchPath "Microsoft.ActiveDirectory.Management.dll"
            if (Test-Path $testPath) {
                $dllPath = $testPath
                break
            }
        }
        
        if ($dllPath) {
            Write-Host "[*] Found AD DLL at: $dllPath" -ForegroundColor Green
            # Load the assembly
            [System.Reflection.Assembly]::LoadFrom($dllPath) | Out-Null
            
            # Create a minimal module
            $moduleScript = @'
# Minimal AD Module Wrapper
function Get-ADObject {
    param(
        [string]$Filter,
        [string[]]$Properties,
        [string]$SearchBase,
        [string]$Server,
        [string]$Identity
    )
    
    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = $Filter
    
    if ($Properties) {
        foreach ($prop in $Properties) {
            $searcher.PropertiesToLoad.Add($prop) | Out-Null
        }
    }
    
    if ($SearchBase) {
        $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$SearchBase")
        $searcher.SearchRoot = $dn
    }
    else {
        $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server")
        $searcher.SearchRoot = $dn
    }
    
    $results = $searcher.FindAll()
    return $results
}

function Get-ADDomain {
    param([string]$Server)
    
    $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server")
    $searcher = New-Object DirectoryServices.DirectorySearcher($dn)
    $searcher.Filter = "(objectClass=domainDNS)"
    $result = $searcher.FindOne()
    
    if ($result) {
        return @{
            DNSRoot = $result.Properties["dc"][0]
            DistinguishedName = $result.Path.Substring($result.Path.IndexOf("DC="))
            DomainSID = @{ Value = (New-Object System.Security.Principal.SecurityIdentifier($result.Properties["objectSid"][0],0)).Value }
        }
    }
    return $null
}
'@
            
            # Execute the module script
            Invoke-Expression $moduleScript
            Write-Host "[+] Created minimal AD module wrapper" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Error "[!] Could not create AD module wrapper: $_"
    }
    
    Write-Error "[!] ActiveDirectory module could not be loaded. Please provide path to Microsoft.ActiveDirectory.Management.dll using -ADModulePath parameter"
    Write-Host "`nHow to get the AD module files:" -ForegroundColor Yellow
    Write-Host "1. Copy these 4 files from a system with RSAT or download from:" -ForegroundColor White
    Write-Host "   https://github.com/samratashok/ADModule" -ForegroundColor Cyan
    Write-Host "   - Microsoft.ActiveDirectory.Management.dll" -ForegroundColor White
    Write-Host "   - ActiveDirectory.psd1" -ForegroundColor White
    Write-Host "   - ActiveDirectory.Format.ps1xml" -ForegroundColor White
    Write-Host "   - ActiveDirectory.Types.ps1xml" -ForegroundColor White
    Write-Host "2. Place them in a folder and use: -ADModulePath '.\ActiveDirectory.psd1'" -ForegroundColor White
    return $false
}

# Function to convert DateTime to Bloodhound timestamp format
function ConvertTo-BloodhoundTime {
    param([datetime]$DateTime)
    if ($DateTime -eq $null) { return 0 }
    return [Math]::Floor([decimal](Get-Date($DateTime).ToUniversalTime().Subtract((Get-Date "1/1/1601").ToUniversalTime()).TotalSeconds))
}

# Function to get SID string
function Get-SidString {
    param([byte[]]$SidBytes)
    try {
        $sid = [System.Security.Principal.SecurityIdentifier]::new($SidBytes, 0)
        return $sid.Value
    }
    catch {
        return $null
    }
}

# Function to get Domain SID using native methods
function Get-DomainSid {
    param([string]$Domain)
    try {
        # Try using AD module first
        if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
            $domainObj = Get-ADDomain -Server $Domain
            return $domainObj.DomainSID.Value
        }
        else {
            # Fallback to LDAP query
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
        Write-Warning "Failed to get domain SID for $Domain: $_"
    }
    return $null
}

# Function to enumerate Domain information
function Get-DomainData {
    param([string]$Domain)
    
    $domainData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating domain: $Domain" -ForegroundColor Green
    
    try {
        $domainSid = Get-DomainSid -Domain $Domain
        if (-not $domainSid) {
            Write-Warning "[!] Could not get domain SID for $Domain"
            return $domainData
        }
        
        # Get basic domain info
        $domainInfo = $null
        if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
            $domainInfo = Get-ADDomain -Server $Domain
        }
        else {
            # Fallback LDAP query
            $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            $searcher = New-Object DirectoryServices.DirectorySearcher($dn)
            $searcher.Filter = "(objectClass=domainDNS)"
            $searcher.PropertiesToLoad.Add("dc") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $result = $searcher.FindOne()
            
            if ($result) {
                $domainInfo = @{
                    DNSRoot = if ($result.Properties["dc"]) { $result.Properties["dc"][0] } else { $Domain }
                    DistinguishedName = $result.Path.Substring($result.Path.IndexOf("DC="))
                }
            }
        }
        
        if ($domainInfo) {
            # Add domain node
            $domainData.nodes += @{
                type = "Domain"
                objectid = $domainSid
                properties = @{
                    name = if ($domainInfo.DNSRoot) { $domainInfo.DNSRoot.ToUpper() } else { $Domain.ToUpper() }
                    domainsid = $domainSid
                    distinguishedname = if ($domainInfo.DistinguishedName) { $domainInfo.DistinguishedName } else { "DC=" + $Domain.Replace(".", ",DC=") }
                    highvalue = $true
                }
            }
        }
    }
    catch {
        Write-Warning "[!] Failed to enumerate domain $Domain: $_"
    }
    
    return $domainData
}

# Function to enumerate Trust Relationships using native methods
function Get-TrustData {
    param([string]$Domain)
    
    $trustData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "  [>] Enumerating trust relationships..." -ForegroundColor DarkGray
    
    try {
        if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {
            $trusts = Get-ADTrust -Filter * -Server $Domain
            
            foreach ($trust in $trusts) {
                $trustData.relationships += @{
                    type = "TrustedBy"
                    from = $trust.Target
                    to = $trust.Source
                    properties = @{
                        trusttype = $trust.TrustType.ToString()
                        direction = $trust.Direction.ToString()
                        transitive = $trust.IsTransitive
                    }
                }
            }
        }
        else {
            # LDAP fallback for trust enumeration
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(objectClass=trustedDomain)"
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            
            $trusts = $searcher.FindAll()
            foreach ($trust in $trusts) {
                $trustData.relationships += @{
                    type = "TrustedBy"
                    from = $trust.Properties["trustPartner"][0]
                    to = $Domain
                    properties = @{
                        trusttype = "Unknown"
                        direction = "Bidirectional"
                        transitive = $true
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate trusts: $_"
    }
    
    return $trustData
}

# Function to enumerate Users with native methods
function Get-UserData {
    param([string]$Domain, [string]$DomainSid, [string]$SearchBase)
    
    $userData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating users in $Domain" -ForegroundColor Cyan
    
    try {
        $users = @()
        
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
            $params = @{
                Filter = "*"
                Properties = @("SamAccountName", "DistinguishedName", "Enabled", "SID", "AdminCount", 
                             "PasswordNeverExpires", "PasswordLastSet", "LastLogonDate", "LastLogonTimestamp",
                             "SIDHistory", "ServicePrincipalNames", "EmailAddress", "Title", "Department", "Description")
                Server = $Domain
            }
            
            if ($SearchBase) {
                $params.SearchBase = $SearchBase
                Write-Host "  [>] Using SearchBase: $SearchBase" -ForegroundColor DarkGray
            }
            
            $users = Get-ADUser @params
        }
        else {
            # LDAP fallback
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
            $searcher.PageSize = 1000
            
            if ($SearchBase) {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain/$SearchBase")
            }
            else {
                $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            }
            
            # Add properties to load
            $properties = @("samaccountname", "distinguishedname", "useraccountcontrol", "objectsid", 
                          "admincount", "pwdlastset", "lastlogon", "lastlogontimestamp", 
                          "sidhistory", "serviceprincipalname", "mail", "title", "department", "description")
            
            foreach ($prop in $properties) {
                $searcher.PropertiesToLoad.Add($prop) | Out-Null
            }
            
            $users = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($users.Count) users" -ForegroundColor DarkGray
        
        $count = 0
        foreach ($user in $users) {
            $count++
            if ($VerboseOutput -and ($count % 100 -eq 0)) {
                Write-Host "    Processed $count users..." -ForegroundColor DarkGray
            }
            
            $userId = $null
            $samAccountName = $null
            $distinguishedName = $null
            $enabled = $true
            $adminCount = $false
            
            if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
                # Using AD module
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
            }
            else {
                # LDAP results
                $sidBytes = $user.Properties["objectsid"][0]
                $userId = Get-SidString $sidBytes
                $samAccountName = $user.Properties["samaccountname"][0]
                $distinguishedName = $user.Properties["distinguishedname"][0]
                
                # Parse userAccountControl for enabled status
                $uac = [int]$user.Properties["useraccountcontrol"][0]
                $enabled = (-not ($uac -band 2))  # ACCOUNTDISABLE flag
                
                $adminCount = if ($user.Properties["admincount"]) { [int]$user.Properties["admincount"][0] -eq 1 } else { $false }
                $pwdLastSet = if ($user.Properties["pwdlastset"]) { [datetime]::FromFileTime([int64]$user.Properties["pwdlastset"][0]) } else { $null }
                $lastLogon = if ($user.Properties["lastlogon"]) { [datetime]::FromFileTime([int64]$user.Properties["lastlogon"][0]) } else { $null }
                $lastLogonTimestamp = if ($user.Properties["lastlogontimestamp"]) { [datetime]::FromFileTime([int64]$user.Properties["lastlogontimestamp"][0]) } else { $null }
                $spns = if ($user.Properties["serviceprincipalname"]) { @($user.Properties["serviceprincipalname"]) } else { @() }
                $description = if ($user.Properties["description"]) { $user.Properties["description"][0] } else { $null }
            }
            
            if (-not $userId) { continue }
            
            $userData.nodes += @{
                type = "User"
                objectid = $userId
                properties = @{
                    name = $samAccountName
                    distinguishedname = $distinguishedName
                    domain = $Domain.ToUpper()
                    samaccountname = $samAccountName
                    enabled = $enabled
                    admincount = $adminCount
                    pwdlastset = ConvertTo-BloodhoundTime $pwdLastSet
                    lastlogon = ConvertTo-BloodhoundTime $lastLogon
                    lastlogontimestamp = ConvertTo-BloodhoundTime $lastLogonTimestamp
                    serviceprincipalnames = $spns
                    description = $description
                    highvalue = $adminCount -or ($samAccountName -eq "Administrator")
                }
            }
            
            # Add to domain relationship
            $userData.relationships += @{
                type = "Contains"
                from = $DomainSid
                to = $userId
                properties = @{}
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate users: $_"
    }
    
    return $userData
}

# Function to enumerate Computers with native methods
function Get-ComputerData {
    param([string]$Domain, [string]$DomainSid, [string]$SearchBase)
    
    $computerData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating computers in $Domain" -ForegroundColor Cyan
    
    try {
        $computers = @()
        
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
            
            $computers = Get-ADComputer @params
        }
        else {
            # LDAP fallback
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
            
            $computers = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($computers.Count) computers" -ForegroundColor DarkGray
        
        foreach ($computer in $computers) {
            $computerId = $null
            $computerName = $null
            $dnsHostName = $null
            $distinguishedName = $null
            $enabled = $true
            $unconstrainedDelegation = $false
            
            if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
                # Using AD module
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
                # LDAP results
                $sidBytes = $computer.Properties["objectsid"][0]
                $computerId = Get-SidString $sidBytes
                $computerName = $computer.Properties["name"][0]
                $dnsHostName = if ($computer.Properties["dnshostname"]) { $computer.Properties["dnshostname"][0] } else { $computerName }
                $distinguishedName = $computer.Properties["distinguishedname"][0]
                
                # Parse userAccountControl
                $uac = if ($computer.Properties["useraccountcontrol"]) { [int]$computer.Properties["useraccountcontrol"][0] } else { 0 }
                $enabled = (-not ($uac -band 2))
                $unconstrainedDelegation = ($uac -band 524288) -eq 524288  # TRUSTED_FOR_DELEGATION flag
                
                $os = if ($computer.Properties["operatingsystem"]) { $computer.Properties["operatingsystem"][0] } else { $null }
                $osVersion = if ($computer.Properties["operatingsystemversion"]) { $computer.Properties["operatingsystemversion"][0] } else { $null }
                $lastLogon = if ($computer.Properties["lastlogon"]) { [datetime]::FromFileTime([int64]$computer.Properties["lastlogon"][0]) } else { $null }
                $lastLogonTimestamp = if ($computer.Properties["lastlogontimestamp"]) { [datetime]::FromFileTime([int64]$computer.Properties["lastlogontimestamp"][0]) } else { $null }
                $pwdLastSet = if ($computer.Properties["pwdlastset"]) { [datetime]::FromFileTime([int64]$computer.Properties["pwdlastset"][0]) } else { $null }
                $spns = if ($computer.Properties["serviceprincipalname"]) { @($computer.Properties["serviceprincipalname"]) } else { @() }
                $description = if ($computer.Properties["description"]) { $computer.Properties["description"][0] } else { $null }
            }
            
            if (-not $computerId) { continue }
            
            $computerData.nodes += @{
                type = "Computer"
                objectid = $computerId
                properties = @{
                    name = if ($dnsHostName) { $dnsHostName } else { $computerName }
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
            
            # Add to domain relationship
            $computerData.relationships += @{
                type = "Contains"
                from = $DomainSid
                to = $computerId
                properties = @{}
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate computers: $_"
    }
    
    return $computerData
}

# Function to enumerate Groups with native methods
function Get-GroupData {
    param([string]$Domain, [string]$DomainSid, [string]$SearchBase)
    
    $groupData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating groups in $Domain" -ForegroundColor Cyan
    
    try {
        $groups = @()
        
        if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {
            $params = @{
                Filter = "*"
                Properties = @("SamAccountName", "DistinguishedName", "SID", "AdminCount", "Description")
                Server = $Domain
            }
            
            if ($SearchBase) {
                $params.SearchBase = $SearchBase
            }
            
            $groups = Get-ADGroup @params
        }
        else {
            # LDAP fallback
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
            
            $groups = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($groups.Count) groups" -ForegroundColor DarkGray
        
        foreach ($group in $groups) {
            $groupId = $null
            $groupName = $null
            $distinguishedName = $null
            $adminCount = $false
            
            if (Get-Command Get-ADGroup -ErrorAction SilentlyContinue) {
                # Using AD module
                $groupId = $group.SID.Value
                $groupName = $group.SamAccountName
                $distinguishedName = $group.DistinguishedName
                $adminCount = if ($group.AdminCount) { $true } else { $false }
                $description = $group.Description
            }
            else {
                # LDAP results
                $sidBytes = $group.Properties["objectsid"][0]
                $groupId = Get-SidString $sidBytes
                $groupName = $group.Properties["samaccountname"][0]
                $distinguishedName = $group.Properties["distinguishedname"][0]
                $adminCount = if ($group.Properties["admincount"]) { [int]$group.Properties["admincount"][0] -eq 1 } else { $false }
                $description = if ($group.Properties["description"]) { $group.Properties["description"][0] } else { $null }
            }
            
            if (-not $groupId) { continue }
            
            $groupData.nodes += @{
                type = "Group"
                objectid = $groupId
                properties = @{
                    name = $groupName
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
            
            # Add to domain relationship
            $groupData.relationships += @{
                type = "Contains"
                from = $DomainSid
                to = $groupId
                properties = @{}
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate groups: $_"
    }
    
    return $groupData
}

# Function to enumerate OUs with native methods
function Get-OUData {
    param([string]$Domain, [string]$DomainSid)
    
    $ouData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating OUs in $Domain" -ForegroundColor Cyan
    
    try {
        $ous = @()
        
        if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {
            $ous = Get-ADOrganizationalUnit -Filter * -Properties * -Server $Domain
        }
        else {
            # LDAP fallback
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(objectCategory=organizationalUnit)"
            $searcher.PageSize = 1000
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
            
            $properties = @("name", "distinguishedname", "objectguid", "description")
            
            foreach ($prop in $properties) {
                $searcher.PropertiesToLoad.Add($prop) | Out-Null
            }
            
            $ous = $searcher.FindAll()
        }
        
        Write-Host "  [>] Found $($ous.Count) OUs" -ForegroundColor DarkGray
        
        foreach ($ou in $ous) {
            $ouGuid = $null
            $ouName = $null
            $distinguishedName = $null
            
            if (Get-Command Get-ADOrganizationalUnit -ErrorAction SilentlyContinue) {
                # Using AD module
                $ouGuid = [guid]::Parse($ou.ObjectGUID).ToString()
                $ouName = $ou.Name
                $distinguishedName = $ou.DistinguishedName
                $description = $ou.Description
            }
            else {
                # LDAP results
                if ($ou.Properties["objectguid"]) {
                    $ouGuid = [guid]::new($ou.Properties["objectguid"][0]).ToString()
                }
                else {
                    # Generate a GUID from the DN if not available
                    $ouGuid = [guid]::NewGuid().ToString()
                }
                $ouName = $ou.Properties["name"][0]
                $distinguishedName = $ou.Properties["distinguishedname"][0]
                $description = if ($ou.Properties["description"]) { $ou.Properties["description"][0] } else { $null }
            }
            
            $ouData.nodes += @{
                type = "OU"
                objectid = "OU:" + $ouGuid
                properties = @{
                    name = $ouName
                    distinguishedname = $distinguishedName
                    domain = $Domain.ToUpper()
                    guid = $ouGuid
                    description = $description
                }
            }
            
            # Simplified parent relationship - always to domain for now
            $ouData.relationships += @{
                type = "Contains"
                from = $DomainSid
                to = "OU:" + $ouGuid
                properties = @{}
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate OUs: $_"
    }
    
    return $ouData
}

# Function to enumerate ACLs with native methods
function Get-ACLData {
    param([string]$Domain, [string]$DomainSid)
    
    $aclData = @{
        relationships = @()
    }
    
    Write-Host "[*] Enumerating ACLs in $Domain (This may take a while...)" -ForegroundColor Yellow
    
    try {
        # Get all objects with ACLs using LDAP
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(|(objectCategory=person)(objectCategory=computer)(objectCategory=group)(objectCategory=organizationalUnit))"
        $searcher.PageSize = 1000
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $searcher.PropertiesToLoad.Add("objectsid") | Out-Null
        $searcher.PropertiesToLoad.Add("objectguid") | Out-Null
        $searcher.PropertiesToLoad.Add("ntsecuritydescriptor") | Out-Null
        $searcher.PropertiesToLoad.Add("distinguishedname") | Out-Null
        
        $objects = $searcher.FindAll()
        
        Write-Host "  [>] Processing $($objects.Count) objects for ACLs" -ForegroundColor DarkGray
        
        $count = 0
        foreach ($object in $objects) {
            $count++
            if ($VerboseOutput -and ($count % 100 -eq 0)) {
                Write-Host "    Processed $count objects..." -ForegroundColor DarkGray
            }
            
            $sdBytes = $object.Properties["ntsecuritydescriptor"]
            if (-not $sdBytes) { continue }
            
            # Get object ID
            $objectId = $null
            if ($object.Properties["objectsid"]) {
                $objectId = Get-SidString $object.Properties["objectsid"][0]
            }
            elseif ($object.Properties["objectguid"]) {
                $objectId = "OU:" + [guid]::new($object.Properties["objectguid"][0]).ToString()
            }
            
            if (-not $objectId) { continue }
            
            # Convert SDDL to analyze ACLs
            try {
                $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes[0], 0)
                
                foreach ($ace in $sd.DiscretionaryAcl) {
                    $trusteeSid = $ace.SecurityIdentifier.Value
                    
                    $relationshipType = $null
                    
                    # Map ACE types to Bloodhound relationships
                    if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed) {
                        $mask = $ace.AccessMask
                        
                        # These are generic mappings - AD specific rights would need more detailed mapping
                        if (($mask -band 0x10000000) -eq 0x10000000) {  # GenericAll
                            $relationshipType = "GenericAll"
                        }
                        elseif (($mask -band 0x40000) -eq 0x40000) {  # WriteDacl
                            $relationshipType = "WriteDacl"
                        }
                        elseif (($mask -band 0x80000) -eq 0x80000) {  # WriteOwner
                            $relationshipType = "WriteOwner"
                        }
                        elseif (($mask -band 0x40000000) -eq 0x40000000) {  # GenericWrite
                            $relationshipType = "GenericWrite"
                        }
                    }
                    
                    if ($relationshipType) {
                        $aclData.relationships += @{
                            type = $relationshipType
                            from = $trusteeSid
                            to = $objectId
                            properties = @{}
                        }
                    }
                }
            }
            catch {
                # Skip ACEs we can't parse
                continue
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate ACLs: $_"
    }
    
    return $aclData
}

# Function to find attack paths using native methods
function Find-AttackPaths {
    param([string]$Domain)
    
    $attackPaths = @{
        UnconstrainedDelegation = @()
        KerberoastableUsers = @()
        ASREPRoastableUsers = @()
        UsersWithSensitiveDescription = @()
        DefaultAdministrator = $null
        TrustRelationships = @()
    }
    
    Write-Host "[*] Hunting for attack paths in $Domain" -ForegroundColor Yellow
    
    # 1. Find computers with unconstrained delegation (excluding DCs)
    Write-Host "  [>] Finding computers with unconstrained delegation..." -ForegroundColor DarkGray
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("dnshostname") | Out-Null
        
        $unconstrained = $searcher.FindAll()
        foreach ($comp in $unconstrained) {
            $name = $comp.Properties["name"][0]
            $dnsName = if ($comp.Properties["dnshostname"]) { $comp.Properties["dnshostname"][0] } else { $name }
            
            # Filter out DCs
            if ($dnsName -notlike "*DC*" -and $name -notlike "*DC*") {
                $attackPaths.UnconstrainedDelegation += @{
                    Name = $name
                    DNSHostName = $dnsName
                }
            }
        }
    }
    catch {
        Write-Warning "    [!] Failed to find unconstrained delegation computers: $_"
    }
    
    # 2. Find Kerberoastable users (users with SPNs)
    Write-Host "  [>] Finding Kerberoastable users..." -ForegroundColor DarkGray
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
        $searcher.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
        
        $kerberoastable = $searcher.FindAll()
        foreach ($user in $kerberoastable) {
            $attackPaths.KerberoastableUsers += @{
                SamAccountName = $user.Properties["samaccountname"][0]
                ServicePrincipalName = $user.Properties["serviceprincipalname"] -join ", "
            }
        }
    }
    catch {
        Write-Warning "    [!] Failed to find Kerberoastable users: $_"
    }
    
    # 3. Find AS-REP Roastable users (no pre-auth required)
    Write-Host "  [>] Finding AS-REP Roastable users..." -ForegroundColor DarkGray
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
        
        $asrep = $searcher.FindAll()
        foreach ($user in $asrep) {
            $attackPaths.ASREPRoastableUsers += @{
                SamAccountName = $user.Properties["samaccountname"][0]
            }
        }
    }
    catch {
        Write-Warning "    [!] Failed to find AS-REP Roastable users: $_"
    }
    
    # 4. Find users with sensitive info in description
    Write-Host "  [>] Finding users with sensitive descriptions..." -ForegroundColor DarkGray
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user)(|(description=*password*)(description=*pass*)(description=*admin*)))"
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
        $searcher.PropertiesToLoad.Add("description") | Out-Null
        
        $sensitive = $searcher.FindAll()
        foreach ($user in $sensitive) {
            $attackPaths.UsersWithSensitiveDescription += @{
                SamAccountName = $user.Properties["samaccountname"][0]
                Description = $user.Properties["description"][0]
            }
        }
    }
    catch {
        Write-Warning "    [!] Failed to find users with sensitive descriptions: $_"
    }
    
    # 5. Find default administrator (SID 500)
    Write-Host "  [>] Finding default administrator account..." -ForegroundColor DarkGray
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $searcher.PropertiesToLoad.Add("samaccountname") | Out-Null
        $searcher.PropertiesToLoad.Add("objectsid") | Out-Null
        $searcher.PropertiesToLoad.Add("useraccountcontrol") | Out-Null
        
        $allUsers = $searcher.FindAll()
        foreach ($user in $allUsers) {
            $sid = Get-SidString $user.Properties["objectsid"][0]
            if ($sid -like "*-500") {
                $uac = [int]$user.Properties["useraccountcontrol"][0]
                $enabled = (-not ($uac -band 2))
                $attackPaths.DefaultAdministrator = @{
                    SamAccountName = $user.Properties["samaccountname"][0]
                    Enabled = $enabled
                }
                break
            }
        }
    }
    catch {
        Write-Warning "    [!] Failed to find default administrator: $_"
    }
    
    # 6. Get trust relationships
    Write-Host "  [>] Enumerating trust relationships..." -ForegroundColor DarkGray
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(objectClass=trustedDomain)"
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
        $searcher.PropertiesToLoad.Add("trustpartner") | Out-Null
        
        $trusts = $searcher.FindAll()
        foreach ($trust in $trusts) {
            $attackPaths.TrustRelationships += @{
                Source = $Domain
                Target = $trust.Properties["trustpartner"][0]
                TrustType = "Unknown"
                Direction = "Bidirectional"
            }
        }
    }
    catch {
        Write-Warning "    [!] Failed to enumerate trusts: $_"
    }
    
    return $attackPaths
}

# Function to display attack paths
function Display-AttackPaths {
    param($AttackPaths, [string]$Domain)
    
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "ATTACK PATHS FOUND IN: $Domain" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    
    # Unconstrained Delegation
    if ($AttackPaths.UnconstrainedDelegation.Count -gt 0) {
        Write-Host "`n[!] UNCONSTRAINED DELEGATION COMPUTERS:" -ForegroundColor Yellow
        $AttackPaths.UnconstrainedDelegation | ForEach-Object {
            Write-Host "  - $($_.Name) ($($_.DNSHostName))" -ForegroundColor Cyan
        }
    }
    
    # Kerberoastable Users
    if ($AttackPaths.KerberoastableUsers.Count -gt 0) {
        Write-Host "`n[!] KERBEROASTABLE USERS:" -ForegroundColor Yellow
        $AttackPaths.KerberoastableUsers | ForEach-Object {
            Write-Host "  - $($_.SamAccountName)" -ForegroundColor Cyan
            if ($VerboseOutput) {
                Write-Host "    SPNs: $($_.ServicePrincipalName)" -ForegroundColor DarkGray
            }
        }
    }
    
    # AS-REP Roastable Users
    if ($AttackPaths.ASREPRoastableUsers.Count -gt 0) {
        Write-Host "`n[!] AS-REP ROASTABLE USERS:" -ForegroundColor Yellow
        $AttackPaths.ASREPRoastableUsers | ForEach-Object {
            Write-Host "  - $($_.SamAccountName)" -ForegroundColor Cyan
        }
    }
    
    # Users with sensitive descriptions
    if ($AttackPaths.UsersWithSensitiveDescription.Count -gt 0) {
        Write-Host "`n[!] USERS WITH SENSITIVE DESCRIPTIONS:" -ForegroundColor Yellow
        $AttackPaths.UsersWithSensitiveDescription | ForEach-Object {
            Write-Host "  - $($_.SamAccountName): $($_.Description)" -ForegroundColor Cyan
        }
    }
    
    # Default Administrator
    if ($AttackPaths.DefaultAdministrator) {
        Write-Host "`n[!] DEFAULT ADMINISTRATOR (SID 500):" -ForegroundColor Yellow
        Write-Host "  - $($AttackPaths.DefaultAdministrator.SamAccountName)" -ForegroundColor Cyan
        Write-Host "    Enabled: $($AttackPaths.DefaultAdministrator.Enabled)" -ForegroundColor DarkGray
    }
    
    # Trust Relationships
    if ($AttackPaths.TrustRelationships.Count -gt 0) {
        Write-Host "`n[!] TRUST RELATIONSHIPS:" -ForegroundColor Yellow
        $AttackPaths.TrustRelationships | ForEach-Object {
            Write-Host "  - $($_.Source) -> $($_.Target)" -ForegroundColor Cyan
            Write-Host "    Type: $($_.TrustType), Direction: $($_.Direction)" -ForegroundColor DarkGray
        }
    }
    
    # Summary
    $totalFindings = $AttackPaths.UnconstrainedDelegation.Count + 
                     $AttackPaths.KerberoastableUsers.Count + 
                     $AttackPaths.ASREPRoastableUsers.Count + 
                     $AttackPaths.UsersWithSensitiveDescription.Count
    if ($AttackPaths.DefaultAdministrator) { $totalFindings += 1 }
    
    if ($totalFindings -eq 0) {
        Write-Host "`n[+] No obvious attack paths found in $Domain" -ForegroundColor Green
    }
    else {
        Write-Host "`n[!] TOTAL ATTACK PATHS FOUND: $totalFindings" -ForegroundColor Red
    }
}

# Main script execution
function Main {
    # Load AD module (no RSAT required)
    if (-not (Load-ADModule -CustomPath $ADModulePath)) {
        return
    }
    
    # Create output directory
    Ensure-Directory $OutputPath
    
    $allData = @{
        nodes = @()
        relationships = @()
    }
    
    $processedDomains = @()
    $allAttackPaths = @{}
    
    foreach ($domain in $Domains) {
        try {
            Write-Host "`n" + ("=" * 50) -ForegroundColor Green
            Write-Host "PROCESSING DOMAIN: $domain" -ForegroundColor Green
            Write-Host ("=" * 50) -ForegroundColor Green
            
            # Test domain connectivity
            Write-Host "[*] Testing connectivity to $domain..." -ForegroundColor Gray
            try {
                $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain")
                $test = $dn.Name  # Try to access a property
                Write-Host "[+] Successfully connected to $domain" -ForegroundColor Green
            }
            catch {
                Write-Warning "[!] Could not connect to $domain: $_"
                Write-Host "[*] Trying alternative connection methods..." -ForegroundColor Yellow
                # Try with DC discovery
                try {
                    $dn = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain/rootDSE")
                    Write-Host "[+] Connected via rootDSE: $($dn.Name)" -ForegroundColor Green
                }
                catch {
                    Write-Error "[!] Failed to connect to domain $domain"
                    continue
                }
            }
            
            # Get domain SID
            $domainSid = Get-DomainSid -Domain $domain
            if (-not $domainSid) {
                Write-Warning "[!] Could not get domain SID for $domain, using placeholder"
                $domainSid = "S-1-5-21-" + (Get-Random -Minimum 1000000000 -Maximum 9999999999)
            }
            
            # Collect data from each domain
            Write-Host "[*] Collecting domain data..." -ForegroundColor Gray
            $domainInfo = Get-DomainData -Domain $domain
            
            Write-Host "[*] Collecting user data..." -ForegroundColor Gray
            $userInfo = Get-UserData -Domain $domain -DomainSid $domainSid -SearchBase $SearchBase
            
            Write-Host "[*] Collecting computer data..." -ForegroundColor Gray
            $computerInfo = Get-ComputerData -Domain $domain -DomainSid $domainSid -SearchBase $SearchBase
            
            Write-Host "[*] Collecting group data..." -ForegroundColor Gray
            $groupInfo = Get-GroupData -Domain $domain -DomainSid $domainSid -SearchBase $SearchBase
            
            Write-Host "[*] Collecting OU data..." -ForegroundColor Gray
            $ouInfo = Get-OUData -Domain $domain -DomainSid $domainSid
            
            Write-Host "[*] Collecting trust data..." -ForegroundColor Gray
            $trustInfo = Get-TrustData -Domain $domain
            
            # Merge all data
            $allData.nodes += $domainInfo.nodes
            $allData.nodes += $userInfo.nodes
            $allData.nodes += $computerInfo.nodes
            $allData.nodes += $groupInfo.nodes
            $allData.nodes += $ouInfo.nodes
            
            $allData.relationships += $domainInfo.relationships
            $allData.relationships += $userInfo.relationships
            $allData.relationships += $computerInfo.relationships
            $allData.relationships += $groupInfo.relationships
            $allData.relationships += $ouInfo.relationships
            $allData.relationships += $trustInfo.relationships
            
            # Add ACL data if not skipped
            if (-not $SkipACLs) {
                Write-Host "[*] Collecting ACL data (this may take time)..." -ForegroundColor Yellow
                $aclInfo = Get-ACLData -Domain $domain -DomainSid $domainSid
                $allData.relationships += $aclInfo.relationships
            }
            else {
                Write-Host "[*] Skipping ACL enumeration as requested..." -ForegroundColor Gray
            }
            
            # Find attack paths if requested
            if ($FindAttackPaths) {
                Write-Host "[*] Hunting for attack paths..." -ForegroundColor Yellow
                $attackPaths = Find-AttackPaths -Domain $domain
                $allAttackPaths[$domain] = $attackPaths
                Display-AttackPaths -AttackPaths $attackPaths -Domain $domain
            }
            
            $processedDomains += $domain
            
            Write-Host "[+] Successfully processed domain: $domain" -ForegroundColor Green
            
        }
        catch {
            Write-Error "[!] Failed to process domain '$domain': $_"
            continue
        }
    }
    
    if ($processedDomains.Count -eq 0) {
        Write-Error "[!] No domains were successfully processed. Exiting."
        return
    }
    
    # Create metadata
    $metadata = @{
        "counts" = @{
            "users" = ($allData.nodes | Where-Object { $_.type -eq "User" }).Count
            "computers" = ($allData.nodes | Where-Object { $_.type -eq "Computer" }).Count
            "groups" = ($allData.nodes | Where-Object { $_.type -eq "Group" }).Count
            "ous" = ($allData.nodes | Where-Object { $_.type -eq "OU" }).Count
            "domains" = ($allData.nodes | Where-Object { $_.type -eq "Domain" }).Count
            "relationships" = $allData.relationships.Count
        }
        "domains" = $processedDomains
        "collection_method" = "Native AD Module (No RSAT)"
        "collection_time" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        "attack_paths_analyzed" = $FindAttackPaths.IsPresent
        "version" = "2.1"
    }
    
    # Prepare final JSON structure
    $bloodhoundJson = @{
        "meta" = $metadata
        "nodes" = $allData.nodes
        "relationships" = $allData.relationships
    }
    
    # Generate filename with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = Join-Path $OutputPath "bloodhound_data_$timestamp.json"
    
    # Convert to JSON and save
    Write-Host "[*] Saving data to JSON file..." -ForegroundColor Gray
    $bloodhoundJson | ConvertTo-Json -Depth 10 | Out-File $outputFile -Encoding UTF8
    
    # Save attack paths separately if found
    if ($FindAttackPaths -and $allAttackPaths.Count -gt 0) {
        $attackPathFile = Join-Path $OutputPath "attack_paths_$timestamp.json"
        $allAttackPaths | ConvertTo-Json -Depth 5 | Out-File $attackPathFile -Encoding UTF8
        Write-Host "[+] Attack paths saved to: $attackPathFile" -ForegroundColor Green
    }
    
    # Display summary
    Write-Host "`n" + ("=" * 50) -ForegroundColor Green
    Write-Host "ENUMERATION COMPLETE!" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Green
    Write-Host "`nSUMMARY:" -ForegroundColor Yellow
    Write-Host "  Domains processed: $($processedDomains -join ', ')" -ForegroundColor Cyan
    Write-Host "  Total objects enumerated:" -ForegroundColor Cyan
    Write-Host "    - Users: $($metadata.counts.users)" -ForegroundColor White
    Write-Host "    - Computers: $($metadata.counts.computers)" -ForegroundColor White
    Write-Host "    - Groups: $($metadata.counts.groups)" -ForegroundColor White
    Write-Host "    - OUs: $($metadata.counts.ous)" -ForegroundColor White
    Write-Host "    - Domains: $($metadata.counts.domains)" -ForegroundColor White
    Write-Host "    - Relationships: $($metadata.counts.relationships)" -ForegroundColor White
    
    Write-Host "`nOUTPUT FILES:" -ForegroundColor Yellow
    Write-Host "  Bloodhound JSON: $outputFile" -ForegroundColor Green
    if ($FindAttackPaths -and $allAttackPaths.Count -gt 0) {
        Write-Host "  Attack Paths: $attackPathFile" -ForegroundColor Green
    }
    
    Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
    Write-Host "  1. Import the JSON file into Bloodhound:" -ForegroundColor White
    Write-Host "     - Open Bloodhound GUI" -ForegroundColor Cyan
    Write-Host "     - Click 'Upload Data'" -ForegroundColor Cyan
    Write-Host "     - Select: $outputFile" -ForegroundColor Cyan
    Write-Host "`n  2. Investigate the attack paths found:" -ForegroundColor White
    if ($FindAttackPaths -and $allAttackPaths.Count -gt 0) {
        foreach ($domain in $allAttackPaths.Keys) {
            $paths = $allAttackPaths[$domain]
            $total = $paths.UnconstrainedDelegation.Count + $paths.KerberoastableUsers.Count + 
                     $paths.ASREPRoastableUsers.Count + $paths.UsersWithSensitiveDescription.Count
            if ($paths.DefaultAdministrator) { $total += 1 }
            Write-Host "     - $domain : $total potential attack vectors" -ForegroundColor Cyan
        }
    }
    Write-Host "`n  3. Note: GPO enumeration requires RSAT GroupPolicy module" -ForegroundColor Yellow
    Write-Host "     For full GPO data, use SharpHound or install RSAT tools" -ForegroundColor White
}

# Execute main function with error handling
try {
    Main
}
catch {
    Write-Error "[!] Script execution failed: $_"
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have the AD module DLLs available" -ForegroundColor White
    Write-Host "2. Use -ADModulePath parameter to specify DLL location" -ForegroundColor White
    Write-Host "3. Check domain connectivity: Test-NetConnection <DC_IP> -Port 389" -ForegroundColor White
    Write-Host "4. Run with -VerboseOutput for detailed progress" -ForegroundColor White
}
