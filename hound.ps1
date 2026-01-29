function Invoke-BloodHoundCollector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DomainController,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [pscredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$Stealth,
        
        [Parameter(Mandatory = $false)]
        [int]$Throttle = 1000
    )
    
    # Display banner
    Show-Banner
    
    Write-Host "[*] Starting BloodHound Data Collection (LDAP Mode)" -ForegroundColor Green
    Write-Host "[*] Output will be saved to: $OutputPath" -ForegroundColor Yellow
    
    $startTime = Get-Date
    $stats = @{
        Users = 0
        Computers = 0
        Groups = 0
        OUs = 0
        GPOs = 0
        Domains = 0
        Relationships = 0
    }
    
    # Initialize data structure for BloodHound JSON
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
            gpos = @()
            domains = @()
            sessions = @()
            relationships = @()
        }
    }
    
    try {
        # Get domain information
        Write-Host "[*] Discovering domain information..." -ForegroundColor Cyan
        $domainInfo = Get-DomainInfo -DomainController $DomainController -Credential $Credential
        
        if (-not $domainInfo) {
            Write-Error "[-] Failed to discover domain information"
            return
        }
        
        $bloodHoundData.data.domains += @{
            ObjectIdentifier = $domainInfo.DomainSid
            Name = $domainInfo.DNSRoot
            Properties = @{
                name = $domainInfo.DNSRoot
                domain = $domainInfo.DNSRoot
                distinguishedname = $domainInfo.DistinguishedName
                domainsid = $domainInfo.DomainSid
                highvalue = $true
            }
        }
        $stats.Domains++
        
        # Collect Users
        Write-Host "[*] Collecting users..." -ForegroundColor Cyan
        $users = Get-ADObjects -ObjectClass "user" -DomainController $DomainController -Credential $Credential
        foreach ($user in $users) {
            $userObject = Format-UserForBloodHound -Object $user -DomainInfo $domainInfo
            $bloodHoundData.data.users += $userObject
            $stats.Users++
            
            if ($stats.Users % 100 -eq 0) {
                Write-Host "  [+] Collected $($stats.Users) users..." -ForegroundColor Gray
            }
        }
        
        # Collect Computers
        Write-Host "[*] Collecting computers..." -ForegroundColor Cyan
        $computers = Get-ADObjects -ObjectClass "computer" -DomainController $DomainController -Credential $Credential
        foreach ($computer in $computers) {
            $computerObject = Format-ComputerForBloodHound -Object $computer -DomainInfo $domainInfo
            $bloodHoundData.data.computers += $computerObject
            $stats.Computers++
            
            if ($stats.Computers % 100 -eq 0) {
                Write-Host "  [+] Collected $($stats.Computers) computers..." -ForegroundColor Gray
            }
        }
        
        # Collect Groups
        Write-Host "[*] Collecting groups..." -ForegroundColor Cyan
        $groups = Get-ADObjects -ObjectClass "group" -DomainController $DomainController -Credential $Credential
        foreach ($group in $groups) {
            $groupObject = Format-GroupForBloodHound -Object $group -DomainInfo $domainInfo
            $bloodHoundData.data.groups += $groupObject
            $stats.Groups++
            
            if ($stats.Groups % 50 -eq 0) {
                Write-Host "  [+] Collected $($stats.Groups) groups..." -ForegroundColor Gray
            }
        }
        
        # Collect OUs
        Write-Host "[*] Collecting organizational units..." -ForegroundColor Cyan
        $ous = Get-ADObjects -ObjectClass "organizationalUnit" -DomainController $DomainController -Credential $Credential
        foreach ($ou in $ous) {
            $ouObject = Format-OUForBloodHound -Object $ou -DomainInfo $domainInfo
            $bloodHoundData.data.ous += $ouObject
            $stats.OUs++
        }
        
        # Collect GPOs
        Write-Host "[*] Collecting group policy objects..." -ForegroundColor Cyan
        $gpos = Get-GPOObjects -DomainController $DomainController -Credential $Credential -DomainInfo $domainInfo
        foreach ($gpo in $gpos) {
            $bloodHoundData.data.gpos += $gpo
            $stats.GPOs++
        }
        
        # Collect Group Memberships
        Write-Host "[*] Collecting group memberships..." -ForegroundColor Cyan
        $groupMemberships = Get-GroupMembershipsLDAP -DomainController $DomainController -Credential $Credential -DomainInfo $domainInfo
        $bloodHoundData.data.relationships += $groupMemberships
        $stats.Relationships += $groupMemberships.Count
        
        # Update meta count
        $bloodHoundData.meta.count = $stats.Users + $stats.Computers + $stats.Groups + $stats.OUs + $stats.GPOs + $stats.Domains
        
        # Convert to JSON and save
        Write-Host "[*] Converting to JSON format..." -ForegroundColor Cyan
        $jsonData = $bloodHoundData | ConvertTo-Json -Depth 10
        
        # Save to file
        $jsonData | Out-File -FilePath $OutputPath -Encoding UTF8
        
        # Calculate and display summary
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        Write-Host "`n[+] Collection Complete!" -ForegroundColor Green
        Write-Host "==============================" -ForegroundColor Yellow
        Write-Host "Collection Statistics:" -ForegroundColor Cyan
        Write-Host "  Domains: $($stats.Domains)" -ForegroundColor White
        Write-Host "  Users: $($stats.Users)" -ForegroundColor White
        Write-Host "  Computers: $($stats.Computers)" -ForegroundColor White
        Write-Host "  Groups: $($stats.Groups)" -ForegroundColor White
        Write-Host "  OUs: $($stats.OUs)" -ForegroundColor White
        Write-Host "  GPOs: $($stats.GPOs)" -ForegroundColor White
        Write-Host "  Relationships: $($stats.Relationships)" -ForegroundColor White
        Write-Host "  Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
        Write-Host "  Output File: $OutputPath" -ForegroundColor Green
        Write-Host "`n[+] You can now upload $OutputPath to BloodHound" -ForegroundColor Green
        
    }
    catch {
        Write-Error "Collection failed: $_"
        Write-Host "[!] Error details: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] Stack trace: $($_.Exception.StackTrace)" -ForegroundColor Red
    }
}

function Show-Banner {
    $banner = @"
================================================================================
  ____  _               _   _           _   _               _                   
 |  _ \| |__   ___  ___| | | |__  _   _| |_| |__   ___   __| |_   _ _ __   ___ 
 | |_) | '_ \ / _ \/ _ \ | | '_ \| | | | __| '_ \ / _ \ / _' | | | | '_ \ / __|
 |  _ <| | | |  __/  __/ | | | | | |_| | |_| | | | (_) | (_| | |_| | | | | (__ 
 |_| \_\_| |_|\___|\___|_| |_| |_|\__,_|\__|_| |_|\___/ \__,_|\__,_|_| |_|\___|
                                                                                
                    BloodHound Data Collector (LDAP Version)
                    No RSAT Required - Works Everywhere
================================================================================
"@
    Write-Host $banner -ForegroundColor Cyan
}

# Core LDAP functions
function Get-DomainInfo {
    param(
        [string]$DomainController,
        [pscredential]$Credential
    )
    
    try {
        # Create directory entry for RootDSE
        if ($Credential) {
            $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/RootDSE", $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        elseif ($DomainController) {
            $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/RootDSE")
        }
        else {
            $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        }
        
        $domainDNS = $de.defaultNamingContext
        $configContext = $de.configurationNamingContext
        
        # Get domain object for SID
        if ($Credential) {
            $domainDE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$domainDNS", $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        elseif ($DomainController) {
            $domainDE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$domainDNS")
        }
        else {
            $domainDE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDNS")
        }
        
        $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainDE)
        $domainSearcher.Filter = "(objectClass=domain)"
        $domainSearcher.PropertiesToLoad.AddRange(@("objectSid", "name", "distinguishedName"))
        $domainResult = $domainSearcher.FindOne()
        
        if ($domainResult) {
            $domainSid = (New-Object System.Security.Principal.SecurityIdentifier($domainResult.Properties["objectsid"][0], 0)).Value
            
            return @{
                DNSRoot = $domainDNS -replace 'DC=','' -replace ',','.' -replace 'DC=',''
                DistinguishedName = $domainDNS
                DomainSid = $domainSid
                NetBIOSName = $domainResult.Properties["name"][0]
                ConfigurationContext = $configContext
            }
        }
    }
    catch {
        Write-Host "[-] Error getting domain info: $_" -ForegroundColor Red
    }
    
    return $null
}

function Get-ADObjects {
    param(
        [string]$ObjectClass,
        [string]$DomainController,
        [pscredential]$Credential,
        [string]$SearchBase,
        [int]$PageSize = 1000
    )
    
    $objects = @()
    
    try {
        # Determine LDAP path
        $ldapPath = "LDAP://"
        if ($DomainController) {
            $ldapPath += "$DomainController/"
        }
        
        if ($SearchBase) {
            $ldapPath += $SearchBase
        }
        else {
            # Get domain if not provided
            $domainInfo = Get-DomainInfo -DomainController $DomainController -Credential $Credential
            if ($domainInfo) {
                $ldapPath += $domainInfo.DistinguishedName
            }
        }
        
        # Create directory entry
        if ($Credential) {
            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else {
            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }
        
        # Create searcher
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
        $searcher.Filter = "(objectClass=$ObjectClass)"
        $searcher.PageSize = $PageSize
        
        # Load common properties
        $searcher.PropertiesToLoad.AddRange(@(
            "distinguishedName",
            "name",
            "objectSid",
            "objectGUID",
            "objectClass",
            "whenCreated",
            "whenChanged",
            "description",
            "samAccountName",
            "userPrincipalName",
            "adminCount",
            "userAccountControl",
            "lastLogon",
            "lastLogonTimestamp",
            "pwdLastSet",
            "operatingSystem",
            "operatingSystemVersion",
            "memberOf",
            "member",
            "gPLink",
            "displayName",
            "mail",
            "title"
        ))
        
        # Perform search
        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $objProps = @{}
            foreach ($propName in $result.Properties.PropertyNames) {
                $objProps[$propName] = $result.Properties[$propName]
            }
            $objects += $objProps
        }
        
        $results.Dispose()
        $de.Dispose()
    }
    catch {
        Write-Host "[-] Error getting $ObjectClass objects: $_" -ForegroundColor Red
    }
    
    return $objects
}

function Get-GPOObjects {
    param(
        [string]$DomainController,
        [pscredential]$Credential,
        $DomainInfo
    )
    
    $gpos = @()
    
    try {
        # GPOs are in the Policies container
        $policiesPath = "CN=Policies,CN=System,$($DomainInfo.DistinguishedName)"
        
        $gpoObjects = Get-ADObjects -ObjectClass "groupPolicyContainer" -DomainController $DomainController -Credential $Credential -SearchBase $policiesPath
        
        foreach ($gpo in $gpoObjects) {
            $gpos += @{
                ObjectIdentifier = [System.BitConverter]::ToString($gpo["objectGUID"][0]).Replace("-", "").ToLower()
                Properties = @{
                    name = if ($gpo["displayName"]) { $gpo["displayName"][0] } else { "Unknown GPO" }
                    distinguishedname = if ($gpo["distinguishedName"]) { $gpo["distinguishedName"][0] } else { "" }
                    domain = $DomainInfo.DNSRoot
                    domainsid = $DomainInfo.DomainSid
                    gpostatus = "Enabled"
                }
            }
        }
    }
    catch {
        Write-Host "[-] Error getting GPOs: $_" -ForegroundColor Red
    }
    
    return $gpos
}

function Get-GroupMembershipsLDAP {
    param(
        [string]$DomainController,
        [pscredential]$Credential,
        $DomainInfo
    )
    
    $relationships = @()
    
    Write-Host "  [*] Getting group members..." -ForegroundColor Yellow
    
    try {
        $groups = Get-ADObjects -ObjectClass "group" -DomainController $DomainController -Credential $Credential
        
        foreach ($group in $groups) {
            if ($group["member"]) {
                $groupId = [System.BitConverter]::ToString($group["objectGUID"][0]).Replace("-", "").ToLower()
                
                foreach ($memberDN in $group["member"]) {
                    try {
                        # Try to resolve the member
                        $member = Get-ADObjectByDN -DistinguishedName $memberDN -DomainController $DomainController -Credential $Credential
                        
                        if ($member -and $member["objectGUID"]) {
                            $memberId = [System.BitConverter]::ToString($member["objectGUID"][0]).Replace("-", "").ToLower()
                            
                            $relationships += @{
                                StartNode = $memberId
                                EndNode = $groupId
                                Relationship = 'MemberOf'
                                Properties = @{}
                            }
                        }
                    }
                    catch {
                        # Skip if we can't resolve
                    }
                }
            }
        }
    }
    catch {
        Write-Host "[-] Error getting group memberships: $_" -ForegroundColor Red
    }
    
    return $relationships
}

function Get-ADObjectByDN {
    param(
        [string]$DistinguishedName,
        [string]$DomainController,
        [pscredential]$Credential
    )
    
    try {
        $ldapPath = "LDAP://"
        if ($DomainController) {
            $ldapPath += "$DomainController/"
        }
        $ldapPath += $DistinguishedName
        
        if ($Credential) {
            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else {
            $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
        $searcher.Filter = "(objectClass=*)"
        $searcher.PropertiesToLoad.AddRange(@("objectGUID", "objectSid", "name", "objectClass"))
        
        $result = $searcher.FindOne()
        
        if ($result) {
            $objProps = @{}
            foreach ($propName in $result.Properties.PropertyNames) {
                $objProps[$propName] = $result.Properties[$propName]
            }
            return $objProps
        }
    }
    catch {
        # Object not found or access denied
    }
    
    return $null
}

# Formatting functions
function Format-UserForBloodHound {
    param(
        $Object,
        $DomainInfo
    )
    
    $highValue = $false
    $adminCount = 0
    
    if ($Object["adminCount"] -and $Object["adminCount"][0] -eq 1) {
        $adminCount = 1
        $highValue = $true
    }
    
    # Check UAC for disabled accounts
    $enabled = $true
    if ($Object["userAccountControl"]) {
        $uac = $Object["userAccountControl"][0]
        # Check if account is disabled (bit 2)
        if (($uac -band 2) -eq 2) {
            $enabled = $false
        }
    }
    
    # Get SID
    $objectSid = ""
    if ($Object["objectSid"]) {
        $objectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object["objectSid"][0], 0)).Value
    }
    
    return @{
        ObjectIdentifier = $objectSid
        Properties = @{
            name = if ($Object["samAccountName"]) { $Object["samAccountName"][0] } else { $Object["name"][0] }
            distinguishedname = $Object["distinguishedName"][0]
            domain = $DomainInfo.DNSRoot
            domainsid = $DomainInfo.DomainSid
            enabled = $enabled
            pwdlastset = if ($Object["pwdLastSet"]) { Convert-ADSTimestamp $Object["pwdLastSet"][0] } else { $null }
            lastlogon = if ($Object["lastLogon"]) { Convert-ADSTimestamp $Object["lastLogon"][0] } else { $null }
            lastlogontimestamp = if ($Object["lastLogonTimestamp"]) { Convert-ADSTimestamp $Object["lastLogonTimestamp"][0] } else { $null }
            admincount = $adminCount
            highvalue = $highValue
            email = if ($Object["mail"]) { $Object["mail"][0] } else { $null }
            description = if ($Object["description"]) { $Object["description"][0] } else { $null }
            title = if ($Object["title"]) { $Object["title"][0] } else { $null }
            haslaps = $false
            hasspn = $false
            dontreqpreauth = $false
            sensitive = $false
            passwordnotreqd = $false
            pwdneverexpires = $false
        }
    }
}

function Format-ComputerForBloodHound {
    param(
        $Object,
        $DomainInfo
    )
    
    $highValue = $false
    $adminCount = 0
    
    if ($Object["adminCount"] -and $Object["adminCount"][0] -eq 1) {
        $adminCount = 1
        $highValue = $true
    }
    
    # Check if computer is a domain controller
    $computerName = if ($Object["name"]) { $Object["name"][0] } else { "" }
    if ($computerName -like "*DC*" -or $computerName -like "*PDC*" -or $computerName -like "*ADC*") {
        $highValue = $true
    }
    
    # Get SID
    $objectSid = ""
    if ($Object["objectSid"]) {
        $objectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object["objectSid"][0], 0)).Value
    }
    
    return @{
        ObjectIdentifier = $objectSid
        Properties = @{
            name = $computerName.ToUpper()
            distinguishedname = $Object["distinguishedName"][0]
            domain = $DomainInfo.DNSRoot
            domainsid = $DomainInfo.DomainSid
            enabled = $true  # Default, could check UAC if available
            pwdlastset = if ($Object["pwdLastSet"]) { Convert-ADSTimestamp $Object["pwdLastSet"][0] } else { $null }
            lastlogon = if ($Object["lastLogon"]) { Convert-ADSTimestamp $Object["lastLogon"][0] } else { $null }
            lastlogontimestamp = if ($Object["lastLogonTimestamp"]) { Convert-ADSTimestamp $Object["lastLogonTimestamp"][0] } else { $null }
            operatingsystem = if ($Object["operatingSystem"]) { $Object["operatingSystem"][0] } else { $null }
            operatingsystemversion = if ($Object["operatingSystemVersion"]) { $Object["operatingSystemVersion"][0] } else { $null }
            admincount = $adminCount
            highvalue = $highValue
            haslaps = $false
            hasspn = $false
            unconstraineddelegation = $false
            trustedtoauth = $false
            description = if ($Object["description"]) { $Object["description"][0] } else { $null }
        }
    }
}

function Format-GroupForBloodHound {
    param(
        $Object,
        $DomainInfo
    )
    
    $highValue = $false
    $adminCount = 0
    
    $groupName = if ($Object["name"]) { $Object["name"][0] } else { "" }
    
    # Check if this is a high value group
    $highValueGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 
                         'Administrators', 'Account Operators', 'Backup Operators',
                         'Print Operators', 'Server Operators', 'Domain Controllers')
    
    if ($highValueGroups -contains $groupName) {
        $highValue = $true
    }
    
    if ($Object["adminCount"] -and $Object["adminCount"][0] -eq 1) {
        $adminCount = 1
        $highValue = $true
    }
    
    # Get SID
    $objectSid = ""
    if ($Object["objectSid"]) {
        $objectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object["objectSid"][0], 0)).Value
    }
    
    return @{
        ObjectIdentifier = $objectSid
        Properties = @{
            name = $groupName
            distinguishedname = $Object["distinguishedName"][0]
            domain = $DomainInfo.DNSRoot
            domainsid = $DomainInfo.DomainSid
            admincount = $adminCount
            highvalue = $highValue
            description = if ($Object["description"]) { $Object["description"][0] } else { $null }
        }
    }
}

function Format-OUForBloodHound {
    param(
        $Object,
        $DomainInfo
    )
    
    $guid = [System.BitConverter]::ToString($Object["objectGUID"][0]).Replace("-", "").ToLower()
    
    return @{
        ObjectIdentifier = $guid
        Properties = @{
            name = $Object["name"][0]
            distinguishedname = $Object["distinguishedName"][0]
            domain = $DomainInfo.DNSRoot
            domainsid = $DomainInfo.DomainSid
            gplink = if ($Object["gPLink"]) { $Object["gPLink"][0] } else { $null }
        }
    }
}

function Convert-ADSTimestamp {
    param([int64]$timestamp)
    
    if ($timestamp -eq 0 -or $timestamp -eq 9223372036854775807) {
        return $null
    }
    
    try {
        $epoch = Get-Date "1601-01-01 00:00:00"
        $date = $epoch.AddTicks($timestamp * 10)
        return $date.ToString("yyyy-MM-ddTHH:mm:ss")
    }
    catch {
        return $null
    }
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    # Parse command line arguments
    $params = @{}
    
    # Check for output path parameter
    for ($i = 0; $i -lt $args.Count; $i++) {
        switch ($args[$i]) {
            "-OutputPath" {
                if ($i + 1 -lt $args.Count) {
                    $params.OutputPath = $args[$i + 1]
                    $i++
                }
            }
            "-DomainController" {
                if ($i + 1 -lt $args.Count) {
                    $params.DomainController = $args[$i + 1]
                    $i++
                }
            }
            "-Stealth" {
                $params.Stealth = $true
            }
            "-Credential" {
                if ($i + 1 -lt $args.Count) {
                    $username = $args[$i + 1]
                    $params.Credential = Get-Credential -UserName $username -Message "Enter password"
                    $i++
                }
            }
        }
    }
    
    # If no output path provided, use default
    if (-not $params.OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $params.OutputPath = "bloodhound_data_$timestamp.json"
    }
    
    # Run the collector
    Invoke-BloodHoundCollector @params
}
