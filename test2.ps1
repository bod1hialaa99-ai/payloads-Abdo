# Advanced AD Bloodhound Enumeration Script
# Version: 2.0
# Features: Multi-domain support, attack path discovery, trust enumeration
# Requirements: ActiveDirectory PowerShell module, appropriate permissions

param(
    [Parameter(Mandatory = $true)]
    [string[]]$Domains,
    
    [string]$OutputPath = ".\Bloodhound_Data",
    
    [switch]$SkipACLs,
    
    [switch]$VerboseOutput,
    
    [string]$SearchBase,
    
    [switch]$FindAttackPaths
)

# Function to create directory if it doesn't exist
function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
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

# Function to get Domain SID
function Get-DomainSid {
    param([string]$Domain)
    try {
        $domainObj = Get-ADDomain -Server $Domain
        return $domainObj.DomainSID.Value
    }
    catch {
        Write-Warning "Failed to get domain SID for $Domain"
        return $null
    }
}

# Function to enumerate Domain information
function Get-DomainData {
    param([string]$Domain)
    
    $domainData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating domain: $Domain" -ForegroundColor Green
    
    # Get domain object
    $domainObj = Get-ADDomain -Server $Domain
    $domainSid = $domainObj.DomainSID.Value
    
    # Add domain node
    $domainData.nodes += @{
        type = "Domain"
        objectid = $domainSid
        properties = @{
            name = $domainObj.DNSRoot.ToUpper()
            domainsid = $domainSid
            distinguishedname = $domainObj.DistinguishedName
            highvalue = $true
        }
    }
    
    return $domainData
}

# Function to enumerate Trust Relationships
function Get-TrustData {
    param([string]$Domain)
    
    $trustData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "  [>] Enumerating trust relationships..." -ForegroundColor DarkGray
    
    try {
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
        
        # Also get forest trusts
        $forest = Get-ADForest -Server $Domain
        foreach ($forestDomain in $forest.Domains) {
            if ($forestDomain -ne $Domain) {
                $trustData.relationships += @{
                    type = "TrustedBy"
                    from = $forestDomain
                    to = $Domain
                    properties = @{
                        trusttype = "Forest"
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

# Function to enumerate Users with advanced queries
function Get-UserData {
    param([string]$Domain, [string]$DomainSid, [string]$SearchBase)
    
    $userData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating users in $Domain" -ForegroundColor Cyan
    
    # Build query parameters
    $params = @{
        Filter = "*"
        Properties = "*"
        Server = $Domain
    }
    
    if ($SearchBase) {
        $params.SearchBase = $SearchBase
        Write-Host "  [>] Using SearchBase: $SearchBase" -ForegroundColor DarkGray
    }
    
    try {
        $users = Get-ADUser @params
        
        Write-Host "  [>] Found $($users.Count) users" -ForegroundColor DarkGray
        
        foreach ($user in $users) {
            $userId = $user.SID.Value
            
            $userData.nodes += @{
                type = "User"
                objectid = $userId
                properties = @{
                    name = $user.SamAccountName
                    distinguishedname = $user.DistinguishedName
                    domain = $Domain.ToUpper()
                    samaccountname = $user.SamAccountName
                    enabled = $user.Enabled
                    admincount = if ($user.AdminCount) { $true } else { $false }
                    pwdneverexpires = $user.PasswordNeverExpires
                    pwdlastset = ConvertTo-BloodhoundTime $user.PasswordLastSet
                    lastlogon = ConvertTo-BloodhoundTime $user.LastLogonDate
                    lastlogontimestamp = ConvertTo-BloodhoundTime $user.LastLogonTimestamp
                    sidhistory = @($user.SIDHistory | ForEach-Object { $_.Value })
                    serviceprincipalnames = @($user.ServicePrincipalNames)
                    email = $user.EmailAddress
                    title = $user.Title
                    department = $user.Department
                    description = $user.Description
                    highvalue = ($user.AdminCount -eq 1) -or ($user.SamAccountName -eq "Administrator")
                }
            }
            
            # Add to domain relationship
            $userData.relationships += @{
                type = "Contains"
                from = $DomainSid
                to = $userId
                properties = @{}
            }
            
            # Add group memberships
            try {
                $groups = Get-ADPrincipalGroupMembership $user -Server $Domain
                foreach ($group in $groups) {
                    $userData.relationships += @{
                        type = "MemberOf"
                        from = $userId
                        to = $group.SID.Value
                        properties = @{}
                    }
                }
            }
            catch {
                # Some users may not have group memberships or access issues
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate users: $_"
    }
    
    return $userData
}

# Function to enumerate Computers with advanced queries
function Get-ComputerData {
    param([string]$Domain, [string]$DomainSid, [string]$SearchBase)
    
    $computerData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating computers in $Domain" -ForegroundColor Cyan
    
    # Build query parameters
    $params = @{
        Filter = "*"
        Properties = "*"
        Server = $Domain
    }
    
    if ($SearchBase) {
        $params.SearchBase = $SearchBase
    }
    
    try {
        $computers = Get-ADComputer @params
        
        Write-Host "  [>] Found $($computers.Count) computers" -ForegroundColor DarkGray
        
        foreach ($computer in $computers) {
            $computerId = $computer.SID.Value
            
            $computerData.nodes += @{
                type = "Computer"
                objectid = $computerId
                properties = @{
                    name = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
                    distinguishedname = $computer.DistinguishedName
                    domain = $Domain.ToUpper()
                    samaccountname = $computer.SamAccountName
                    enabled = $computer.Enabled
                    operatingsystem = $computer.OperatingSystem
                    operatingsystemversion = $computer.OperatingSystemVersion
                    lastlogon = ConvertTo-BloodhoundTime $computer.LastLogonDate
                    lastlogontimestamp = ConvertTo-BloodhoundTime $computer.LastLogonTimestamp
                    pwdlastset = ConvertTo-BloodhoundTime $computer.PasswordLastSet
                    serviceprincipalnames = @($computer.ServicePrincipalNames)
                    unconstraineddelegation = $computer.TrustedForDelegation
                    description = $computer.Description
                    highvalue = ($computer.TrustedForDelegation -eq $true)
                }
            }
            
            # Add to domain relationship
            $computerData.relationships += @{
                type = "Contains"
                from = $DomainSid
                to = $computerId
                properties = @{}
            }
            
            # Add group memberships
            try {
                $groups = Get-ADPrincipalGroupMembership $computer -Server $Domain
                foreach ($group in $groups) {
                    $computerData.relationships += @{
                        type = "MemberOf"
                        from = $computerId
                        to = $group.SID.Value
                        properties = @{}
                    }
                }
            }
            catch {
                # Some computers may not have group memberships
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate computers: $_"
    }
    
    return $computerData
}

# Function to enumerate Groups
function Get-GroupData {
    param([string]$Domain, [string]$DomainSid, [string]$SearchBase)
    
    $groupData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating groups in $Domain" -ForegroundColor Cyan
    
    # Build query parameters
    $params = @{
        Filter = "*"
        Properties = "*"
        Server = $Domain
    }
    
    if ($SearchBase) {
        $params.SearchBase = $SearchBase
    }
    
    try {
        $groups = Get-ADGroup @params
        
        Write-Host "  [>] Found $($groups.Count) groups" -ForegroundColor DarkGray
        
        foreach ($group in $groups) {
            $groupId = $group.SID.Value
            
            $groupData.nodes += @{
                type = "Group"
                objectid = $groupId
                properties = @{
                    name = $group.SamAccountName
                    distinguishedname = $group.DistinguishedName
                    domain = $Domain.ToUpper()
                    samaccountname = $group.SamAccountName
                    admincount = if ($group.AdminCount) { $true } else { $false }
                    description = $group.Description
                    highvalue = ($group.SamAccountName -like "*Domain Admins*") -or 
                               ($group.SamAccountName -like "*Enterprise Admins*") -or
                               ($group.SamAccountName -like "*Schema Admins*") -or
                               ($group.AdminCount -eq 1)
                }
            }
            
            # Add to domain relationship
            $groupData.relationships += @{
                type = "Contains"
                from = $DomainSid
                to = $groupId
                properties = @{}
            }
            
            # Get group members (recursive)
            try {
                $members = Get-ADGroupMember -Identity $group -Recursive -Server $Domain
                foreach ($member in $members) {
                    $groupData.relationships += @{
                        type = "MemberOf"
                        from = $member.SID.Value
                        to = $groupId
                        properties = @{}
                    }
                }
            }
            catch {
                # Some groups may be empty or have access issues
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate groups: $_"
    }
    
    return $groupData
}

# Function to enumerate OUs
function Get-OUData {
    param([string]$Domain, [string]$DomainSid)
    
    $ouData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating OUs in $Domain" -ForegroundColor Cyan
    
    try {
        $ous = Get-ADOrganizationalUnit -Filter * -Properties * -Server $Domain
        
        Write-Host "  [>] Found $($ous.Count) OUs" -ForegroundColor DarkGray
        
        foreach ($ou in $ous) {
            $ouGuid = [guid]::Parse($ou.ObjectGUID).ToString()
            
            $ouData.nodes += @{
                type = "OU"
                objectid = "OU:" + $ouGuid
                properties = @{
                    name = $ou.Name
                    distinguishedname = $ou.DistinguishedName
                    domain = $Domain.ToUpper()
                    guid = $ouGuid
                    description = $ou.Description
                }
            }
            
            # Add parent relationship (either to domain or parent OU)
            if ($ou.DistinguishedName -eq $domainObj.DistinguishedName) {
                $parentId = $DomainSid
            }
            else {
                $parentDN = $ou.DistinguishedName.Substring($ou.DistinguishedName.IndexOf(",") + 1)
                if ($parentDN -like "*OU=*") {
                    # Parent is an OU
                    $parentOU = $ous | Where-Object { $_.DistinguishedName -eq $parentDN }
                    if ($parentOU) {
                        $parentId = "OU:" + [guid]::Parse($parentOU.ObjectGUID).ToString()
                    }
                    else {
                        $parentId = $DomainSid
                    }
                }
                else {
                    # Parent is the domain
                    $parentId = $DomainSid
                }
            }
            
            $ouData.relationships += @{
                type = "Contains"
                from = $parentId
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

# Function to enumerate GPOs
function Get-GPOData {
    param([string]$Domain, [string]$DomainSid)
    
    $gpoData = @{
        nodes = @()
        relationships = @()
    }
    
    Write-Host "[*] Enumerating GPOs in $Domain" -ForegroundColor Cyan
    
    try {
        $gpos = Get-GPO -All -Domain $Domain
        
        Write-Host "  [>] Found $($gpos.Count) GPOs" -ForegroundColor DarkGray
        
        foreach ($gpo in $gpos) {
            $gpoId = "GPO:" + $gpo.Id.ToString()
            
            $gpoData.nodes += @{
                type = "GPO"
                objectid = $gpoId
                properties = @{
                    name = $gpo.DisplayName
                    guid = $gpo.Id.ToString()
                    domain = $Domain.ToUpper()
                }
            }
        }
    }
    catch {
        Write-Warning "  [!] Failed to enumerate GPOs: $_"
    }
    
    return $gpoData
}

# Function to enumerate ACLs
function Get-ACLData {
    param([string]$Domain, [string]$DomainSid)
    
    $aclData = @{
        relationships = @()
    }
    
    Write-Host "[*] Enumerating ACLs in $Domain (This may take a while...)" -ForegroundColor Yellow
    
    try {
        # Get all objects with ACLs
        $objects = @()
        $objects += Get-ADUser -Filter * -Properties nTSecurityDescriptor -Server $Domain
        $objects += Get-ADGroup -Filter * -Properties nTSecurityDescriptor -Server $Domain
        $objects += Get-ADComputer -Filter * -Properties nTSecurityDescriptor -Server $Domain
        $objects += Get-ADOrganizationalUnit -Filter * -Properties nTSecurityDescriptor -Server $Domain
        
        Write-Host "  [>] Processing $($objects.Count) objects for ACLs" -ForegroundColor DarkGray
        
        foreach ($object in $objects) {
            $sd = $object.nTSecurityDescriptor
            if ($sd -eq $null) { continue }
            
            $objectId = if ($object.ObjectSid) { 
                $object.ObjectSid.Value 
            } else { 
                "OU:" + [guid]::Parse($object.ObjectGUID).ToString()
            }
            
            foreach ($ace in $sd.Access) {
                $trusteeSid = Get-SidString $ace.SecurityIdentifier.BinaryForm
                if (-not $trusteeSid) { continue }
                
                $relationshipType = $null
                
                # Map ACE types to Bloodhound relationships
                switch ($ace.AccessControlType) {
                    "Allow" {
                        switch ($ace.ActiveDirectoryRights) {
                            { $_ -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll } {
                                $relationshipType = "GenericAll"
                            }
                            { $_ -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl } {
                                $relationshipType = "WriteDacl"
                            }
                            { $_ -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner } {
                                $relationshipType = "WriteOwner"
                            }
                            { $_ -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite } {
                                $relationshipType = "GenericWrite"
                            }
                        }
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
    }
    catch {
        Write-Warning "  [!] Failed to enumerate ACLs: $_"
    }
    
    return $aclData
}

# Function to find attack paths (from the article)
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
        $unconstrained = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties Name, DNSHostName, TrustedForDelegation -Server $Domain
        $attackPaths.UnconstrainedDelegation = $unconstrained | Where-Object { $_.DNSHostName -notlike "*DC*" } | Select-Object Name, DNSHostName
    }
    catch {
        Write-Warning "    [!] Failed to find unconstrained delegation computers: $_"
    }
    
    # 2. Find Kerberoastable users (users with SPNs)
    Write-Host "  [>] Finding Kerberoastable users..." -ForegroundColor DarkGray
    try {
        $kerberoastable = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties SamAccountName, ServicePrincipalName, MemberOf -Server $Domain
        $attackPaths.KerberoastableUsers = $kerberoastable | Select-Object SamAccountName, ServicePrincipalName
    }
    catch {
        Write-Warning "    [!] Failed to find Kerberoastable users: $_"
    }
    
    # 3. Find AS-REP Roastable users (no pre-auth required)
    Write-Host "  [>] Finding AS-REP Roastable users..." -ForegroundColor DarkGray
    try {
        $asrep = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties SamAccountName, DoesNotRequirePreAuth -Server $Domain
        $attackPaths.ASREPRoastableUsers = $asrep | Select-Object SamAccountName
    }
    catch {
        Write-Warning "    [!] Failed to find AS-REP Roastable users: $_"
    }
    
    # 4. Find users with sensitive info in description
    Write-Host "  [>] Finding users with sensitive descriptions..." -ForegroundColor DarkGray
    try {
        $sensitive = Get-ADUser -Filter {Description -like "*password*" -or Description -like "*pass*" -or Description -like "*admin*"} -Properties SamAccountName, Description -Server $Domain
        $attackPaths.UsersWithSensitiveDescription = $sensitive | Select-Object SamAccountName, Description
    }
    catch {
        Write-Warning "    [!] Failed to find users with sensitive descriptions: $_"
    }
    
    # 5. Find default administrator (SID 500)
    Write-Host "  [>] Finding default administrator account..." -ForegroundColor DarkGray
    try {
        $admin = Get-ADUser -Filter * -Properties * -Server $Domain | Where-Object { $_.SID -like "*-500" }
        if ($admin) {
            $attackPaths.DefaultAdministrator = $admin | Select-Object SamAccountName, Enabled, LastLogonDate
        }
    }
    catch {
        Write-Warning "    [!] Failed to find default administrator: $_"
    }
    
    # 6. Get trust relationships
    Write-Host "  [>] Enumerating trust relationships..." -ForegroundColor DarkGray
    try {
        $trusts = Get-ADTrust -Filter * -Server $Domain
        $attackPaths.TrustRelationships = $trusts | Select-Object Source, Target, TrustType, Direction
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
        Write-Host "    Last Logon: $($AttackPaths.DefaultAdministrator.LastLogonDate)" -ForegroundColor DarkGray
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
    # Check for ActiveDirectory module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module is not available. Please install RSAT tools."
        Write-Host "`nYou can load AD module manually using:" -ForegroundColor Yellow
        Write-Host "1. Copy these files from a system with RSAT:" -ForegroundColor White
        Write-Host "   - Microsoft.ActiveDirectory.Management.dll" -ForegroundColor Cyan
        Write-Host "   - ActiveDirectory.psd1" -ForegroundColor Cyan
        Write-Host "   - ActiveDirectory.Format.ps1xml" -ForegroundColor Cyan
        Write-Host "   - ActiveDirectory.Types.ps1xml" -ForegroundColor Cyan
        Write-Host "2. Import them: Import-Module .\ActiveDirectory.psd1" -ForegroundColor White
        return
    }
    
    # Import AD module
    Import-Module ActiveDirectory -ErrorAction Stop
    
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
            
            # Test domain connectivity with explicit -Server parameter
            Write-Host "[*] Testing connectivity to $domain..." -ForegroundColor Gray
            $testDC = Get-ADDomainController -Discover -DomainName $domain -ErrorAction Stop
            Write-Host "[+] Connected to Domain Controller: $($testDC.HostName)" -ForegroundColor Green
            
            # Get domain SID
            $domainSid = Get-DomainSid -Domain $domain
            if (-not $domainSid) {
                Write-Warning "[!] Skipping domain $domain due to SID retrieval failure"
                continue
            }
            
            # Collect data from each domain with explicit -Server parameter
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
            
            Write-Host "[*] Collecting GPO data..." -ForegroundColor Gray
            $gpoInfo = Get-GPOData -Domain $domain -DomainSid $domainSid
            
            Write-Host "[*] Collecting trust data..." -ForegroundColor Gray
            $trustInfo = Get-TrustData -Domain $domain
            
            # Merge all data
            $allData.nodes += $domainInfo.nodes
            $allData.nodes += $userInfo.nodes
            $allData.nodes += $computerInfo.nodes
            $allData.nodes += $groupInfo.nodes
            $allData.nodes += $ouInfo.nodes
            $allData.nodes += $gpoInfo.nodes
            
            $allData.relationships += $domainInfo.relationships
            $allData.relationships += $userInfo.relationships
            $allData.relationships += $computerInfo.relationships
            $allData.relationships += $groupInfo.relationships
            $allData.relationships += $ouInfo.relationships
            $allData.relationships += $gpoInfo.relationships
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
            "gpos" = ($allData.nodes | Where-Object { $_.type -eq "GPO" }).Count
            "domains" = ($allData.nodes | Where-Object { $_.type -eq "Domain" }).Count
            "relationships" = $allData.relationships.Count
        }
        "domains" = $processedDomains
        "collection_method" = "Advanced PowerShell AD Module"
        "collection_time" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        "attack_paths_analyzed" = $FindAttackPaths.IsPresent
        "version" = "2.0"
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
    Write-Host "    - GPOs: $($metadata.counts.gpos)" -ForegroundColor White
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
    Write-Host "`n  2. Use SharpHound for additional data:" -ForegroundColor White
    Write-Host "     SharpHound.exe -d $($processedDomains[0]) --CollectionMethod All --OutputDirectory .\" -ForegroundColor Cyan
    Write-Host "`n  3. Investigate the attack paths found:" -ForegroundColor White
    if ($FindAttackPaths -and $allAttackPaths.Count -gt 0) {
        foreach ($domain in $allAttackPaths.Keys) {
            $paths = $allAttackPaths[$domain]
            $total = $paths.UnconstrainedDelegation.Count + $paths.KerberoastableUsers.Count + 
                     $paths.ASREPRoastableUsers.Count + $paths.UsersWithSensitiveDescription.Count
            if ($paths.DefaultAdministrator) { $total += 1 }
            Write-Host "     - $domain : $total potential attack vectors" -ForegroundColor Cyan
        }
    }
}

# Execute main function with error handling
try {
    Main
}
catch {
    Write-Error "[!] Script execution failed: $_"
    Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have AD module installed (RSAT)" -ForegroundColor White
    Write-Host "2. Run PowerShell as Administrator" -ForegroundColor White
    Write-Host "3. Check domain connectivity: Test-NetConnection <DC_IP> -Port 389" -ForegroundColor White
    Write-Host "4. Verify you have permissions to query the domains" -ForegroundColor White
}
