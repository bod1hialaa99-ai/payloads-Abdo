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
        [ValidateSet('All', 'Group', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'ObjectProps', 
                    'ACL', 'Container', 'RDP', 'PSRemote', 'DCOM', 'Trusts', 'Default', 'DCOnly')]
        [string[]]$CollectionMethods = @('Default'),
        
        [Parameter(Mandatory = $false)]
        [int]$Throttle = 100,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipGCDeconfliction,
        
        [Parameter(Mandatory = $false)]
        [switch]$Stealth
    )
    
    # Check for ActiveDirectory module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "ActiveDirectory module is not available. This script requires RSAT tools."
        return
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # Display banner
    Show-Banner
    
    Write-Host "[*] Starting BloodHound Data Collection" -ForegroundColor Green
    Write-Host "[*] Output will be saved to: $OutputPath" -ForegroundColor Yellow
    
    $startTime = Get-Date
    $stats = @{
        Users = 0
        Computers = 0
        Groups = 0
        OUs = 0
        GPOs = 0
        Domains = 0
        Sessions = 0
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
    
    # Build search parameters
    $searchParams = @{}
    if ($DomainController) { $searchParams.Server = $DomainController }
    if ($Credential) { $searchParams.Credential = $Credential }
    
    try {
        # 1. Collect Domain Information
        Write-Host "[*] Collecting domain information..." -ForegroundColor Cyan
        $domain = Get-ADDomain @searchParams -Properties *
        $domainObject = Format-DomainForBloodHound -Domain $domain
        $bloodHoundData.data.domains += $domainObject
        $stats.Domains++
        
        # 2. Collect Users
        Write-Host "[*] Collecting users..." -ForegroundColor Cyan
        $users = Get-ADUser -Filter * -Properties * @searchParams
        foreach ($user in $users) {
            $userObject = Format-UserForBloodHound -User $user -Domain $domain
            $bloodHoundData.data.users += $userObject
            $stats.Users++
            
            if ($stats.Users % 100 -eq 0) {
                Write-Host "  [+] Collected $($stats.Users) users..." -ForegroundColor Gray
            }
        }
        
        # 3. Collect Computers
        Write-Host "[*] Collecting computers..." -ForegroundColor Cyan
        $computers = Get-ADComputer -Filter * -Properties * @searchParams
        foreach ($computer in $computers) {
            $computerObject = Format-ComputerForBloodHound -Computer $computer -Domain $domain
            $bloodHoundData.data.computers += $computerObject
            $stats.Computers++
            
            if ($stats.Computers % 100 -eq 0) {
                Write-Host "  [+] Collected $($stats.Computers) computers..." -ForegroundColor Gray
            }
        }
        
        # 4. Collect Groups
        Write-Host "[*] Collecting groups..." -ForegroundColor Cyan
        $groups = Get-ADGroup -Filter * -Properties * @searchParams
        foreach ($group in $groups) {
            $groupObject = Format-GroupForBloodHound -Group $group -Domain $domain
            $bloodHoundData.data.groups += $groupObject
            $stats.Groups++
            
            if ($stats.Groups % 50 -eq 0) {
                Write-Host "  [+] Collected $($stats.Groups) groups..." -ForegroundColor Gray
            }
        }
        
        # 5. Collect OUs
        Write-Host "[*] Collecting organizational units..." -ForegroundColor Cyan
        $ous = Get-ADOrganizationalUnit -Filter * -Properties * @searchParams
        foreach ($ou in $ous) {
            $ouObject = Format-OUForBloodHound -OU $ou -Domain $domain
            $bloodHoundData.data.ous += $ouObject
            $stats.OUs++
        }
        
        # 6. Collect GPOs
        Write-Host "[*] Collecting group policy objects..." -ForegroundColor Cyan
        $gpos = Get-GPO -All -Domain $domain.DNSRoot -Server $DomainController @searchParams
        foreach ($gpo in $gpos) {
            $gpoObject = Format-GPOForBloodHound -GPO $gpo -Domain $domain
            $bloodHoundData.data.gpos += $gpoObject
            $stats.GPOs++
        }
        
        # 7. Collect Group Memberships
        Write-Host "[*] Collecting group memberships..." -ForegroundColor Cyan
        $groupMemberships = Get-GroupMemberships @searchParams
        $bloodHoundData.data.relationships += $groupMemberships
        $stats.Relationships += $groupMemberships.Count
        
        # 8. Collect ACLs (if not in stealth mode)
        if (-not $Stealth) {
            Write-Host "[*] Collecting ACLs (this may take a while)..." -ForegroundColor Cyan
            $acls = Get-ACLsForBloodHound @searchParams
            $bloodHoundData.data.relationships += $acls
            $stats.Relationships += $acls.Count
        }
        
        # 9. Collect Sessions (if not in stealth mode)
        if (-not $Stealth) {
            Write-Host "[*] Collecting sessions..." -ForegroundColor Cyan
            $sessions = Get-SessionsForBloodHound @searchParams
            $bloodHoundData.data.sessions += $sessions
            $stats.Sessions += $sessions.Count
        }
        
        # Update meta count
        $bloodHoundData.meta.count = $stats.Users + $stats.Computers + $stats.Groups + $stats.OUs + $stats.GPOs + $stats.Domains
        
        # Convert to JSON and save
        Write-Host "[*] Converting to JSON format..." -ForegroundColor Cyan
        $jsonData = ConvertTo-Json -InputObject $bloodHoundData -Depth 10 -Compress
        
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
        Write-Host "  Sessions: $($stats.Sessions)" -ForegroundColor White
        Write-Host "  Relationships: $($stats.Relationships)" -ForegroundColor White
        Write-Host "  Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
        Write-Host "  Output File: $OutputPath" -ForegroundColor Green
        Write-Host "`n[+] You can now upload $OutputPath to BloodHound" -ForegroundColor Green
        
    }
    catch {
        Write-Error "Collection failed: $_"
        throw
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
                                                                                
                    BloodHound Data Collector for PowerShell
================================================================================
"@
    Write-Host $banner -ForegroundColor Cyan
}

function Format-DomainForBloodHound {
    param(
        $Domain
    )
    
    return @{
        ObjectIdentifier = $Domain.DomainSID.Value
        Name = $Domain.DNSRoot
        Properties = @{
            name = $Domain.DNSRoot
            domain = $Domain.DNSRoot
            distinguishedname = $Domain.DistinguishedName
            domainsid = $Domain.DomainSID.Value
            highvalue = $true
        }
    }
}

function Format-UserForBloodHound {
    param(
        $User,
        $Domain
    )
    
    $highValue = $false
    $adminCount = 0
    
    if ($User.AdminCount -eq 1) {
        $adminCount = 1
        $highValue = $true
    }
    
    return @{
        ObjectIdentifier = $User.SID.Value
        Properties = @{
            name = $User.SamAccountName
            distinguishedname = $User.DistinguishedName
            domain = $Domain.DNSRoot
            domainsid = $Domain.DomainSID.Value
            enabled = ($User.Enabled -eq $true)
            pwdlastset = if ($User.PasswordLastSet) { $User.PasswordLastSet.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null }
            lastlogon = if ($User.LastLogonDate) { $User.LastLogonDate.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null }
            lastlogontimestamp = if ($User.LastLogonTimestamp) { $User.LastLogonTimestamp.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null }
            sidhistory = if ($User.SIDHistory) { $User.SIDHistory.Value } else { $null }
            admincount = $adminCount
            highvalue = $highValue
            email = $User.Email
            description = $User.Description
            title = $User.Title
            haslaps = $false  # Would need additional checks
        }
    }
}

function Format-ComputerForBloodHound {
    param(
        $Computer,
        $Domain
    )
    
    $highValue = $false
    $adminCount = 0
    
    if ($Computer.AdminCount -eq 1) {
        $adminCount = 1
        $highValue = $true
    }
    
    return @{
        ObjectIdentifier = $Computer.SID.Value
        Properties = @{
            name = $Computer.Name
            distinguishedname = $Computer.DistinguishedName
            domain = $Domain.DNSRoot
            domainsid = $Domain.DomainSID.Value
            enabled = ($Computer.Enabled -eq $true)
            pwdlastset = if ($Computer.PasswordLastSet) { $Computer.PasswordLastSet.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null }
            lastlogon = if ($Computer.LastLogonDate) { $Computer.LastLogonDate.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null }
            lastlogontimestamp = if ($Computer.LastLogonTimestamp) { $Computer.LastLogonTimestamp.ToString('yyyy-MM-ddTHH:mm:ss') } else { $null }
            operatingsystem = $Computer.OperatingSystem
            operatingsystemversion = $Computer.OperatingSystemVersion
            sidhistory = if ($Computer.SIDHistory) { $Computer.SIDHistory.Value } else { $null }
            admincount = $adminCount
            highvalue = $highValue
            haslaps = $false  # Would need additional checks
            description = $Computer.Description
        }
    }
}

function Format-GroupForBloodHound {
    param(
        $Group,
        $Domain
    )
    
    $highValue = $false
    $adminCount = 0
    
    # Check if this is a high value group
    $highValueGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 
                         'Administrators', 'Account Operators', 'Backup Operators',
                         'Print Operators', 'Server Operators', 'Domain Controllers')
    
    if ($highValueGroups -contains $Group.Name) {
        $highValue = $true
    }
    
    if ($Group.AdminCount -eq 1) {
        $adminCount = 1
        $highValue = $true
    }
    
    return @{
        ObjectIdentifier = $Group.SID.Value
        Properties = @{
            name = $Group.Name
            distinguishedname = $Group.DistinguishedName
            domain = $Domain.DNSRoot
            domainsid = $Domain.DomainSID.Value
            admincount = $adminCount
            highvalue = $highValue
            description = $Group.Description
        }
    }
}

function Format-OUForBloodHound {
    param(
        $OU,
        $Domain
    )
    
    return @{
        ObjectIdentifier = $OU.ObjectGUID.Guid
        Properties = @{
            name = $OU.Name
            distinguishedname = $OU.DistinguishedName
            domain = $Domain.DNSRoot
            domainsid = $Domain.DomainSID.Value
            gplink = $OU.gPLink
        }
    }
}

function Format-GPOForBloodHound {
    param(
        $GPO,
        $Domain
    )
    
    return @{
        ObjectIdentifier = $GPO.Id.Guid
        Properties = @{
            name = $GPO.DisplayName
            distinguishedname = "CN=$($GPO.Id),CN=Policies,CN=System,$($Domain.DistinguishedName)"
            domain = $Domain.DNSRoot
            domainsid = $Domain.DomainSID.Value
            gpostatus = "Enabled"
        }
    }
}

function Get-GroupMemberships {
    param($searchParams)
    
    $relationships = @()
    
    Write-Host "  [*] Getting group members..." -ForegroundColor Yellow
    
    $groups = Get-ADGroup -Filter * -Properties Members @searchParams
    
    foreach ($group in $groups) {
        if ($group.Members) {
            foreach ($member in $group.Members) {
                try {
                    $memberObj = Get-ADObject -Identity $member -Properties ObjectSID, ObjectGUID @searchParams -ErrorAction SilentlyContinue
                    if ($memberObj) {
                        $relationships += @{
                            StartNode = if ($memberObj.ObjectSid) { $memberObj.ObjectSid.Value } else { $memberObj.ObjectGUID.Guid }
                            EndNode = $group.SID.Value
                            Relationship = 'MemberOf'
                            Properties = @{}
                        }
                    }
                }
                catch {
                    # Skip if we can't resolve the member
                }
            }
        }
    }
    
    return $relationships
}

function Get-ACLsForBloodHound {
    param($searchParams)
    
    $relationships = @()
    Write-Host "  [*] Collecting ACLs (this is CPU intensive)..." -ForegroundColor Yellow
    
    # Get high value targets first
    $highValueObjects = @()
    
    # Domain Admins group
    try {
        $domainAdmins = Get-ADGroup -Identity "Domain Admins" -Properties nTSecurityDescriptor @searchParams
        $highValueObjects += $domainAdmins
    } catch {}
    
    # Enterprise Admins group
    try {
        $enterpriseAdmins = Get-ADGroup -Identity "Enterprise Admins" -Properties nTSecurityDescriptor @searchParams
        $highValueObjects += $enterpriseAdmins
    } catch {}
    
    # Domain Controllers OU
    try {
        $dcOU = Get-ADOrganizationalUnit -Identity "Domain Controllers" -Properties nTSecurityDescriptor @searchParams
        $highValueObjects += $dcOU
    } catch {}
    
    # Process ACLs for high value objects
    foreach ($object in $highValueObjects) {
        if ($object.nTSecurityDescriptor) {
            $acl = $object.nTSecurityDescriptor
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference) {
                    $relationships += @{
                        StartNode = $ace.IdentityReference.Value
                        EndNode = if ($object.ObjectSid) { $object.ObjectSid.Value } else { $object.ObjectGUID.Guid }
                        Relationship = $ace.AccessControlType.ToString()
                        Properties = @{
                            AceType = $ace.ActiveDirectoryRights.ToString()
                            IsInherited = $ace.IsInherited
                        }
                    }
                }
            }
        }
    }
    
    return $relationships
}

function Get-SessionsForBloodHound {
    param($searchParams)
    
    $sessions = @()
    
    # This is a simplified version. Real session collection would require
    # querying each computer for logged on users, which is noisy.
    # For now, we'll create placeholder sessions for demo purposes.
    
    Write-Host "  [*] Note: Session collection would be noisy. Skipping detailed session collection." -ForegroundColor Yellow
    
    return $sessions
}

function Get-QuickCollection {
    param(
        [string]$DomainController,
        [pscredential]$Credential,
        [string]$OutputPath = ".\bloodhound_data.json"
    )
    
    Write-Host "[*] Performing quick BloodHound collection..." -ForegroundColor Green
    
    $params = @{
        OutputPath = $OutputPath
    }
    
    if ($DomainController) { $params.DomainController = $DomainController }
    if ($Credential) { $params.Credential = $Credential }
    
    Invoke-BloodHoundCollector @params
}

# Export the functions
Export-ModuleMember -Function Invoke-BloodHoundCollector, Get-QuickCollection
