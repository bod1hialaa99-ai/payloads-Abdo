# Save as ADStructureMapper.ps1
param(
    [string]$DomainController,
    [string]$OutputPath = "ad_structure.json",
    [switch]$UseIPAddress,
    [switch]$NoDNS,
    [int]$Timeout = 120
)

$ErrorActionPreference = "Continue"
$startTime = Get-Date

# ==================== BANNER ====================
Write-Host @"
===============================================================
    ____  _____     __  ___      __           __  ___          
   / __ \/ ___/    /  |/  /___ _/ /_____     /  |/  /___ _____ 
  / / / /\__ \    / /|_/ / __ '/ __/ __ \   / /|_/ / __ '/ __ \
 / /_/ /___/ /   / /  / / /_/ / /_/ /_/ /  / /  / / /_/ / /_/ /
/_____//____/   /_/  /_/\__,_/\__/\____/  /_/  /_/\__,_/ .___/ 
                                                     /_/        
            Active Directory Structure Mapper
            Resilient Version with Error Handling
===============================================================
"@ -ForegroundColor Cyan

# ==================== CONNECTION UTILITIES ====================
function Test-LDAPConnection {
    param([string]$Server, [switch]$UseIP, [switch]$SkipDNS)
    
    Write-Host "[*] Testing LDAP connection..." -ForegroundColor Yellow
    
    $connectionMethods = @()
    $successfulMethod = $null
    
    # Method 1: Try direct ADSI with RootDSE
    try {
        if ($UseIP -or $SkipDNS) {
            # Use IP or hostname without DNS resolution
            $serverToUse = if ($Server) { $Server } else { [System.Net.Dns]::GetHostName() }
            $ldapPath = "LDAP://$serverToUse/RootDSE"
        } else {
            $ldapPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
        }
        
        Write-Host "  [*] Trying: $ldapPath" -ForegroundColor Gray
        $rootDSE = [ADSI]$ldapPath
        $domainDN = $rootDSE.defaultNamingContext
        $serverName = $rootDSE.dnsHostName
        
        $connectionMethods += @{
            Method = "ADSI RootDSE"
            Status = "SUCCESS"
            Domain = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
            Server = $serverName
        }
        
        $successfulMethod = @{
            Type = "ADSI"
            RootDSE = $rootDSE
            DomainDN = $domainDN
            Server = if ($Server) { $Server } else { $serverName }
        }
        
        Write-Host "  [+] Connected via ADSI to $serverName" -ForegroundColor Green
    } catch {
        $connectionMethods += @{
            Method = "ADSI RootDSE"
            Status = "FAILED: $_"
        }
    }
    
    # Method 2: Try System.DirectoryServices.DirectoryEntry
    if (-not $successfulMethod) {
        try {
            Write-Host "  [*] Trying DirectoryEntry..." -ForegroundColor Gray
            $de = New-Object System.DirectoryServices.DirectoryEntry
            if ($Server) { $de.Path = "LDAP://$Server" }
            $de.RefreshCache()
            
            if ($de.Properties["distinguishedName"]) {
                $connectionMethods += @{
                    Method = "DirectoryEntry"
                    Status = "SUCCESS"
                    Domain = $de.Properties["distinguishedName"][0]
                }
                
                $successfulMethod = @{
                    Type = "DirectoryEntry"
                    Object = $de
                    Server = $Server
                }
                
                Write-Host "  [+] Connected via DirectoryEntry" -ForegroundColor Green
            }
        } catch {
            $connectionMethods += @{
                Method = "DirectoryEntry"
                Status = "FAILED: $_"
            }
        }
    }
    
    # Method 3: Try .NET DirectoryContext
    if (-not $successfulMethod) {
        try {
            Write-Host "  [*] Trying .NET DirectoryContext..." -ForegroundColor Gray
            Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction SilentlyContinue
            
            if ($Server) {
                $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                    [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer,
                    $Server
                )
            } else {
                $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                    [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
                )
            }
            
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
            
            $connectionMethods += @{
                Method = ".NET DirectoryContext"
                Status = "SUCCESS"
                Domain = $domain.Name
                Server = $domain.DomainControllers[0].Name
            }
            
            $successfulMethod = @{
                Type = ".NET"
                Domain = $domain
                Server = $domain.DomainControllers[0].Name
            }
            
            Write-Host "  [+] Connected via .NET DirectoryContext" -ForegroundColor Green
        } catch {
            $connectionMethods += @{
                Method = ".NET DirectoryContext"
                Status = "FAILED: $_"
            }
        }
    }
    
    # Method 4: Try direct LDAP connection using .NET
    if (-not $successfulMethod) {
        try {
            Write-Host "  [*] Trying raw LDAP connection..." -ForegroundColor Gray
            
            # Create an LDAP connection
            $ldapIdentifier = if ($Server) { $Server } else { [System.Net.Dns]::GetHostName() }
            
            $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($ldapIdentifier)
            $conn.SessionOptions.ProtocolVersion = 3
            $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
            
            $request = New-Object System.DirectoryServices.Protocols.SearchRequest
            $request.DistinguishedName = ""
            $request.Filter = "(objectClass=*)"
            $request.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
            
            $response = $conn.SendRequest($request)
            
            $connectionMethods += @{
                Method = "Raw LDAP"
                Status = "SUCCESS"
            }
            
            $successfulMethod = @{
                Type = "RawLDAP"
                Connection = $conn
                Server = $ldapIdentifier
            }
            
            Write-Host "  [+] Connected via raw LDAP" -ForegroundColor Green
        } catch {
            $connectionMethods += @{
                Method = "Raw LDAP"
                Status = "FAILED: $_"
            }
        }
    }
    
    if (-not $successfulMethod) {
        Write-Host "[!] All connection methods failed!" -ForegroundColor Red
        Write-Host "`nTroubleshooting tips:" -ForegroundColor Yellow
        Write-Host "1. Run as Administrator" -ForegroundColor White
        Write-Host "2. Ensure you're on the domain network" -ForegroundColor White
        Write-Host "3. Try specifying -DomainController parameter" -ForegroundColor White
        Write-Host "4. Try -UseIPAddress with DC's IP" -ForegroundColor White
        Write-Host "5. Check firewall allows LDAP (389/636)" -ForegroundColor White
        Write-Host "6. Run: Test-NetConnection -ComputerName DC01 -Port 389" -ForegroundColor White
        
        return $null
    }
    
    return $successfulMethod
}

# ==================== SAFE ENUMERATION FUNCTIONS ====================
function Safe-GetDomainInfo {
    Write-Host "`n[*] Getting domain information (safe mode)..." -ForegroundColor Green
    
    try {
        # Use the simplest possible method
        $domainInfo = @{
            Name = "UNKNOWN"
            DistinguishedName = ""
            SID = ""
            FunctionalLevel = "Unknown"
        }
        
        # Try to get current domain via .NET
        try {
            $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainInfo.Name = $currentDomain.Name.ToUpper()
            $domainInfo.DistinguishedName = "DC=" + $domainInfo.Name.Replace(".", ",DC=")
            
            Write-Host "  [+] Domain: $($domainInfo.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  [-] Could not get domain name: $_" -ForegroundColor Yellow
        }
        
        # Try to get domain SID via WMI
        try {
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($computerSystem.Domain) {
                $domainInfo.Name = $computerSystem.Domain.ToUpper()
            }
            
            # Try to get SID via local SAM
            $sid = (Get-WmiObject Win32_UserAccount -Filter "Name='Administrator' and Domain='$($domainInfo.Name)'" -ErrorAction SilentlyContinue).SID
            if ($sid) {
                $domainInfo.SID = $sid -replace "-500$", ""
            }
        } catch {
            Write-Host "  [-] Could not get domain SID" -ForegroundColor Yellow
        }
        
        return $domainInfo
    } catch {
        Write-Host "  [!] Error in Safe-GetDomainInfo: $_" -ForegroundColor Red
        return @{Name = "ERROR"; DistinguishedName = ""; SID = ""; FunctionalLevel = "Unknown"}
    }
}

function Safe-GetGroups {
    param([string]$DomainDN, [string]$Server)
    
    Write-Host "`n[*] Enumerating groups (safe mode)..." -ForegroundColor Green
    
    $groups = @{
        HighValue = @()
        Builtin = @()
        AdminCount = @()
        Regular = @()
    }
    
    # Define high-value groups to look for
    $highValueGroupNames = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Print Operators", "Server Operators", "Domain Controllers",
        "Group Policy Creator Owners", "DNS Admins", "DnsAdmins"
    )
    
    # Try different methods to get groups
    $methodsTried = 0
    
    # Method 1: Try ADSI with simple query
    try {
        Write-Host "  [*] Method 1: ADSI search..." -ForegroundColor Gray
        
        $searcher = New-Object DirectoryServices.DirectorySearcher
        if ($Server) {
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/$DomainDN")
        } else {
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
        }
        
        $searcher.Filter = "(objectClass=group)"
        $searcher.PageSize = 100
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("description") | Out-Null
        $searcher.PropertiesToLoad.Add("adminCount") | Out-Null
        
        $results = $searcher.FindAll()
        $methodsTried++
        
        foreach ($result in $results) {
            $groupName = $result.Properties["name"][0]
            
            $groupInfo = @{
                Name = $groupName
                Description = if ($result.Properties["description"]) { $result.Properties["description"][0] } else { "" }
                AdminCount = if ($result.Properties["adminCount"]) { $result.Properties["adminCount"][0] } else { 0 }
            }
            
            if ($highValueGroupNames -contains $groupName) {
                $groups.HighValue += $groupInfo
            } elseif ($groupInfo.AdminCount -eq 1) {
                $groups.AdminCount += $groupInfo
            } else {
                $groups.Regular += $groupInfo
            }
        }
        
        Write-Host "    [+] Found $($results.Count) groups via ADSI" -ForegroundColor Green
    } catch {
        Write-Host "    [-] ADSI method failed: $_" -ForegroundColor Yellow
    }
    
    # Method 2: Try net commands (fallback)
    if ($methodsTried -eq 0) {
        try {
            Write-Host "  [*] Method 2: NET commands..." -ForegroundColor Gray
            
            # Get local groups
            $localGroups = net localgroup 2>$null | Where-Object { $_ -match "^\*" } | ForEach-Object { $_.Substring(2).Trim() }
            
            foreach ($group in $localGroups) {
                if ($highValueGroupNames -contains $group) {
                    $groups.Builtin += @{Name = $group; Description = "Built-in local group"}
                }
            }
            
            Write-Host "    [+] Found $($localGroups.Count) local groups" -ForegroundColor Green
        } catch {
            Write-Host "    [-] NET command method failed" -ForegroundColor Yellow
        }
    }
    
    # Method 3: Try WMI
    if ($methodsTried -eq 0) {
        try {
            Write-Host "  [*] Method 3: WMI..." -ForegroundColor Gray
            
            $wmiGroups = Get-WmiObject -Class Win32_Group -Filter "Domain='$env:USERDOMAIN'" -ErrorAction SilentlyContinue
            
            foreach ($group in $wmiGroups) {
                $groupInfo = @{
                    Name = $group.Name
                    Description = $group.Description
                }
                
                if ($highValueGroupNames -contains $group.Name) {
                    $groups.HighValue += $groupInfo
                } else {
                    $groups.Regular += $groupInfo
                }
            }
            
            Write-Host "    [+] Found $($wmiGroups.Count) groups via WMI" -ForegroundColor Green
        } catch {
            Write-Host "    [-] WMI method failed" -ForegroundColor Yellow
        }
    }
    
    Write-Host "  [+] Total groups found: $($groups.HighValue.Count + $groups.Builtin.Count + $groups.AdminCount.Count + $groups.Regular.Count)" -ForegroundColor Green
    
    return $groups
}

function Safe-GetOUs {
    param([string]$DomainDN, [string]$Server)
    
    Write-Host "`n[*] Enumerating OUs (safe mode)..." -ForegroundColor Green
    
    $ous = @()
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        if ($Server) {
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/$DomainDN")
        } else {
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
        }
        
        $searcher.Filter = "(objectClass=organizationalUnit)"
        $searcher.PageSize = 50
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
        
        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $ous += @{
                Name = $result.Properties["name"][0]
                DistinguishedName = $result.Properties["distinguishedName"][0]
            }
        }
        
        Write-Host "  [+] Found $($ous.Count) OUs" -ForegroundColor Green
        
    } catch {
        Write-Host "  [-] Could not enumerate OUs: $_" -ForegroundColor Yellow
        # Create at least a default OU structure
        $ous = @(
            @{Name = "Domain Root"; DistinguishedName = $DomainDN},
            @{Name = "Domain Controllers"; DistinguishedName = "OU=Domain Controllers,$DomainDN"}
        )
    }
    
    return $ous
}

function Safe-GetComputers {
    param([string]$DomainDN, [string]$Server)
    
    Write-Host "`n[*] Enumerating computers (safe mode)..." -ForegroundColor Green
    
    $computers = @{
        DomainControllers = @()
        Servers = @()
        Workstations = @()
    }
    
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        if ($Server) {
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$Server/$DomainDN")
        } else {
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
        }
        
        # Just get a sample, not all computers
        $searcher.Filter = "(objectClass=computer)"
        $searcher.PageSize = 100
        $searcher.SizeLimit = 100  # Limit results
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
        
        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $computerName = $result.Properties["name"][0]
            $os = if ($result.Properties["operatingSystem"]) { $result.Properties["operatingSystem"][0] } else { "" }
            
            $computerInfo = @{
                Name = $computerName
                OperatingSystem = $os
            }
            
            if ($computerName -like "*DC*" -or $computerName -like "*PDC*") {
                $computers.DomainControllers += $computerInfo
            } elseif ($os -like "*Server*") {
                $computers.Servers += $computerInfo
            } else {
                $computers.Workstations += $computerInfo
            }
        }
        
        Write-Host "  [+] Found $($results.Count) computers (sampled)" -ForegroundColor Green
        
    } catch {
        Write-Host "  [-] Could not enumerate computers: $_" -ForegroundColor Yellow
    }
    
    return $computers
}

function Safe-GetGPOs {
    Write-Host "`n[*] Looking for GPOs (safe mode)..." -ForegroundColor Green
    
    $gpos = @()
    
    try {
        # Try to get GPOs via GPMC
        $gpmcAvailable = $false
        try {
            $gpm = New-Object -ComObject GPMgmt.GPM
            $gpmcAvailable = $true
        } catch { }
        
        if ($gpmcAvailable) {
            $domain = $gpm.GetDomain($env:USERDOMAIN, "", $gpm.Constants.UseAnyDC)
            $gpoList = $domain.SearchGPOs()
            
            foreach ($gpo in $gpoList) {
                $gpos += @{
                    Name = $gpo.DisplayName
                    ID = $gpo.ID
                    Status = if ($gpo.GPOStatus -eq 0) { "Enabled" } else { "Disabled" }
                }
            }
        } else {
            # Fallback: Check sysvol for GPOs
            $sysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
            if (Test-Path $sysvolPath) {
                $gpoFolders = Get-ChildItem -Path $sysvolPath -Directory | Where-Object { $_.Name -match "^\{[A-F0-9-]+\}$" }
                
                foreach ($folder in $gpoFolders) {
                    $gpos += @{
                        Name = "GPO_$($folder.Name)"
                        ID = $folder.Name
                        Status = "Unknown"
                    }
                }
            }
        }
        
        Write-Host "  [+] Found $($gpos.Count) GPOs" -ForegroundColor Green
        
    } catch {
        Write-Host "  [-] Could not enumerate GPOs: $_" -ForegroundColor Yellow
    }
    
    return $gpos
}

function Safe-GetTrusts {
    Write-Host "`n[*] Looking for domain trusts (safe mode)..." -ForegroundColor Green
    
    $trusts = @()
    
    try {
        # Method 1: nltest
        $nltestOutput = nltest /domain_trusts 2>$null
        if ($nltestOutput) {
            $trustDomains = $nltestOutput | Where-Object { $_ -match "^\s+[A-Z]" } | ForEach-Object { $_.Trim() }
            
            foreach ($domain in $trustDomains) {
                if ($domain -ne $env:USERDOMAIN) {
                    $trusts += @{
                        Name = $domain
                        Direction = "Unknown"
                        Type = "Unknown"
                    }
                }
            }
        }
        
        # Method 2: .NET Domain
        if ($trusts.Count -eq 0) {
            try {
                $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $domainTrusts = $currentDomain.GetAllTrustRelationships()
                
                foreach ($trust in $domainTrusts) {
                    $trusts += @{
                        Name = $trust.TargetName
                        Direction = $trust.TrustDirection.ToString()
                        Type = $trust.TrustType.ToString()
                    }
                }
            } catch { }
        }
        
        Write-Host "  [+] Found $($trusts.Count) domain trusts" -ForegroundColor Green
        
    } catch {
        Write-Host "  [-] Could not enumerate trusts" -ForegroundColor Yellow
    }
    
    return $trusts
}

function Safe-GetServiceAccounts {
    Write-Host "`n[*] Looking for service accounts (safe mode)..." -ForegroundColor Green
    
    $serviceAccounts = @()
    
    try {
        # Look for common service account patterns
        $patterns = @("*svc*", "*service*", "*app*", "*sql*", "*iis*", "*exchange*", "*sharepoint*")
        
        foreach ($pattern in $patterns) {
            try {
                $searcher = New-Object DirectoryServices.DirectorySearcher
                $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry
                $searcher.Filter = "(&(objectClass=user)(samAccountName=$pattern))"
                $searcher.PageSize = 20
                $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
                $searcher.PropertiesToLoad.Add("description") | Out-Null
                
                $results = $searcher.FindAll()
                
                foreach ($result in $results) {
                    $serviceAccounts += @{
                        Name = $result.Properties["samAccountName"][0]
                        Description = if ($result.Properties["description"]) { $result.Properties["description"][0] } else { "" }
                        Type = "ServiceAccount"
                    }
                }
            } catch { }
        }
        
        # Remove duplicates
        $serviceAccounts = $serviceAccounts | Sort-Object -Property Name -Unique
        
        Write-Host "  [+] Found $($serviceAccounts.Count) potential service accounts" -ForegroundColor Green
        
    } catch {
        Write-Host "  [-] Could not enumerate service accounts" -ForegroundColor Yellow
    }
    
    return $serviceAccounts
}

# ==================== MAIN EXECUTION ====================
try {
    Write-Host "[*] Starting AD Structure Mapper (Resilient Mode)" -ForegroundColor Green
    Write-Host "[*] Parameters:" -ForegroundColor Gray
    Write-Host "    - DomainController: $(if($DomainController){$DomainController}else{'Auto-detect'})" -ForegroundColor Gray
    Write-Host "    - OutputPath: $OutputPath" -ForegroundColor Gray
    Write-Host "    - UseIPAddress: $UseIPAddress" -ForegroundColor Gray
    Write-Host "    - Timeout: $Timeout seconds" -ForegroundColor Gray
    
    # Test connection
    $connection = Test-LDAPConnection -Server $DomainController -UseIP:$UseIPAddress -SkipDNS:$NoDNS
    
    if (-not $connection) {
        Write-Host "`n[!] WARNING: Could not establish LDAP connection." -ForegroundColor Red
        Write-Host "[*] Switching to fallback mode using available methods..." -ForegroundColor Yellow
    }
    
    # Get basic domain info
    $domainInfo = Safe-GetDomainInfo
    
    # Collect data using safe methods
    Write-Host "`n[*] Collecting AD structure data..." -ForegroundColor Green
    
    $adStructure = @{
        Metadata = @{
            CollectionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Collector = "ADStructureMapper v2.0"
            DomainController = if ($connection -and $connection.Server) { $connection.Server } else { "Unknown" }
            ExecutionContext = @{
                User = "$env:USERDOMAIN\$env:USERNAME"
                Computer = $env:COMPUTERNAME
                OS = [System.Environment]::OSVersion.VersionString
            }
        }
        Domain = $domainInfo
        Groups = Safe-GetGroups -DomainDN $domainInfo.DistinguishedName -Server $domainInfo.Name
        OUs = Safe-GetOUs -DomainDN $domainInfo.DistinguishedName -Server $domainInfo.Name
        Computers = Safe-GetComputers -DomainDN $domainInfo.DistinguishedName -Server $domainInfo.Name
        GPOs = Safe-GetGPOs
        Trusts = Safe-GetTrusts
        ServiceAccounts = Safe-GetServiceAccounts
        Findings = @()
    }
    
    # Calculate statistics
    $totalGroups = $adStructure.Groups.HighValue.Count + $adStructure.Groups.Builtin.Count + 
                   $adStructure.Groups.AdminCount.Count + $adStructure.Groups.Regular.Count
    
    $totalComputers = $adStructure.Computers.DomainControllers.Count + 
                      $adStructure.Computers.Servers.Count + 
                      $adStructure.Computers.Workstations.Count
    
    $adStructure.Statistics = @{
        TotalGroups = $totalGroups
        TotalOUs = $adStructure.OUs.Count
        TotalComputers = $totalComputers
        TotalGPOs = $adStructure.GPOs.Count
        TotalTrusts = $adStructure.Trusts.Count
        TotalServiceAccounts = $adStructure.ServiceAccounts.Count
        HighValueGroups = $adStructure.Groups.HighValue.Count
        DomainControllers = $adStructure.Computers.DomainControllers.Count
    }
    
    # Identify critical findings
    if ($adStructure.Groups.HighValue.Count -gt 0) {
        $adStructure.Findings += @{
            Severity = "High"
            Type = "HighValueGroups"
            Description = "Found $($adStructure.Groups.HighValue.Count) high-value groups"
            Groups = $adStructure.Groups.HighValue.Name
        }
    }
    
    if ($adStructure.Computers.DomainControllers.Count -gt 0) {
        $adStructure.Findings += @{
            Severity = "High"
            Type = "DomainControllers"
            Description = "Found $($adStructure.Computers.DomainControllers.Count) domain controllers"
            DCs = $adStructure.Computers.DomainControllers.Name
        }
    }
    
    # Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    
    $json = $adStructure | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Create summary report
    $summaryPath = $OutputPath -replace "\.json$", "_summary.txt"
    
    $summary = @"
AD STRUCTURE MAPPING - SUMMARY REPORT
===============================================================
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain: $($adStructure.Domain.Name)
Collector: $($adStructure.Metadata.Collector)
User: $($adStructure.Metadata.ExecutionContext.User)

CONNECTION STATUS:
  Domain Controller: $($adStructure.Metadata.DomainController)
  Connection Method: $(if($connection){"Successful"}else{"Fallback Mode"})

SUMMARY STATISTICS:
  Domain: $($adStructure.Domain.Name)
  Domain Functional Level: $($adStructure.Domain.FunctionalLevel)
  
  Groups: $totalGroups
    - High-Value Groups: $($adStructure.Groups.HighValue.Count)
    - Built-in Groups: $($adStructure.Groups.Builtin.Count)
    - AdminCount=1 Groups: $($adStructure.Groups.AdminCount.Count)
  
  Organizational Units: $($adStructure.OUs.Count)
  
  Computers: $totalComputers
    - Domain Controllers: $($adStructure.Computers.DomainControllers.Count)
    - Servers: $($adStructure.Computers.Servers.Count)
    - Workstations: $($adStructure.Computers.Workstations.Count)
  
  Group Policy Objects: $($adStructure.GPOs.Count)
  
  Domain Trusts: $($adStructure.Trusts.Count)
  
  Service Accounts: $($adStructure.ServiceAccounts.Count)

CRITICAL FINDINGS:
$(
    if ($adStructure.Findings.Count -gt 0) {
        foreach ($finding in $adStructure.Findings) {
            "  [$($finding.Severity)] $($finding.Description)"
            if ($finding.Groups) {
                foreach ($group in $finding.Groups) {
                    "      - $group"
                }
            }
            if ($finding.DCs) {
                foreach ($dc in $finding.DCs) {
                    "      - $dc"
                }
            }
        }
    } else {
        "  No critical findings identified."
    }
)

NOTES:
- This report was generated in resilient mode
- Some data may be limited due to permissions or connectivity
- Complete data saved to: $OutputPath
- Use for authorized security assessments only

RECOMMENDATIONS:
1. Review high-value group memberships
2. Check Domain Controller security configurations
3. Review service account permissions
4. Analyze trust relationships for attack paths
"@
    
    $summary | Out-File -FilePath $summaryPath -Encoding UTF8
    
    # Display final summary
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host " AD STRUCTURE MAPPING COMPLETE" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    Write-Host "Collection Time: $($duration.ToString('mm\:ss'))" -ForegroundColor White
    Write-Host "Domain: $($adStructure.Domain.Name)" -ForegroundColor White
    Write-Host "Mode: $(if($connection){'Full Access'}else{'Fallback'})" -ForegroundColor $(if($connection){'Green'}else{'Yellow'})
    
    Write-Host "`nRESULTS SUMMARY:" -ForegroundColor Yellow
    Write-Host "  High-Value Groups: $($adStructure.Groups.HighValue.Count)" -ForegroundColor $(if($adStructure.Groups.HighValue.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  Domain Controllers: $($adStructure.Computers.DomainControllers.Count)" -ForegroundColor $(if($adStructure.Computers.DomainControllers.Count -gt 0){'Yellow'}else{'White'})
    Write-Host "  OUs: $($adStructure.OUs.Count)" -ForegroundColor White
    Write-Host "  Total Groups: $totalGroups" -ForegroundColor White
    Write-Host "  GPOs: $($adStructure.GPOs.Count)" -ForegroundColor White
    Write-Host "  Trusts: $($adStructure.Trusts.Count)" -ForegroundColor White
    
    Write-Host "`nOUTPUT FILES:" -ForegroundColor Green
    Write-Host "  Complete Data: $OutputPath" -ForegroundColor White
    Write-Host "  Summary Report: $summaryPath" -ForegroundColor White
    
    Write-Host "`n[+] Mapping completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "`n[!] UNEXPECTED ERROR: $_" -ForegroundColor Red
    Write-Host "[!] Please report this error with the following details:" -ForegroundColor Yellow
    Write-Host "    - Error: $($_.Exception.Message)" -ForegroundColor White
    Write-Host "    - Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor White
    Write-Host "    - Command: $($_.InvocationInfo.Line)" -ForegroundColor White
}
