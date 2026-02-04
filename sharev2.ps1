# Save as Find-DomainShares.ps1
param(
    [string]$Domain,
    [string]$DomainController,
    [string]$OutputPath = "domain_shares.json",
    [int]$Threads = 10,
    [switch]$QuickScan,
    [switch]$DeepScan,
    [switch]$UseAD,
    [string]$Credential,
    [switch]$RecursiveDomains,
    [int]$TimeoutSeconds = 2
)

Write-Host @"
===============================================================
   _____ _           _        ____  _               
  / ____| |         | |      / __ \| |              
 | (___ | |__   __ _| |_ ___| |  | | |__   ___ _ __ 
  \___ \| '_ \ / _' | __/ _ \ |  | | '_ \ / _ \ '__|
  ____) | | | | (_| | ||  __/ |__| | | | |  __/ |   
 |_____/|_| |_|\__,_|\__\___|\____/|_| |_|\___|_|   
                                                    
         Domain Share & File Discovery Tool
===============================================================
"@ -ForegroundColor Cyan

# ==================== TIMEOUT FUNCTIONS ====================
function Test-ConnectionWithTimeout {
    param([string]$ComputerName, [int]$TimeoutMilliseconds = 2000)
    
    try {
        # Use .NET for faster ping with timeout
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ComputerName, $TimeoutMilliseconds)
        return $reply.Status -eq "Success"
    }
    catch {
        return $false
    }
}

function Test-PortWithTimeout {
    param([string]$ComputerName, [int]$Port = 445, [int]$TimeoutMilliseconds = 1000)
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
        
        # Wait for connection or timeout
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)
        
        if ($wait) {
            $tcpClient.EndConnect($connect)
            $tcpClient.Close()
            return $true
        }
        else {
            $tcpClient.Close()
            return $false
        }
    }
    catch {
        try { $tcpClient.Close() } catch { }
        return $false
    }
}

function Get-ChildItemWithTimeout {
    param(
        [string]$Path,
        [int]$TimeoutSeconds = 3,
        [switch]$Recurse,
        [int]$Depth = 0
    )
    
    $job = Start-Job -ScriptBlock {
        param($p, $r, $d)
        try {
            if ($r) {
                if ($d -gt 0) {
                    Get-ChildItem -Path $p -Recurse -Depth $d -ErrorAction SilentlyContinue
                } else {
                    Get-ChildItem -Path $p -Recurse -ErrorAction SilentlyContinue
                }
            } else {
                Get-ChildItem -Path $p -ErrorAction SilentlyContinue
            }
        } catch {
            return $null
        }
    } -ArgumentList $Path, $Recurse, $Depth
    
    $result = $job | Wait-Job -Timeout $TimeoutSeconds
    
    if ($result) {
        $output = Receive-Job -Job $job
        Stop-Job -Job $job
        Remove-Job -Job $job
        return $output
    } else {
        Stop-Job -Job $job
        Remove-Job -Job $job
        return $null
    }
}

# ==================== AD FUNCTIONS ====================
function Get-DomainComputers {
    param([string]$DomainName)
    
    Write-Host "[*] Querying Active Directory for computers in domain: $DomainName" -ForegroundColor Green
    
    $computers = @()
    
    try {
        if ($UseAD) {
            # Using Active Directory module
            if ($Credential) {
                $cred = Get-Credential $Credential
                $computers = Get-ADComputer -Filter * -Server $DomainName -Credential $cred -Properties DNSHostName | 
                             Select-Object -ExpandProperty DNSHostName
            } else {
                $computers = Get-ADComputer -Filter * -Server $DomainName -Properties DNSHostName | 
                             Select-Object -ExpandProperty DNSHostName
            }
        } else {
            # Using DirectorySearcher
            $searchRoot = "LDAP://$DomainName"
            if ($DomainController) {
                $searchRoot = "LDAP://$DomainController/$DomainName"
            }
            
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($searchRoot)
            $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer))"
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
            $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                if ($result.Properties["dNSHostName"]) {
                    $computers += $result.Properties["dNSHostName"][0]
                }
            }
        }
        
        Write-Host "  [+] Found $($computers.Count) computers via AD" -ForegroundColor Green
    }
    catch {
        Write-Host "  [-] AD query failed: $_" -ForegroundColor Yellow
        Write-Host "  [*] Falling back to network discovery..." -ForegroundColor Yellow
        $computers = Get-NetworkComputers -DomainName $DomainName
    }
    
    return $computers
}

function Get-ChildDomains {
    param([string]$ParentDomain)
    
    Write-Host "[*] Enumerating child domains for: $ParentDomain" -ForegroundColor Green
    
    $childDomains = @()
    
    try {
        if ($UseAD) {
            if ($Credential) {
                $cred = Get-Credential $Credential
                $childDomains = Get-ADObject -Filter "(objectClass=domainDNS)" -SearchBase "DC=$($ParentDomain.Replace('.',',DC='))" -Server $ParentDomain -Credential $cred |
                               Where-Object {$_.DistinguishedName -ne "DC=$($ParentDomain.Replace('.',',DC='))"} |
                               ForEach-Object { $_.Name }
            } else {
                $childDomains = Get-ADObject -Filter "(objectClass=domainDNS)" -SearchBase "DC=$($ParentDomain.Replace('.',',DC='))" -Server $ParentDomain |
                               Where-Object {$_.DistinguishedName -ne "DC=$($ParentDomain.Replace('.',',DC='))"} |
                               ForEach-Object { $_.Name }
            }
        } else {
            # Alternative method using DirectorySearcher
            $searchRoot = "LDAP://$ParentDomain"
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($searchRoot)
            $searcher.Filter = "(objectClass=domainDNS)"
            $searcher.SearchScope = "Subtree"
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $distinguishedName = $result.Properties["distinguishedName"][0]
                $domainName = ($distinguishedName -replace 'DC=','' -replace ',','.')
                if ($domainName -ne $ParentDomain -and $domainName -like "*.$ParentDomain") {
                    $childDomains += $domainName
                }
            }
        }
        
        if ($childDomains.Count -gt 0) {
            Write-Host "  [+] Found $($childDomains.Count) child domains:" -ForegroundColor Green
            foreach ($child in $childDomains) {
                Write-Host "      - $child" -ForegroundColor Gray
            }
        } else {
            Write-Host "  [-] No child domains found" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [-] Child domain enumeration failed: $_" -ForegroundColor Yellow
    }
    
    return $childDomains
}

function Get-DNSChildDomains {
    param([string]$DomainName)
    
    Write-Host "[*] Attempting DNS-based subdomain discovery for: $DomainName" -ForegroundColor Green
    
    $subdomains = @($DomainName)
    
    # Common subdomain prefixes
    $prefixes = @("child", "sub", "dev", "test", "prod", "lab", "corp", "internal", "ad", "dc", 
                  "us", "eu", "uk", "asia", "north", "south", "east", "west", "office", "branch")
    
    foreach ($prefix in $prefixes) {
        $testDomain = "$prefix.$DomainName"
        try {
            $result = Resolve-DnsName -Name $testDomain -Type A -ErrorAction SilentlyContinue -Timeout 2
            if ($result) {
                Write-Host "  [+] Found subdomain: $testDomain" -ForegroundColor Green
                $subdomains += $testDomain
                
                # Check for nested subdomains
                foreach ($nestedPrefix in $prefixes) {
                    $nestedDomain = "$nestedPrefix.$testDomain"
                    $nestedResult = Resolve-DnsName -Name $nestedDomain -Type A -ErrorAction SilentlyContinue -Timeout 2
                    if ($nestedResult) {
                        Write-Host "  [+] Found nested subdomain: $nestedDomain" -ForegroundColor Green
                        $subdomains += $nestedDomain
                    }
                }
            }
        } catch { }
    }
    
    return $subdomains | Select-Object -Unique
}

function Get-NetworkComputers {
    param([string]$DomainName)
    
    Write-Host "[*] Discovering network computers in domain: $DomainName..." -ForegroundColor Green
    
    $computers = @()
    
    # Method 1: DNS query for common hostnames with timeout
    $commonHosts = @("dc", "dc1", "dc2", "fileserver", "fs", "nas", "share", "server", "srv", "print", "exchange", "sql")
    
    foreach ($hostname in $commonHosts) {
        $fqdn = "$hostname.$DomainName"
        try {
            $job = Start-Job -ScriptBlock {
                param($name)
                try {
                    $ip = [System.Net.Dns]::GetHostAddresses($name) | Select-Object -First 1
                    return @{Name=$name; IP=$ip}
                } catch { return $null }
            } -ArgumentList $fqdn
            
            $result = $job | Wait-Job -Timeout 2
            if ($result) {
                $output = Receive-Job -Job $job
                if ($output -and $output.IP) {
                    $computers += $fqdn
                    Write-Host "  [+] Found via DNS: $fqdn ($($output.IP))" -ForegroundColor Gray
                }
            }
            Stop-Job -Job $job 2>$null
            Remove-Job -Job $job 2>$null
        } catch { }
    }
    
    # Method 2: NetBIOS scan (more comprehensive)
    try {
        $netView = net view /domain:$DomainName 2>$null
        if ($netView) {
            $discovered = $netView | Where-Object { $_ -match '\\\\' } | ForEach-Object { 
                $computerName = $_.Trim() -replace '\\\\', ''
                "$computerName.$DomainName"
            }
            $computers += $discovered
            Write-Host "  [+] Found $($discovered.Count) computers via NetBIOS" -ForegroundColor Gray
        }
    } catch { }
    
    $computers = $computers | Select-Object -Unique
    Write-Host "  [+] Total found: $($computers.Count) potential targets" -ForegroundColor Green
    return $computers
}

function Get-SMBShares {
    param([string]$ComputerName)
    
    Write-Host "    [*] Enumerating SMB shares on $ComputerName..." -ForegroundColor Gray
    
    $shares = @()
    
    try {
        # Method 1: Using net view with timeout
        $job = Start-Job -ScriptBlock {
            param($comp)
            try {
                $result = net view \\$comp 2>$null
                return $result
            } catch { return $null }
        } -ArgumentList $ComputerName
        
        $result = $job | Wait-Job -Timeout 3
        if ($result) {
            $netResult = Receive-Job -Job $job
            if ($netResult) {
                $shareLines = $netResult | Where-Object { $_ -match 'Disk|Print' }
                foreach ($line in $shareLines) {
                    if ($line -match '([A-Za-z0-9_\$\-]+)\s+(Disk|Print)') {
                        $shares += $matches[1]
                    }
                }
            }
        }
        Stop-Job -Job $job 2>$null
        Remove-Job -Job $job 2>$null
        
        # Method 2: WMI query (if net view fails)
        if ($shares.Count -eq 0) {
            try {
                $wmiShares = Get-WmiObject -Class Win32_Share -ComputerName $ComputerName -ErrorAction Stop -Timeout 3
                $shares = $wmiShares | Where-Object { $_.Type -in @(0, 2147483648) } | Select-Object -ExpandProperty Name
            } catch { }
        }
    }
    catch {
        Write-Host "    [-] Failed to enumerate shares on $ComputerName" -ForegroundColor DarkYellow
    }
    
    return $shares | Select-Object -Unique
}

# ==================== ENHANCED TEST FUNCTIONS ====================
function Test-SMBShare {
    param([string]$Computer, [string]$Share)
    
    try {
        $sharePath = "\\$Computer\$Share"
        
        # Test SMB port first with timeout
        if (-not (Test-PortWithTimeout -ComputerName $Computer -Port 445 -TimeoutMilliseconds 1000)) {
            return $false
        }
        
        # Try to list directory with timeout
        $job = Start-Job -ScriptBlock {
            param($path)
            try {
                $test = Get-ChildItem -Path $path -ErrorAction Stop | Select-Object -First 1
                return $true
            } catch { return $false }
        } -ArgumentList $sharePath
        
        $result = $job | Wait-Job -Timeout 3
        if ($result) {
            $output = Receive-Job -Job $job
            Stop-Job -Job $job
            Remove-Job -Job $job
            return $output
        } else {
            Stop-Job -Job $job
            Remove-Job -Job $job
            return $false
        }
    }
    catch {
        # Try alternative methods with timeout
        try {
            $job = Start-Job -ScriptBlock {
                param($comp, $shr)
                try {
                    $wmiShare = Get-WmiObject -Class Win32_Share -ComputerName $comp -Filter "Name='$shr'" -ErrorAction SilentlyContinue
                    return [bool]$wmiShare
                } catch { return $false }
            } -ArgumentList $Computer, $Share
            
            $result = $job | Wait-Job -Timeout 2
            if ($result) {
                $output = Receive-Job -Job $job
                Stop-Job -Job $job
                Remove-Job -Job $job
                return $output
            } else {
                Stop-Job -Job $job
                Remove-Job -Job $job
                return $false
            }
        } catch { }
        
        return $false
    }
}

function Scan-ComputerShares {
    param([string]$Computer, [switch]$Quick)
    
    Write-Host "  [*] Scanning $Computer..." -ForegroundColor Gray
    
    $results = @{
        Computer = $Computer
        AccessibleShares = @()
        TotalSharesTested = 0
        ScanTime = Get-Date
    }
    
    # First get all shares with timeout
    $allShares = Get-SMBShares -ComputerName $Computer
    
    if ($allShares.Count -eq 0) {
        # Fallback to common shares
        $commonShares = @(
            "ADMIN$", "C$", "D$", "E$", "F$", "G$", "IPC$", 
            "NETLOGON", "SYSVOL", "Print$", "Users", "Public", 
            "Share", "Data", "Shared", "Documents", "Backup"
        )
        $allShares = $commonShares
    }
    
    foreach ($share in $allShares) {
        $results.TotalSharesTested++
        
        if (Test-SMBShare -Computer $Computer -Share $share) {
            Write-Host "    [+] ACCESSIBLE: \\$Computer\$share" -ForegroundColor Green
            
            $shareInfo = @{
                Name = $share
                Path = "\\$Computer\$share"
                Type = if ($share -match '\$$') { "Admin" } elseif ($share -eq "IPC$") { "IPC" } else { "Regular" }
                Discovered = "Enumerated"
            }
            
            # Try to get share info with timeout
            try {
                # Get sample files
                $sampleItems = Get-ChildItemWithTimeout -Path "\\$Computer\$share" -TimeoutSeconds 2
                if ($sampleItems) {
                    $shareInfo.SampleFiles = @($sampleItems | Select-Object -First 5 | ForEach-Object { $_.Name })
                } else {
                    $shareInfo.SampleFiles = @()
                }
                
                # Get file count and size - FIXED: Handle empty directories
                $allItems = Get-ChildItemWithTimeout -Path "\\$Computer\$share" -Recurse -TimeoutSeconds 5 -Depth 1
                
                if ($allItems) {
                    $shareInfo.FileCount = ($allItems | Measure-Object).Count
                    
                    # Only calculate size for files that have Length property
                    $filesWithSize = $allItems | Where-Object { $_.PSIsContainer -eq $false -and $_.Length -gt 0 }
                    if ($filesWithSize) {
                        $totalSize = ($filesWithSize | Measure-Object -Property Length -Sum).Sum
                        $shareInfo.SizeMB = [math]::Round($totalSize / 1MB, 2)
                    } else {
                        $shareInfo.SizeMB = 0
                    }
                } else {
                    $shareInfo.FileCount = 0
                    $shareInfo.SizeMB = 0
                }
            }
            catch {
                $shareInfo.SampleFiles = @()
                $shareInfo.FileCount = 0
                $shareInfo.SizeMB = 0
                Write-Host "      [!] Error accessing share details: $_" -ForegroundColor DarkYellow
            }
            
            $results.AccessibleShares += $shareInfo
            
            # In quick mode, stop after first few accessible shares
            if ($Quick -and $results.AccessibleShares.Count -ge 3) {
                Write-Host "    [*] Quick mode: Stopping after 3 accessible shares" -ForegroundColor Yellow
                break
            }
        }
    }
    
    return $results
}

function Find-InterestingFiles {
    param([string]$SharePath, [int]$MaxDepth = 2, [int]$MaxFiles = 100)
    
    $interestingFiles = @()
    $patterns = @(
        "*.txt", "*.xml", "*.config", "*.ini", "*.bat", "*.ps1",
        "*.vbs", "*.sql", "*.mdb", "*.xls*", "*.doc*", "*.pdf",
        "pass*.txt", "cred*.txt", "backup*", "secret*", "*.pwd"
    )
    
    try {
        foreach ($pattern in $patterns) {
            # Use timeout for file search
            $files = Get-ChildItemWithTimeout -Path $SharePath -Filter $pattern -Recurse -Depth $MaxDepth -TimeoutSeconds 5
            
            if ($files) {
                foreach ($file in ($files | Select-Object -First $MaxFiles)) {
                    $interestingFiles += @{
                        Name = $file.Name
                        Path = $file.FullName
                        Size = if ($file.Length) { $file.Length } else { 0 }
                        LastWrite = $file.LastWriteTime
                        Extension = $file.Extension
                    }
                }
            }
        }
    }
    catch { }
    
    return $interestingFiles
}

# ==================== MAIN EXECUTION ====================
try {
    $startTime = Get-Date
    Write-Host "[*] Starting Domain Share Discovery" -ForegroundColor Green
    
    # Determine target domain(s)
    $domainsToScan = @()
    
    if ($Domain) {
        Write-Host "[*] Using specified domain: $Domain" -ForegroundColor White
        $domainsToScan += $Domain
        
        if ($RecursiveDomains) {
            # Get child domains via AD
            $childDomains = Get-ChildDomains -ParentDomain $Domain
            $domainsToScan += $childDomains
            
            # Also try DNS-based discovery
            $dnsSubdomains = Get-DNSChildDomains -DomainName $Domain
            $domainsToScan += $dnsSubdomains
        }
    } else {
        # Get current domain
        $currentDomain = $env:USERDNSDOMAIN
        if (-not $currentDomain) {
            $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
        Write-Host "[*] Using current domain: $currentDomain" -ForegroundColor White
        $domainsToScan += $currentDomain
    }
    
    $domainsToScan = $domainsToScan | Select-Object -Unique
    Write-Host "[*] Domains to scan: $($domainsToScan -join ', ')" -ForegroundColor White
    Write-Host "[*] Timeout per host: ${TimeoutSeconds}s" -ForegroundColor White
    
    # Discover computers in each domain
    $allComputers = @()
    foreach ($domain in $domainsToScan) {
        Write-Host "`n[*] Discovering computers in domain: $domain" -ForegroundColor Cyan
        
        $domainComputers = @()
        
        # Try AD first if specified
        if ($UseAD -or $DomainController) {
            $domainComputers = Get-DomainComputers -DomainName $domain
        } else {
            $domainComputers = Get-NetworkComputers -DomainName $domain
        }
        
        if ($domainComputers.Count -eq 0) {
            Write-Host "  [!] No computers found in domain $domain" -ForegroundColor Yellow
            continue
        }
        
        $allComputers += $domainComputers
        Write-Host "  [+] Added $($domainComputers.Count) computers from $domain" -ForegroundColor Green
    }
    
    $allComputers = $allComputers | Select-Object -Unique
    
    if ($allComputers.Count -eq 0) {
        Write-Host "[!] No computers found in any domain" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`n[*] Total unique computers to scan: $($allComputers.Count)" -ForegroundColor Green
    
    # Limit computers for quick scan
    if ($QuickScan) {
        $allComputers = $allComputers | Select-Object -First 20
        Write-Host "[*] Quick scan mode: Testing first 20 computers" -ForegroundColor Yellow
    }
    
    # Scan for accessible shares
    $allResults = @()
    $accessibleComputers = 0
    $skippedComputers = 0
    
    Write-Host "`n[*] Scanning for accessible shares..." -ForegroundColor Green
    
    $current = 0
    $total = $allComputers.Count
    
    foreach ($computer in $allComputers) {
        $current++
        $percentComplete = [math]::Round(($current / $total) * 100, 2)
        
        Write-Progress -Activity "Scanning Computers" -Status "$current of $total ($percentComplete%)" -PercentComplete $percentComplete
        Write-Host "  [$current/$total] Testing $computer..." -ForegroundColor Gray
        
        try {
            # First, check if SMB port is open with timeout
            $hostNameOnly = $computer -replace '\..*$', ''
            
            # Skip if no SMB port
            if (-not (Test-PortWithTimeout -ComputerName $hostNameOnly -Port 445 -TimeoutMilliseconds 1000)) {
                Write-Host "    [-] SMB port (445) closed or timeout" -ForegroundColor DarkGray
                $skippedComputers++
                continue
            }
            
            # If we get here, scan the computer
            $results = Scan-ComputerShares -Computer $computer -Quick:$QuickScan
            
            if ($results.AccessibleShares.Count -gt 0) {
                $accessibleComputers++
                
                # If deep scan enabled, scan for interesting files
                if ($DeepScan) {
                    Write-Host "    [*] Deep scanning accessible shares..." -ForegroundColor Gray
                    
                    foreach ($share in $results.AccessibleShares) {
                        if ($share.Type -ne "IPC") {
                            $interestingFiles = Find-InterestingFiles -SharePath $share.Path
                            $share.InterestingFiles = $interestingFiles
                            $share.InterestingFileCount = $interestingFiles.Count
                        }
                    }
                }
            }
            
            $allResults += $results
        }
        catch {
            Write-Host "    [-] Error scanning $computer : $_" -ForegroundColor DarkYellow
        }
    }
    
    Write-Progress -Activity "Scanning Computers" -Completed
    
    # Calculate statistics
    $totalAccessibleShares = ($allResults | ForEach-Object { $_.AccessibleShares.Count } | Measure-Object -Sum).Sum
    $totalInterestingFiles = ($allResults | ForEach-Object { 
        $_.AccessibleShares | ForEach-Object { if ($_.InterestingFileCount) { $_.InterestingFileCount } else { 0 } }
    } | Measure-Object -Sum).Sum
    
    # Build results structure
    $scanResults = @{
        Metadata = @{
            ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            DomainsScanned = $domainsToScan
            DomainController = $DomainController
            ScanType = if ($DeepScan) { "Deep" } elseif ($QuickScan) { "Quick" } else { "Standard" }
            UseAD = $UseAD
            TimeoutSeconds = $TimeoutSeconds
            ComputersScanned = $allComputers.Count
            SkippedComputers = $skippedComputers
            ScanDuration = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
        }
        Results = $allResults
        Statistics = @{
            TotalComputers = $allComputers.Count
            SkippedComputers = $skippedComputers
            AccessibleComputers = $accessibleComputers
            TotalAccessibleShares = $totalAccessibleShares
            AdminSharesFound = ($allResults | ForEach-Object { 
                $_.AccessibleShares | Where-Object { $_.Type -eq "Admin" }
            }).Count
            TotalInterestingFiles = $totalInterestingFiles
            TotalSizeMB = ($allResults | ForEach-Object { 
                $_.AccessibleShares | ForEach-Object { if ($_.SizeMB) { $_.SizeMB } else { 0 } }
            } | Measure-Object -Sum).Sum
        }
        Summary = @()
    }
    
    # Create summary
    foreach ($result in $allResults | Where-Object { $_.AccessibleShares.Count -gt 0 }) {
        foreach ($share in $result.AccessibleShares) {
            $scanResults.Summary += @{
                Computer = $result.Computer
                Share = $share.Name
                Path = $share.Path
                Type = $share.Type
                FileCount = if ($share.FileCount) { $share.FileCount } else { 0 }
                SizeMB = if ($share.SizeMB) { $share.SizeMB } else { 0 }
                InterestingFiles = if ($share.InterestingFiles) { $share.InterestingFiles.Count } else { 0 }
            }
        }
    }
    
    # Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    $scanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Export to CSV as well
    $csvPath = $OutputPath -replace '\.json$', '.csv'
    $scanResults.Summary | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "[*] Also saved to: $csvPath" -ForegroundColor Green
    
    # Display final summary
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host " SHARE DISCOVERY COMPLETE" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    Write-Host "Domains scanned: $($domainsToScan -join ', ')" -ForegroundColor White
    Write-Host "Scan Duration: $($scanResults.Metadata.ScanDuration)" -ForegroundColor White
    
    Write-Host "`nSUMMARY STATISTICS:" -ForegroundColor Yellow
    Write-Host "  Total computers found: $($allComputers.Count)" -ForegroundColor White
    Write-Host "  Computers skipped (no SMB): $skippedComputers" -ForegroundColor Gray
    Write-Host "  Computers scanned: $($allComputers.Count - $skippedComputers)" -ForegroundColor White
    Write-Host "  Computers with accessible shares: $accessibleComputers" -ForegroundColor $(if($accessibleComputers -gt 0){"Green"}else{"White"})
    Write-Host "  Total accessible shares: $totalAccessibleShares" -ForegroundColor $(if($totalAccessibleShares -gt 0){"Green"}else{"White"})
    Write-Host "  Admin shares found: $($scanResults.Statistics.AdminSharesFound)" -ForegroundColor $(if($scanResults.Statistics.AdminSharesFound -gt 0){"Red"}else{"White"})
    Write-Host "  Interesting files found: $totalInterestingFiles" -ForegroundColor $(if($totalInterestingFiles -gt 0){"Yellow"}else{"White"})
    Write-Host "  Total data size: $($scanResults.Statistics.TotalSizeMB) MB" -ForegroundColor White
    
    # Show top 5 shares by size
    $topShares = $scanResults.Summary | Sort-Object SizeMB -Descending | Select-Object -First 5
    if ($topShares.Count -gt 0) {
        Write-Host "`nTOP 5 LARGEST SHARES:" -ForegroundColor Yellow
        foreach ($share in $topShares) {
            Write-Host "  - $($share.Path) ($($share.SizeMB) MB, $($share.FileCount) files)" -ForegroundColor Gray
        }
    }
    
    # Show critical findings
    if ($scanResults.Statistics.AdminSharesFound -gt 0) {
        Write-Host "`n[!] CRITICAL FINDING: Admin shares are accessible!" -ForegroundColor Red
        $adminShares = $scanResults.Summary | Where-Object { $_.Type -eq "Admin" }
        foreach ($share in $adminShares) {
            Write-Host "    - $($share.Path)" -ForegroundColor Yellow
        }
    }
    
    if ($totalInterestingFiles -gt 0) {
        Write-Host "`n[!] Potentially interesting files found:" -ForegroundColor Yellow
        $filesByType = $scanResults.Results | ForEach-Object { 
            $_.AccessibleShares | Where-Object { $_.InterestingFiles } | ForEach-Object { $_.InterestingFiles }
        } | Group-Object Extension
        
        foreach ($type in $filesByType) {
            Write-Host "    - $($type.Count) $($type.Name) files" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nOutput saved to:" -ForegroundColor Green
    Write-Host "  JSON: $OutputPath" -ForegroundColor White
    Write-Host "  CSV:  $csvPath" -ForegroundColor White
    
}
catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
}
