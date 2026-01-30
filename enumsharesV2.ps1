# Save as SimpleShareScanner.ps1
param(
    [string]$DomainController,
    [string]$OutputPath = "shares_found.json",
    [switch]$TestOnly,
    [switch]$UseNetView
)

$ErrorActionPreference = "Continue"
$startTime = Get-Date

Write-Host @"
===============================================================
   ____  _     _   _        ____  _               
  / ___|(_) __| | | |      / ___|| |__   ___  ___ 
  \___ \| |/ _' | | |      \___ \| '_ \ / _ \/ __|
   ___) | | (_| | | |___    ___) | | | |  __/ (__ 
  |____/|_|\__,_| |_____|  |____/|_| |_|\___|\___|
                                                  
        Simple Domain Share Scanner
===============================================================
"@ -ForegroundColor Cyan

# ==================== TEST CONNECTION ====================
function Test-DCConnection {
    param([string]$DCName)
    
    Write-Host "[*] Testing connection to: $DCName" -ForegroundColor Green
    
    $testResults = @{
        Ping = $false
        LDAP = $false
        NetBIOS = $false
        Domain = ""
        Error = ""
    }
    
    # Test 1: Ping
    try {
        Write-Host "  [*] Testing ping..." -ForegroundColor Gray
        $ping = Test-Connection -ComputerName $DCName -Count 1 -Quiet -ErrorAction Stop
        $testResults.Ping = $ping
        Write-Host "  [+] Ping: $(if($ping){'Success'}else{'Failed'})" -ForegroundColor $(if($ping){'Green'}else{'Yellow'})
    } catch {
        Write-Host "  [-] Ping failed: $_" -ForegroundColor Yellow
    }
    
    # Test 2: LDAP (port 389)
    try {
        Write-Host "  [*] Testing LDAP (port 389)..." -ForegroundColor Gray
        $test = Test-NetConnection -ComputerName $DCName -Port 389 -WarningAction SilentlyContinue -ErrorAction Stop
        $testResults.LDAP = $test.TcpTestSucceeded
        Write-Host "  [+] LDAP: $(if($test.TcpTestSucceeded){'Open'}else{'Closed'})" -ForegroundColor $(if($test.TcpTestSucceeded){'Green'}else{'Yellow'})
    } catch {
        Write-Host "  [-] LDAP test failed" -ForegroundColor Yellow
    }
    
    # Test 3: NetBIOS (port 445 for SMB)
    try {
        Write-Host "  [*] Testing SMB (port 445)..." -ForegroundColor Gray
        $test = Test-NetConnection -ComputerName $DCName -Port 445 -WarningAction SilentlyContinue -ErrorAction Stop
        $testResults.NetBIOS = $test.TcpTestSucceeded
        Write-Host "  [+] SMB: $(if($test.TcpTestSucceeded){'Open'}else{'Closed'})" -ForegroundColor $(if($test.TcpTestSucceeded){'Green'}else{'Yellow'})
    } catch {
        Write-Host "  [-] SMB test failed" -ForegroundColor Yellow
    }
    
    # Try to get domain info if LDAP is open
    if ($testResults.LDAP) {
        try {
            $rootDSE = [ADSI]"LDAP://$DCName/RootDSE"
            $domainDN = $rootDSE.defaultNamingContext
            $testResults.Domain = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
            Write-Host "  [+] Domain: $($testResults.Domain)" -ForegroundColor Green
        } catch {
            Write-Host "  [-] Could not get domain info" -ForegroundColor Yellow
        }
    }
    
    return $testResults
}

# ==================== GET COMPUTERS ====================
function Get-ComputersSimple {
    param([string]$DCName, [string]$Domain)
    
    Write-Host "`n[*] Getting list of computers..." -ForegroundColor Green
    
    $computers = @()
    
    # Method 1: Try net view (works without AD permissions)
    if ($UseNetView -or -not $DCName) {
        Write-Host "  [*] Using net view to discover computers..." -ForegroundColor Gray
        try {
            $netOutput = net view /domain 2>$null
            if ($netOutput) {
                $computerNames = $netOutput | Where-Object { $_ -match '\\\\' } | ForEach-Object { 
                    $_.Trim() -replace '\\\\', ''
                }
                
                foreach ($name in $computerNames) {
                    $computers += @{
                        Name = $name
                        DNSHostName = $name
                        Source = "NetView"
                    }
                }
                Write-Host "  [+] Found $($computers.Count) computers via net view" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [-] Net view failed: $_" -ForegroundColor Yellow
        }
    }
    
    # Method 2: Try AD query if DC is provided
    if ($DCName -and $computers.Count -eq 0) {
        Write-Host "  [*] Querying AD for computers via $DCName..." -ForegroundColor Gray
        try {
            # Get domain DN first
            $rootDSE = [ADSI]"LDAP://$DCName/RootDSE"
            $domainDN = $rootDSE.defaultNamingContext
            
            # Create a simpler query with smaller page size
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"LDAP://$DCName/$domainDN"
            $searcher.Filter = "(objectClass=computer)"
            $searcher.PageSize = 100  # Smaller page size for reliability
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
            
            $results = $searcher.FindAll()
            
            foreach ($result in $results) {
                $name = $result.Properties["name"][0]
                $dnsName = if ($result.Properties["dNSHostName"]) { 
                    $result.Properties["dNSHostName"][0] 
                } else { 
                    "$name.$Domain".ToLower()
                }
                
                $computers += @{
                    Name = $name
                    DNSHostName = $dnsName
                    Source = "ADQuery"
                }
            }
            
            Write-Host "  [+] Found $($computers.Count) computers via AD query" -ForegroundColor Green
            
        } catch {
            Write-Host "  [!] AD query failed: $_" -ForegroundColor Red
            Write-Host "  [*] Falling back to local network discovery..." -ForegroundColor Yellow
            
            # Fallback: Try ARP or local network
            try {
                $arpOutput = arp -a 2>$null
                $ips = $arpOutput | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' } | ForEach-Object {
                    if ($_ -match '(\d+\.\d+\.\d+\.\d+)') { $matches[1] }
                }
                
                foreach ($ip in $ips) {
                    try {
                        $hostname = [System.Net.Dns]::GetHostByAddress($ip).HostName
                        $computers += @{
                            Name = $hostname.Split('.')[0]
                            DNSHostName = $hostname
                            Source = "ARP"
                        }
                    } catch { }
                }
                
                Write-Host "  [+] Found $($computers.Count) computers via network discovery" -ForegroundColor Green
            } catch {
                Write-Host "  [-] Network discovery also failed" -ForegroundColor Yellow
            }
        }
    }
    
    # If still no computers, create a test list
    if ($computers.Count -eq 0) {
        Write-Host "  [!] No computers found. Using test list..." -ForegroundColor Yellow
        
        # Common computer names to test
        $testComputers = @(
            "DC01", "DC02", "FS01", "SRV01", 
            "EXCHANGE", "SQL", "WEB", "FILE",
            $env:COMPUTERNAME
        )
        
        foreach ($name in $testComputers) {
            $computers += @{
                Name = $name
                DNSHostName = "$name.$Domain".ToLower()
                Source = "TestList"
            }
        }
    }
    
    return $computers
}

# ==================== CHECK SHARES ====================
function Test-ShareAccess {
    param([string]$Computer, [string]$Share)
    
    $sharePath = "\\$Computer\$Share"
    
    try {
        # First test if we can even access the share
        $test = Get-ChildItem -Path $sharePath -ErrorAction Stop 2>$null
        
        # If we get here, we have access
        return @{
            Accessible = $true
            Path = $sharePath
            Error = $null
        }
    }
    catch [System.UnauthorizedAccessException] {
        return @{
            Accessible = $false
            Path = $sharePath
            Error = "Access Denied"
        }
    }
    catch [System.IO.DirectoryNotFoundException] {
        return @{
            Accessible = $false
            Path = $sharePath
            Error = "Share Not Found"
        }
    }
    catch {
        return @{
            Accessible = $false
            Path = $sharePath
            Error = $_.Exception.Message
        }
    }
}

function Scan-Computer {
    param([string]$ComputerName, [array]$SharesToTest)
    
    Write-Host "  [*] Scanning $ComputerName..." -ForegroundColor Gray
    
    $results = @{
        Computer = $ComputerName
        Online = $false
        AccessibleShares = @()
        ScanTime = Get-Date
    }
    
    # First check if computer is online
    try {
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop
        if (-not $ping) {
            Write-Host "    [-] $ComputerName is offline" -ForegroundColor DarkGray
            return $results
        }
        
        $results.Online = $true
        
    } catch {
        Write-Host "    [-] $ComputerName is unreachable" -ForegroundColor DarkGray
        return $results
    }
    
    # Test each share
    $foundShares = 0
    
    foreach ($share in $SharesToTest) {
        $accessResult = Test-ShareAccess -Computer $ComputerName -Share $share
        
        if ($accessResult.Accessible) {
            $foundShares++
            
            Write-Host "    [+] $($accessResult.Path)" -ForegroundColor Green
            
            $shareInfo = @{
                Name = $share
                Path = $accessResult.Path
                Type = if ($share -match '\$$') { "Admin" } else { "Regular" }
            }
            
            $results.AccessibleShares += $shareInfo
        }
    }
    
    if ($foundShares -gt 0) {
        Write-Host "    [+] Found $foundShares accessible shares" -ForegroundColor Green
    } else {
        Write-Host "    [-] No accessible shares found" -ForegroundColor DarkGray
    }
    
    return $results
}

# ==================== MAIN EXECUTION ====================
try {
    Write-Host "[*] Simple Share Scanner Starting..." -ForegroundColor Green
    
    # If no DC specified, use current
    if (-not $DomainController) {
        $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers[0].Name
        Write-Host "[*] No DC specified, using: $DomainController" -ForegroundColor Yellow
    }
    
    # Test connection first
    $connection = Test-DCConnection -DCName $DomainController
    
    if ($TestOnly) {
        Write-Host "`n[*] Test completed. Connection results:" -ForegroundColor Green
        Write-Host "    Ping: $(if($connection.Ping){'OK'}else{'FAILED'})" -ForegroundColor $(if($connection.Ping){'Green'}else{'Red'})
        Write-Host "    LDAP: $(if($connection.LDAP){'OK'}else{'FAILED'})" -ForegroundColor $(if($connection.LDAP){'Green'}else{'Red'})
        Write-Host "    SMB: $(($connection.NetBIOS){'OK'}else{'FAILED'})" -ForegroundColor $(if($connection.NetBIOS){'Green'}else{'Red'})
        Write-Host "    Domain: $($connection.Domain)" -ForegroundColor White
        exit 0
    }
    
    # Get domain name
    $domainName = $connection.Domain
    if (-not $domainName) {
        # Try to extract from DC name
        if ($DomainController -match '\.') {
            $domainName = $DomainController.Substring($DomainController.IndexOf('.') + 1).ToUpper()
        } else {
            $domainName = "LOCALDOMAIN"
        }
    }
    
    Write-Host "`n[*] Target Domain: $domainName" -ForegroundColor White
    
    # Get computers to scan
    $computers = Get-ComputersSimple -DCName $DomainController -Domain $domainName
    
    if ($computers.Count -eq 0) {
        Write-Host "[!] No computers found to scan" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "[*] Found $($computers.Count) computers to scan" -ForegroundColor Green
    
    # Define shares to test
    $sharesToTest = @(
        # Admin shares
        "C$", "ADMIN$", "IPC$", 
        # System shares
        "NETLOGON", "SYSVOL", 
        # Common shares
        "Users", "Public", "Share",
        "Data", "Files", "Backup",
        "IT", "Finance", "HR",
        "Software", "Apps", "Logs"
    )
    
    # Scan computers
    Write-Host "`n[*] Scanning for accessible shares..." -ForegroundColor Green
    Write-Host "[*] Testing each computer for $(sharesToTest.Count) common shares" -ForegroundColor Gray
    
    $scanResults = @()
    $onlineCount = 0
    $accessibleCount = 0
    $adminShareCount = 0
    
    $i = 0
    foreach ($computer in $computers) {
        $i++
        Write-Progress -Activity "Scanning Computers" -Status "$i of $($computers.Count)" -PercentComplete (($i / $computers.Count) * 100)
        
        # Try multiple name formats
        $namesToTry = @(
            $computer.DNSHostName,
            $computer.Name,
            "$($computer.Name).$domainName".ToLower()
        )
        
        foreach ($name in ($namesToTry | Select-Object -Unique)) {
            $result = Scan-Computer -ComputerName $name -SharesToTest $sharesToTest
            
            if ($result.Online) {
                $onlineCount++
                
                if ($result.AccessibleShares.Count -gt 0) {
                    $accessibleCount++
                    
                    # Count admin shares
                    $adminShares = $result.AccessibleShares | Where-Object { $_.Type -eq "Admin" }
                    if ($adminShares.Count -gt 0) {
                        $adminShareCount++
                    }
                    
                    $scanResults += $result
                }
                
                break  # Found accessible name, move to next computer
            }
        }
    }
    
    Write-Progress -Activity "Scanning Computers" -Completed
    
    # Compile results
    $totalSharesFound = ($scanResults | ForEach-Object { $_.AccessibleShares.Count } | Measure-Object -Sum).Sum
    
    $finalResults = @{
        Metadata = @{
            ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            DomainController = $DomainController
            Domain = $domainName
            ScanDuration = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
            Parameters = @{
                UseNetView = $UseNetView
                TestOnly = $TestOnly
            }
        }
        ConnectionTest = $connection
        ScanSummary = @{
            TotalComputersFound = $computers.Count
            ComputersOnline = $onlineCount
            ComputersWithAccessibleShares = $accessibleCount
            TotalAccessibleShares = $totalSharesFound
            AdminSharesAccessible = $adminShareCount
        }
        AccessibleShares = @()
    }
    
    # List all accessible shares
    foreach ($result in $scanResults) {
        foreach ($share in $result.AccessibleShares) {
            $finalResults.AccessibleShares += @{
                Computer = $result.Computer
                ShareName = $share.Name
                SharePath = $share.Path
                ShareType = $share.Type
            }
        }
    }
    
    # Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    $finalResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Create summary report
    $summaryPath = $OutputPath -replace "\.json$", "_summary.txt"
    
    $summary = @"
SIMPLE SHARE SCAN - SUMMARY REPORT
===============================================================
Scan Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Target: $DomainController
Domain: $domainName
Scan Duration: $($finalResults.Metadata.ScanDuration)

CONNECTION TEST:
  Ping: $(if($connection.Ping){'OK'}else{'FAILED'})
  LDAP (389): $(if($connection.LDAP){'OK'}else{'FAILED'})
  SMB (445): $(if($connection.NetBIOS){'OK'}else{'FAILED'})

SCAN RESULTS:
  Computers discovered: $($computers.Count)
  Computers online: $onlineCount
  Computers with accessible shares: $accessibleCount
  Total accessible shares found: $totalSharesFound
  Admin shares accessible: $adminShareCount

ACCESSIBLE SHARES:
$(
    if ($finalResults.AccessibleShares.Count -gt 0) {
        $i = 0
        foreach ($share in $finalResults.AccessibleShares) {
            $i++
            "$i. $($share.SharePath) ($($share.ShareType))"
        }
    } else {
        "  None found"
    }
)

SECURITY NOTES:
$(
    if ($adminShareCount -gt 0) {
        "  [!] WARNING: Admin shares are accessible!"
        "      This could indicate misconfigured share permissions."
        "      Admin shares (C$, ADMIN$) should be restricted."
    } else {
        "  No critical security issues detected."
    }
)

TROUBLESHOOTING:
  If no shares were found:
  1. Check if you're on the domain network
  2. Verify firewall allows SMB (port 445)
  3. Try running as Administrator
  4. Use -UseNetView flag for network discovery
  5. Try specifying DC with IP address: -DomainController '192.168.1.10'

NOTES:
- This is a simple share scanner focusing on common shares
- Results are saved to: $OutputPath
- Use findings for authorized security assessments only
"@
    
    $summary | Out-File -FilePath $summaryPath -Encoding UTF8
    
    # Display final summary
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host " SCAN COMPLETE" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    Write-Host "Domain: $domainName" -ForegroundColor White
    Write-Host "Duration: $($finalResults.Metadata.ScanDuration)" -ForegroundColor White
    
    Write-Host "`nRESULTS:" -ForegroundColor Yellow
    Write-Host "  Computers scanned: $($computers.Count)" -ForegroundColor White
    Write-Host "  Computers online: $onlineCount" -ForegroundColor White
    Write-Host "  Computers with shares: $accessibleCount" -ForegroundColor $(if($accessibleCount -gt 0){'Green'}else{'White'})
    Write-Host "  Total shares found: $totalSharesFound" -ForegroundColor $(if($totalSharesFound -gt 0){'Green'}else{'White'})
    Write-Host "  Admin shares: $adminShareCount" -ForegroundColor $(if($adminShareCount -gt 0){'Red'}else{'Green'})
    
    if ($adminShareCount -gt 0) {
        Write-Host "`n[!] SECURITY WARNING!" -ForegroundColor Red
        Write-Host "    Admin shares are accessible. This could allow:" -ForegroundColor Yellow
        Write-Host "    - Lateral movement to other systems" -ForegroundColor Yellow
        Write-Host "    - Data theft or modification" -ForegroundColor Yellow
        Write-Host "    - Malware deployment" -ForegroundColor Yellow
    }
    
    Write-Host "`nOutput saved to:" -ForegroundColor Green
    Write-Host "  $OutputPath" -ForegroundColor White
    Write-Host "  $summaryPath" -ForegroundColor White
    
    Write-Host "`n[+] Scan completed!" -ForegroundColor Green
    
}
catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
    Write-Host "[!] Stack trace: $($_.Exception.StackTrace)" -ForegroundColor DarkRed
}
