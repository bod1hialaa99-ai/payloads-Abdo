# Save as SimpleShareScanner.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainController,
    
    [string]$OutputPath = "shares_results.json",
    [switch]$TestOnly,
    [switch]$UseNetBIOS
)

$startTime = Get-Date

Write-Host @"
===============================================================
    ____  _                           
   / __ \(_)___  ____  ___  __________
  / /_/ / / __ \/ __ \/ _ \/ ___/ ___/
 / ____/ / /_/ / /_/ /  __/ /  (__  ) 
/_/   /_/\____/ .___/\___/_/  /____/  
             /_/                      
    Simple Targeted Share Scanner
===============================================================
"@ -ForegroundColor Cyan

# ==================== SIMPLE CONNECTION TEST ====================
function Test-SimpleConnection {
    param([string]$DCName)
    
    Write-Host "[*] Testing connection to: $DCName" -ForegroundColor Yellow
    
    # Remove any leading/trailing spaces
    $DCName = $DCName.Trim()
    
    # Try multiple connection methods
    $methods = @(
        @{Name="Ping Test"; Action={ Test-Connection -ComputerName $DCName -Count 1 -Quiet }},
        @{Name="LDAP Port 389"; Action={ 
            try { 
                $socket = New-Object System.Net.Sockets.TcpClient
                $socket.Connect($DCName, 389)
                $socket.Close()
                $true
            } catch { $false }
        }},
        @{Name="LDAPS Port 636"; Action={ 
            try { 
                $socket = New-Object System.Net.Sockets.TcpClient
                $socket.Connect($DCName, 636)
                $socket.Close()
                $true
            } catch { $false }
        }},
        @{Name="NetBIOS (Port 445)"; Action={ 
            try { 
                $socket = New-Object System.Net.Sockets.TcpClient
                $socket.Connect($DCName, 445)
                $socket.Close()
                $true
            } catch { $false }
        }}
    )
    
    $results = @()
    foreach ($method in $methods) {
        try {
            $success = & $method.Action
            $results += "$($method.Name): $(if($success){'SUCCESS'}else{'FAILED'})"
            Write-Host "  [$($method.Name)]: $(if($success){'✓' -f 'Green'}else{'✗' -f 'Red'})" -ForegroundColor $(if($success){'Green'}else{'DarkYellow'})
        } catch {
            $results += "$($method.Name): ERROR - $_"
            Write-Host "  [$($method.Name)]: ERROR" -ForegroundColor Red
        }
    }
    
    # Try to get domain info
    $domainInfo = $null
    try {
        Write-Host "  [*] Getting domain info..." -ForegroundColor Gray
        $rootDSE = [ADSI]"LDAP://$DCName/RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        $domainName = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
        
        $domainInfo = @{
            DomainName = $domainName
            DomainDN = $domainDN
            ServerName = $rootDSE.dnsHostName
        }
        
        Write-Host "  [+] Domain: $domainName" -ForegroundColor Green
        Write-Host "  [+] Server: $($rootDSE.dnsHostName)" -ForegroundColor Green
        
    } catch {
        Write-Host "  [-] Could not get domain info: $_" -ForegroundColor Yellow
        
        # Try to infer domain from DC name
        if ($DCName -match '\.') {
            $parts = $DCName -split '\.'
            if ($parts.Count -ge 2) {
                $inferredDomain = ($parts[1..($parts.Count-1)] -join '.').ToUpper()
                $domainInfo = @{
                    DomainName = $inferredDomain
                    DomainDN = "DC=" + ($inferredDomain -replace '\.', ',DC=')
                    ServerName = $DCName
                }
                Write-Host "  [*] Inferred domain: $inferredDomain" -ForegroundColor Yellow
            }
        }
    }
    
    return @{
        DCName = $DCName
        DomainInfo = $domainInfo
        ConnectionTests = $results
        Success = ($domainInfo -ne $null)
    }
}

# ==================== SIMPLE COMPUTER DISCOVERY ====================
function Get-ComputersSimple {
    param([string]$DCName, [string]$DomainName, [switch]$UseNetBIOSMode)
    
    Write-Host "`n[*] Discovering computers in domain: $DomainName" -ForegroundColor Green
    
    $computers = @()
    
    # Method 1: Use net view (works without special permissions)
    try {
        Write-Host "  [*] Using net view to discover computers..." -ForegroundColor Gray
        
        if ($UseNetBIOSMode) {
            # Extract NetBIOS name if DC is in FQDN format
            $netbiosName = $DCName.Split('.')[0]
            $netViewOutput = net view /domain:$netbiosName 2>$null
        } else {
            $netViewOutput = net view /domain:$DomainName 2>$null
        }
        
        if ($netViewOutput) {
            $computerNames = $netViewOutput | Where-Object { $_ -match '\\\\' } | ForEach-Object { 
                $_.Trim() -replace '\\\\', '' 
            }
            
            foreach ($name in $computerNames) {
                $computers += @{
                    Name = $name
                    DNSHostName = if ($name -notmatch '\.') { "$name.$DomainName".ToLower() } else { $name }
                    Type = "Unknown"
                }
            }
            
            Write-Host "  [+] Found $($computers.Count) computers via net view" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [-] net view failed: $_" -ForegroundColor Yellow
    }
    
    # Method 2: Try AD query (if we have permission)
    if ($computers.Count -eq 0) {
        try {
            Write-Host "  [*] Trying AD query..." -ForegroundColor Gray
            
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(objectClass=computer)"
            $searcher.PageSize = 100
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
            
            $results = $searcher.FindAll()
            
            foreach ($result in $results) {
                $name = $result.Properties["name"][0]
                $dnsName = if ($result.Properties["dNSHostName"]) { 
                    $result.Properties["dNSHostName"][0] 
                } else { 
                    "$name.$DomainName".ToLower() 
                }
                
                $computers += @{
                    Name = $name
                    DNSHostName = $dnsName
                    Type = "AD Computer"
                }
            }
            
            Write-Host "  [+] Found $($computers.Count) computers via AD query" -ForegroundColor Green
            
        } catch {
            Write-Host "  [-] AD query failed: $_" -ForegroundColor Yellow
        }
    }
    
    # If still no computers, create some common targets
    if ($computers.Count -eq 0) {
        Write-Host "  [*] Creating common target list..." -ForegroundColor Yellow
        
        $commonTargets = @(
            "DC01", "DC02", "FS01", "FS02", 
            "SRV01", "SRV02", "EXCH01", "SQL01"
        )
        
        foreach ($target in $commonTargets) {
            $computers += @{
                Name = $target
                DNSHostName = "$target.$DomainName".ToLower()
                Type = "Common Target"
            }
        }
        
        Write-Host "  [+] Created $($computers.Count) common targets" -ForegroundColor Yellow
    }
    
    return $computers
}

# ==================== SIMPLE SHARE TEST ====================
function Test-ShareAccess {
    param([string]$Computer, [string]$Share)
    
    $sharePath = "\\$Computer\$Share"
    
    try {
        # Try to list one item
        $test = Get-ChildItem -Path $sharePath -ErrorAction Stop 2>$null
        return $true
    } catch {
        return $false
    }
}

function Test-CommonShares {
    param([string]$Computer)
    
    Write-Host "    [*] Testing $Computer..." -ForegroundColor Gray
    
    $results = @{
        Computer = $Computer
        Online = $false
        Shares = @()
        TestTime = Get-Date
    }
    
    # First, test if computer is online
    try {
        $ping = Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction Stop
        if (-not $ping) {
            Write-Host "      [-] Offline" -ForegroundColor DarkGray
            return $results
        }
        
        $results.Online = $true
    } catch {
        Write-Host "      [-] Cannot reach" -ForegroundColor DarkGray
        return $results
    }
    
    # Test common shares
    $commonShares = @(
        "C$", "ADMIN$", "IPC$", 
        "NETLOGON", "SYSVOL",
        "Users", "Public", "Share",
        "Data", "Files", "Backup"
    )
    
    foreach ($share in $commonShares) {
        $accessible = Test-ShareAccess -Computer $Computer -Share $share
        
        if ($accessible) {
            Write-Host "      [+] $share" -ForegroundColor Green
            
            $shareInfo = @{
                Name = $share
                Path = "\\$Computer\$share"
                Type = if ($share -match '\$$') { "Admin" } else { "Regular" }
            }
            
            # Try to get some basic info
            try {
                $items = Get-ChildItem -Path "\\$Computer\$share" -ErrorAction Stop | Select-Object -First 3
                $shareInfo.SampleFiles = @($items | ForEach-Object { $_.Name })
            } catch {
                $shareInfo.SampleFiles = @()
            }
            
            $results.Shares += $shareInfo
        }
    }
    
    if ($results.Shares.Count -gt 0) {
        Write-Host "      [+] Found $($results.Shares.Count) accessible shares" -ForegroundColor Green
    } else {
        Write-Host "      [-] No accessible shares" -ForegroundColor DarkYellow
    }
    
    return $results
}

# ==================== MAIN EXECUTION ====================
try {
    Write-Host "[*] Starting Simple Share Scanner" -ForegroundColor Green
    Write-Host "[*] Target: $DomainController" -ForegroundColor White
    Write-Host "[*] UseNetBIOS: $UseNetBIOS" -ForegroundColor Gray
    
    # Step 1: Test connection
    $connection = Test-SimpleConnection -DCName $DomainController
    
    if (-not $connection.Success) {
        Write-Host "`n[!] WARNING: Could not verify domain connection" -ForegroundColor Red
        Write-Host "[*] You may not have access to this domain" -ForegroundColor Yellow
        Write-Host "[*] Or the domain controller may be unreachable" -ForegroundColor Yellow
        
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -notmatch '^y') {
            exit 1
        }
        
        # Create basic domain info
        $connection.DomainInfo = @{
            DomainName = "UNKNOWN"
            DomainDN = ""
            ServerName = $DomainController
        }
    }
    
    if ($TestOnly) {
        Write-Host "`n[+] Test completed. Use without -TestOnly to scan for shares." -ForegroundColor Green
        exit 0
    }
    
    # Step 2: Discover computers
    $computers = Get-ComputersSimple -DCName $DomainController `
        -DomainName $connection.DomainInfo.DomainName `
        -UseNetBIOSMode:$UseNetBIOS
    
    if ($computers.Count -eq 0) {
        Write-Host "[!] No computers found to scan" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`n[*] Found $($computers.Count) computers to test" -ForegroundColor Green
    Write-Host "[*] Testing share accessibility..." -ForegroundColor Green
    
    # Step 3: Test shares
    $scanResults = @()
    $onlineCount = 0
    $shareCount = 0
    $adminShareCount = 0
    
    $i = 0
    foreach ($computer in $computers) {
        $i++
        $computerName = $computer.DNSHostName
        
        Write-Host "  [$i/$($computers.Count)] $computerName" -ForegroundColor Cyan
        
        # Try multiple name formats if needed
        $testNames = @($computerName)
        if ($computerName -match '\.') {
            $testNames += $computerName.Split('.')[0]  # Short name
        }
        
        foreach ($testName in $testNames) {
            $result = Test-CommonShares -Computer $testName
            
            if ($result.Online) {
                $onlineCount++
                
                if ($result.Shares.Count -gt 0) {
                    $shareCount += $result.Shares.Count
                    $adminShareCount += ($result.Shares | Where-Object { $_.Type -eq "Admin" }).Count
                    
                    $scanResults += $result
                    
                    # Stop testing names if we found shares
                    break
                }
            }
        }
        
        # Progress
        [int]$percent = ($i / $computers.Count) * 100
        Write-Progress -Activity "Scanning Shares" -Status "$i of $($computers.Count) computers" -PercentComplete $percent
    }
    
    Write-Progress -Activity "Scanning Shares" -Completed
    
    # Step 4: Compile results
    $finalResults = @{
        Metadata = @{
            ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Target = $DomainController
            Domain = $connection.DomainInfo.DomainName
            TotalComputers = $computers.Count
            ScanDuration = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
        }
        ConnectionInfo = $connection
        Computers = $computers
        ScanResults = $scanResults
        Summary = @{
            OnlineComputers = $onlineCount
            ComputersWithShares = $scanResults.Count
            TotalSharesFound = $shareCount
            AdminSharesFound = $adminShareCount
        }
    }
    
    # Step 5: Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    $finalResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Step 6: Display summary
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host " SCAN COMPLETE" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    Write-Host "Target Domain: $($connection.DomainInfo.DomainName)" -ForegroundColor White
    Write-Host "Scan Duration: $($finalResults.Metadata.ScanDuration)" -ForegroundColor White
    
    Write-Host "`nRESULTS:" -ForegroundColor Yellow
    Write-Host "  Computers tested: $($computers.Count)" -ForegroundColor White
    Write-Host "  Computers online: $onlineCount" -ForegroundColor White
    Write-Host "  Computers with shares: $($scanResults.Count)" -ForegroundColor $(if($scanResults.Count -gt 0){'Green'}else{'White'})
    Write-Host "  Total shares found: $shareCount" -ForegroundColor $(if($shareCount -gt 0){'Green'}else{'White'})
    Write-Host "  Admin shares (C$, ADMIN$): $adminShareCount" -ForegroundColor $(if($adminShareCount -gt 0){'Red'}else{'Green'})
    
    # Show accessible shares
    if ($shareCount -gt 0) {
        Write-Host "`nACCESSIBLE SHARES:" -ForegroundColor Green
        foreach ($result in $scanResults) {
            foreach ($share in $result.Shares) {
                Write-Host "  - $($share.Path)" -ForegroundColor $(if($share.Type -eq 'Admin'){'Red'}else{'White'})
            }
        }
    }
    
    # Security warnings
    if ($adminShareCount -gt 0) {
        Write-Host "`n[!] SECURITY WARNING!" -ForegroundColor Red
        Write-Host "    Admin shares are accessible. This is a critical security issue!" -ForegroundColor Red
    }
    
    Write-Host "`nOutput saved to: $OutputPath" -ForegroundColor Green
    
} catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
    Write-Host "[!] Error occurred at line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor DarkRed
}
