# Save as DomainShareScanner.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainController,
    
    [string]$OutputPath = "domain_shares.json",
    [switch]$QuickScan,
    [switch]$DeepScan,
    [int]$MaxComputers = 100
)

$ErrorActionPreference = "Continue"
$startTime = Get-Date

Write-Host @"
===============================================================
   ____                _        ____  _               
  / __ \ ___  _ __ ___| |__    / __ \| |              
 / / _' / _ \| '__/ __| '_ \  / / _' | |__   ___ _ __ 
| | (_| (_) | | | (__| | | |/ / (_| | '_ \ / _ \ '__|
 \ \__,_\___/|_|  \___|_| |_/_/ \__,_|_.__/ \___|_|   
  \____/                                              
        Targeted Domain Share Scanner
===============================================================
"@ -ForegroundColor Cyan

# ==================== TARGETED FUNCTIONS ====================
function Get-TargetedComputers {
    param([string]$DCName)
    
    Write-Host "[*] Getting computers from domain controller: $DCName" -ForegroundColor Green
    
    $computers = @()
    
    try {
        # First, get the domain DN from the DC
        $rootDSE = [ADSI]"LDAP://$DCName/RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        $domainName = ($domainDN -replace 'DC=','' -replace ',','.' -replace 'DC=','').ToUpper()
        
        Write-Host "  [+] Domain: $domainName" -ForegroundColor Green
        Write-Host "  [+] Domain DN: $domainDN" -ForegroundColor Gray
        
        # Now query computers from that domain via the specified DC
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$DCName/$domainDN"
        $searcher.Filter = "(objectClass=computer)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
        
        $results = $searcher.FindAll()
        
        Write-Host "  [*] Querying computers via LDAP://$DCName/$domainDN" -ForegroundColor Gray
        
        foreach ($result in $results) {
            $computerName = if ($result.Properties["dNSHostName"]) { 
                $result.Properties["dNSHostName"][0] 
            } else { 
                if ($result.Properties["name"]) { 
                    $result.Properties["name"][0] + "." + $domainName.ToLower()
                } else {
                    continue
                }
            }
            
            $os = if ($result.Properties["operatingSystem"]) { 
                $result.Properties["operatingSystem"][0] 
            } else { 
                "Unknown" 
            }
            
            $computers += @{
                Name = $result.Properties["name"][0]
                DNSHostName = $computerName
                OperatingSystem = $os
                IsServer = $os -like "*Server*"
            }
        }
        
        Write-Host "  [+] Found $($computers.Count) computers in domain $domainName" -ForegroundColor Green
        
        return @{
            DomainName = $domainName
            DomainDN = $domainDN
            Computers = $computers
        }
        
    } catch {
        Write-Host "  [!] Failed to get computers from $DCName : $_" -ForegroundColor Red
        return $null
    }
}

function Test-ComputerAccess {
    param([string]$Computer, [string]$Domain)
    
    # Try multiple methods to test if computer is accessible
    
    # Method 1: Ping
    try {
        $ping = Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction Stop
        if ($ping) { return $true }
    } catch { }
    
    # Method 2: Try with domain suffix
    if (-not $Computer.Contains(".")) {
        try {
            $fqdn = "$Computer.$Domain"
            $ping = Test-Connection -ComputerName $fqdn -Count 1 -Quiet -ErrorAction Stop
            if ($ping) { 
                return $true, $fqdn
            }
        } catch { }
    }
    
    # Method 3: Try short name
    $shortName = $Computer.Split('.')[0]
    if ($shortName -ne $Computer) {
        try {
            $ping = Test-Connection -ComputerName $shortName -Count 1 -Quiet -ErrorAction Stop
            if ($ping) { 
                return $true, $shortName
            }
        } catch { }
    }
    
    return $false, $Computer
}

function Scan-ComputerForShares {
    param([string]$Computer, [string]$ResolvedName, [switch]$Quick)
    
    Write-Host "    [*] Scanning $ResolvedName..." -ForegroundColor Gray
    
    $results = @{
        Computer = $Computer
        ResolvedName = $ResolvedName
        Online = $true
        AccessibleShares = @()
        ScanTime = Get-Date
        Error = $null
    }
    
    # Define shares to test
    $sharesToTest = @(
        "C$", "ADMIN$", "IPC$", 
        "NETLOGON", "SYSVOL", 
        "Users", "Public", "Share",
        "Data", "Files", "Backup",
        "IT", "Finance", "HR"
    )
    
    $testedCount = 0
    $accessibleCount = 0
    
    foreach ($share in $sharesToTest) {
        $sharePath = "\\$ResolvedName\$share"
        $testedCount++
        
        try {
            # Try to access the share
            $test = Get-ChildItem -Path $sharePath -ErrorAction Stop 2>$null
            
            Write-Host "      [+] ACCESSIBLE: $sharePath" -ForegroundColor Green
            
            $shareInfo = @{
                Name = $share
                Path = $sharePath
                Type = if ($share -match '\$$') { "Admin" } else { "Regular" }
                Accessible = $true
            }
            
            # Try to get some file info if not quick scan
            if (-not $Quick) {
                try {
                    $files = Get-ChildItem -Path $sharePath -ErrorAction Stop | Select-Object -First 5
                    $shareInfo.SampleFiles = @($files | ForEach-Object { $_.Name })
                    $shareInfo.FileCount = (Get-ChildItem -Path $sharePath -ErrorAction SilentlyContinue | Measure-Object).Count
                } catch {
                    $shareInfo.SampleFiles = @()
                    $shareInfo.FileCount = 0
                }
            }
            
            $results.AccessibleShares += $shareInfo
            $accessibleCount++
            
            # In quick mode, stop after first admin share or 2 regular shares
            if ($Quick -and $accessibleCount -ge 2) {
                break
            }
            
        } catch {
            # Share not accessible or doesn't exist
            continue
        }
    }
    
    $results.TotalSharesTested = $testedCount
    $results.AccessibleShareCount = $accessibleCount
    
    return $results
}

function Find-InterestingFilesInShare {
    param([string]$SharePath, [int]$MaxDepth = 1)
    
    $interestingFiles = @()
    $interestingPatterns = @(
        "*.txt", "*.xml", "*.config", "*.ini", 
        "*.bat", "*.ps1", "*.vbs", "*.cmd",
        "*.sql", "*.mdb", "*.accdb",
        "*.xls*", "*.doc*", "*.pdf",
        "pass*.txt", "cred*.txt", "backup*", 
        "secret*", "*.pwd", "*.kdbx"
    )
    
    try {
        foreach ($pattern in $interestingPatterns) {
            try {
                $files = Get-ChildItem -Path $SharePath -Filter $pattern -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue | Select-Object -First 10
                
                foreach ($file in $files) {
                    $interestingFiles += @{
                        Name = $file.Name
                        Path = $file.FullName
                        Size = "{0:N2} KB" -f ($file.Length / 1KB)
                        LastWrite = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                        Extension = $file.Extension
                    }
                }
            } catch { }
        }
    } catch { }
    
    return $interestingFiles
}

# ==================== MAIN EXECUTION ====================
try {
    Write-Host "[*] Starting Targeted Domain Share Scanner" -ForegroundColor Green
    Write-Host "[*] Target Domain Controller: $DomainController" -ForegroundColor White
    Write-Host "[*] Max Computers to Scan: $MaxComputers" -ForegroundColor Gray
    
    # Step 1: Get computers from the specified domain controller
    $domainData = Get-TargetedComputers -DCName $DomainController
    
    if (-not $domainData) {
        Write-Host "[!] Failed to get computers from $DomainController" -ForegroundColor Red
        Write-Host "[*] Trying alternative methods..." -ForegroundColor Yellow
        
        # Fallback: Try to get domain from DC name
        if ($DomainController -match '\.') {
            $domainName = $DomainController.Substring($DomainController.IndexOf('.') + 1).ToUpper()
            Write-Host "[*] Inferred domain: $domainName" -ForegroundColor Yellow
            
            # Try net view for this domain
            try {
                $netOutput = net view /domain:$domainName 2>$null
                $computers = $netOutput | Where-Object { $_ -match '\\\\' } | ForEach-Object { 
                    @{ Name = ($_.Trim() -replace '\\\\', ''); DNSHostName = ($_.Trim() -replace '\\\\', ''); OperatingSystem = "Unknown"; IsServer = $false }
                }
                
                if ($computers.Count -gt 0) {
                    $domainData = @{
                        DomainName = $domainName
                        DomainDN = ""
                        Computers = $computers
                    }
                    Write-Host "[+] Found $($computers.Count) computers via net view" -ForegroundColor Green
                }
            } catch {
                Write-Host "[!] Net view also failed" -ForegroundColor Red
                exit 1
            }
        }
        
        if (-not $domainData) {
            exit 1
        }
    }
    
    # Step 2: Filter and limit computers
    $allComputers = $domainData.Computers
    Write-Host "[*] Total computers in domain: $($allComputers.Count)" -ForegroundColor White
    
    # Prioritize servers and DCs
    $servers = $allComputers | Where-Object { $_.IsServer -or $_.Name -like "*DC*" -or $_.Name -like "*SRV*" }
    $workstations = $allComputers | Where-Object { -not $_.IsServer }
    
    # Select computers to scan
    $computersToScan = @()
    if ($servers.Count -gt 0) {
        $computersToScan += $servers | Select-Object -First ($MaxComputers / 2)
    }
    if ($workstations.Count -gt 0) {
        $computersToScan += $workstations | Select-Object -First ($MaxComputers / 2)
    }
    
    if ($computersToScan.Count -eq 0) {
        $computersToScan = $allComputers | Select-Object -First $MaxComputers
    }
    
    Write-Host "[*] Selected $($computersToScan.Count) computers for scanning" -ForegroundColor Green
    Write-Host "    - Servers: $(($computersToScan | Where-Object { $_.IsServer }).Count)" -ForegroundColor Gray
    Write-Host "    - Workstations: $(($computersToScan | Where-Object { -not $_.IsServer }).Count)" -ForegroundColor Gray
    
    # Step 3: Scan for accessible shares
    Write-Host "`n[*] Scanning for accessible shares..." -ForegroundColor Green
    
    $scanResults = @()
    $onlineCount = 0
    $accessibleCount = 0
    $adminShareCount = 0
    
    $i = 0
    foreach ($computer in $computersToScan) {
        $i++
        Write-Progress -Activity "Scanning Computers" -Status "Computer $i of $($computersToScan.Count)" -PercentComplete (($i / $computersToScan.Count) * 100)
        
        Write-Host "  [$i/$($computersToScan.Count)] Testing: $($computer.Name)" -ForegroundColor Cyan
        
        # Test if computer is accessible
        $accessible, $resolvedName = Test-ComputerAccess -Computer $computer.DNSHostName -Domain $domainData.DomainName
        
        if ($accessible) {
            $onlineCount++
            
            # Scan for shares
            $result = Scan-ComputerForShares -Computer $computer.Name -ResolvedName $resolvedName -Quick:$QuickScan
            
            if ($result.AccessibleShareCount -gt 0) {
                $accessibleCount++
                
                # Deep scan if requested
                if ($DeepScan) {
                    foreach ($share in $result.AccessibleShares) {
                        if ($share.Accessible) {
                            $interestingFiles = Find-InterestingFilesInShare -SharePath $share.Path
                            $share.InterestingFiles = $interestingFiles
                            $share.InterestingFileCount = $interestingFiles.Count
                            
                            if ($share.Type -eq "Admin") {
                                $adminShareCount++
                            }
                        }
                    }
                }
                
                $scanResults += $result
                
                Write-Host "    [+] Found $($result.AccessibleShareCount) accessible shares" -ForegroundColor Green
            } else {
                Write-Host "    [-] No accessible shares found" -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "    [-] Offline or unreachable" -ForegroundColor DarkGray
        }
    }
    
    Write-Progress -Activity "Scanning Computers" -Completed
    
    # Step 4: Compile results
    $totalAccessibleShares = ($scanResults | ForEach-Object { $_.AccessibleShareCount } | Measure-Object -Sum).Sum
    $totalInterestingFiles = ($scanResults | ForEach-Object { 
        $_.AccessibleShares | ForEach-Object { $_.InterestingFileCount }
    } | Measure-Object -Sum).Sum
    
    $finalResults = @{
        Metadata = @{
            ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TargetDomainController = $DomainController
            Domain = $domainData.DomainName
            ScanType = if ($DeepScan) { "Deep" } elseif ($QuickScan) { "Quick" } else { "Standard" }
            ScanDuration = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
            Parameters = @{
                MaxComputers = $MaxComputers
                QuickScan = $QuickScan
                DeepScan = $DeepScan
            }
        }
        DomainInfo = $domainData
        ScanResults = $scanResults
        Statistics = @{
            TotalComputersFound = $allComputers.Count
            ComputersScanned = $computersToScan.Count
            ComputersOnline = $onlineCount
            ComputersWithAccessibleShares = $accessibleCount
            TotalAccessibleShares = $totalAccessibleShares
            AdminSharesAccessible = $adminShareCount
            InterestingFilesFound = $totalInterestingFiles
        }
        SecurityFindings = @()
    }
    
    # Step 5: Identify security findings
    if ($adminShareCount -gt 0) {
        $finalResults.SecurityFindings += @{
            Severity = "CRITICAL"
            Type = "AdminShareAccess"
            Description = "$adminShareCount admin shares are accessible"
            Details = $scanResults | ForEach-Object {
                $_.AccessibleShares | Where-Object { $_.Type -eq "Admin" } | ForEach-Object {
                    "$($_.Path)"
                }
            }
        }
    }
    
    if ($accessibleCount -gt 0) {
        $finalResults.SecurityFindings += @{
            Severity = "HIGH"
            Type = "ShareAccess"
            Description = "Access to $accessibleCount computers with $totalAccessibleShares shares"
        }
    }
    
    # Step 6: Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    
    $finalResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Step 7: Create summary report
    $summaryPath = $OutputPath -replace "\.json$", "_summary.txt"
    
    $summary = @"
TARGETED DOMAIN SHARE SCAN - SUMMARY REPORT
===============================================================
Scan Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Target Domain Controller: $DomainController
Domain: $($domainData.DomainName)
Scan Duration: $($finalResults.Metadata.ScanDuration)

SCAN PARAMETERS:
  Max Computers: $MaxComputers
  Quick Scan: $QuickScan
  Deep Scan: $DeepScan

RESULTS SUMMARY:
  Total computers in domain: $($allComputers.Count)
  Computers scanned: $($computersToScan.Count)
  Computers online: $onlineCount
  Computers with accessible shares: $accessibleCount
  Total accessible shares: $totalAccessibleShares
  Admin shares accessible: $adminShareCount
  Interesting files found: $totalInterestingFiles

SECURITY FINDINGS:
$(
    if ($finalResults.SecurityFindings.Count -gt 0) {
        foreach ($finding in $finalResults.SecurityFindings) {
            "  [$($finding.Severity)] $($finding.Description)"
            if ($finding.Details) {
                foreach ($detail in $finding.Details) {
                    "      - $detail"
                }
            }
        }
    } else {
        "  No significant security findings."
    }
)

ACCESSIBLE SHARES FOUND:
$(
    if ($totalAccessibleShares -gt 0) {
        $shareCount = 0
        foreach ($result in $scanResults) {
            foreach ($share in $result.AccessibleShares) {
                $shareCount++
                "  $shareCount. $($share.Path)"
                if ($share.InterestingFileCount -gt 0) {
                    "      Interesting files: $($share.InterestingFileCount)"
                }
            }
        }
    } else {
        "  No accessible shares found."
    }
)

RECOMMENDATIONS:
1. Review and secure admin shares (C$, ADMIN$)
2. Implement share permissions and access controls
3. Remove unnecessary shares
4. Monitor share access logs
5. Educate users about file sharing security

NOTES:
- This scan targeted domain controller: $DomainController
- Results are specific to domain: $($domainData.DomainName)
- Complete data saved to: $OutputPath
- Use findings for authorized security improvements only
"@
    
    $summary | Out-File -FilePath $summaryPath -Encoding UTF8
    
    # Step 8: Display final summary
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host " TARGETED SHARE SCAN COMPLETE" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    Write-Host "Domain: $($domainData.DomainName)" -ForegroundColor White
    Write-Host "Domain Controller: $DomainController" -ForegroundColor White
    Write-Host "Scan Duration: $($finalResults.Metadata.ScanDuration)" -ForegroundColor White
    
    Write-Host "`nSCAN RESULTS:" -ForegroundColor Yellow
    Write-Host "  Computers online: $onlineCount/$($computersToScan.Count)" -ForegroundColor White
    Write-Host "  Computers with shares: $accessibleCount" -ForegroundColor $(if($accessibleCount -gt 0){"Green"}else{"White"})
    Write-Host "  Total shares found: $totalAccessibleShares" -ForegroundColor $(if($totalAccessibleShares -gt 0){"Green"}else{"White"})
    Write-Host "  Admin shares: $adminShareCount" -ForegroundColor $(if($adminShareCount -gt 0){"Red"}else{"Green"})
    Write-Host "  Interesting files: $totalInterestingFiles" -ForegroundColor $(if($totalInterestingFiles -gt 0){"Yellow"}else{"White"})
    
    if ($adminShareCount -gt 0) {
        Write-Host "`n[!] CRITICAL SECURITY ISSUE!" -ForegroundColor Red
        Write-Host "    Admin shares are accessible without proper restrictions!" -ForegroundColor Red
        Write-Host "    This allows potential lateral movement and data exposure." -ForegroundColor Red
    }
    
    Write-Host "`nOUTPUT FILES:" -ForegroundColor Green
    Write-Host "  Complete Data: $OutputPath" -ForegroundColor White
    Write-Host "  Summary Report: $summaryPath" -ForegroundColor White
    
    Write-Host "`n[+] Share scanning completed successfully!" -ForegroundColor Green
    
}
catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
    Write-Host "[!] Error details: $($_.Exception.Message)" -ForegroundColor DarkRed
    Write-Host "[!] Stack trace: $($_.Exception.StackTrace)" -ForegroundColor DarkRed
}
