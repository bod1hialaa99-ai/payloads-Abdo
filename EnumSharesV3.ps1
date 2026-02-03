# Save as Find-DataShares.ps1
param(
    [string]$DomainController,
    [string]$OutputPath = "data_shares.txt",
    [int]$MaxComputers = 30,
    [switch]$QuickScan,
    [switch]$TestOnly
)

Write-Host "[*] Data-Containing Share Finder v3.0" -ForegroundColor Green
Write-Host "[*] Target: $DomainController" -ForegroundColor Cyan

# ==================== ENHANCED FUNCTIONS ====================
function Get-ComputersFromDC {
    param([string]$DC)
    
    Write-Host "[*] Getting computers from $DC..." -ForegroundColor Yellow
    
    try {
        $rootDSE = [ADSI]"LDAP://$DC/RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        $domainName = $rootDSE.rootDomainNamingContext -replace 'DC=','' -replace ',','.' -replace 'DC=',''
        
        Write-Host "  [+] Domain: $domainName" -ForegroundColor Green
        
        # Get servers and workstations separately
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$DC/$domainDN")
        $searcher.Filter = "(objectClass=computer)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
        $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
        
        $servers = @()
        $workstations = @()
        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $compName = $result.Properties["name"][0]
            $dnsName = if ($result.Properties["dNSHostName"]) { $result.Properties["dNSHostName"][0] } else { $compName }
            $os = if ($result.Properties["operatingSystem"]) { $result.Properties["operatingSystem"][0] } else { "" }
            
            $computerInfo = @{
                Name = $compName
                DNSHostName = $dnsName
                FQDN = if ($dnsName.Contains('.')) { $dnsName } else { "$dnsName.$domainName" }
                OS = $os
            }
            
            if ($os -like "*Server*") {
                $servers += $computerInfo
            } else {
                $workstations += $computerInfo
            }
        }
        
        # Prioritize servers (they're more likely to have data shares)
        $computers = $servers + $workstations
        
        Write-Host "  [+] Found $($servers.Count) servers and $($workstations.Count) workstations" -ForegroundColor Green
        return $computers[0..([Math]::Min($computers.Count, 100) - 1)]  # Limit to 100
        
    } catch {
        Write-Host "  [!] Error querying $DC : $_" -ForegroundColor Red
        return $null
    }
}

function Test-ShareHasData {
    param([string]$Computer, [string]$Share, [switch]$Quick)
    
    $sharePath = "\\$Computer\$Share"
    
    try {
        if ($Quick) {
            # Quick check: just see if we can access and list first item
            $firstItem = Get-ChildItem -Path $sharePath -ErrorAction Stop -Force | Select-Object -First 1
            if ($null -ne $firstItem) {
                # Get basic stats for quick mode
                $itemCount = (Get-ChildItem -Path $sharePath -ErrorAction SilentlyContinue -Force).Count
                return @{
                    HasData = $true
                    ItemCount = $itemCount
                    SampleItem = $firstItem.Name
                    IsAccessible = $true
                }
            }
            return @{HasData = $false; IsAccessible = $true}
        } else {
            # Detailed check: get more information
            $items = Get-ChildItem -Path $sharePath -ErrorAction Stop -Force
            if ($items.Count -gt 0) {
                # Get some statistics
                $totalSize = 0
                $fileCount = 0
                $folderCount = 0
                $recentFiles = @()
                $fileTypes = @{}
                
                foreach ($item in $items | Select-Object -First 50) {  # Limit scan depth
                    if ($item.PSIsContainer) {
                        $folderCount++
                    } else {
                        $fileCount++
                        $totalSize += $item.Length
                        
                        # Track file types
                        $ext = [System.IO.Path]::GetExtension($item.Name).ToLower()
                        if ($ext) {
                            if ($fileTypes.ContainsKey($ext)) {
                                $fileTypes[$ext]++
                            } else {
                                $fileTypes[$ext] = 1
                            }
                        }
                        
                        # Track recent files (last 30 days)
                        if ($item.LastWriteTime -gt (Get-Date).AddDays(-30)) {
                            $recentFiles += $item.Name
                        }
                    }
                }
                
                # Get top file types
                $topFileTypes = $fileTypes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3
                
                return @{
                    HasData = $true
                    TotalItems = $items.Count
                    FileCount = $fileCount
                    FolderCount = $folderCount
                    TotalSizeMB = [Math]::Round($totalSize / 1MB, 2)
                    RecentFilesCount = $recentFiles.Count
                    TopFileTypes = $topFileTypes | ForEach-Object { "$($_.Key):$($_.Value)" } -join ", "
                    IsAccessible = $true
                }
            }
            return @{HasData = $false; IsAccessible = $true}
        }
    } catch [System.UnauthorizedAccessException] {
        return @{HasData = $false; IsAccessible = $false; Error = "Access Denied"}
    } catch {
        return @{HasData = $false; IsAccessible = $false; Error = $_.Exception.Message}
    }
}

function Get-SharesList {
    param([string]$Computer)
    
    # Common shares that often contain data
    $commonDataShares = @(
        "Data",
        "Shares",
        "Shared",
        "Public",
        "Documents",
        "Files",
        "Archive",
        "Backup",
        "IT",
        "Department",
        "Projects",
        "Finance",
        "HR",
        "Legal",
        "Marketing",
        "Sales",
        "Engineering",
        "Software",
        "Install",
        "Logs",
        "Reports",
        "Temp",
        "Transfer",
        "Upload",
        "Users",
        "Home",
        "Profiles"
    )
    
    # Always check admin shares too (they often have access to data)
    $adminShares = @("C$", "D$", "E$", "F$", "ADMIN$")
    
    # System shares (usually don't contain user data but good to check)
    $systemShares = @("NETLOGON", "SYSVOL", "IPC$")
    
    return $adminShares + $commonDataShares + $systemShares
}

function Scan-ComputerForDataShares {
    param([string]$Computer, [switch]$Quick)
    
    $foundDataShares = @()
    $sharesToCheck = Get-SharesList -Computer $Computer
    
    Write-Host "    [*] Testing $($sharesToCheck.Count) potential shares on $Computer..." -ForegroundColor Gray
    
    foreach ($share in $sharesToCheck) {
        # Quick ping test first
        if (-not $Quick) {
            Write-Host "      - Testing \\$Computer\$share" -NoNewline -ForegroundColor DarkGray
        }
        
        $result = Test-ShareHasData -Computer $Computer -Share $share -Quick:$Quick
        
        if ($result.HasData) {
            if ($Quick) {
                $displayMsg = "\\$Computer\$share (Found: $($result.ItemCount) items)"
            } else {
                $displayMsg = "\\$Computer\$share (Files: $($result.FileCount), Size: $($result.TotalSizeMB) MB, Recent: $($result.RecentFilesCount))"
            }
            
            Write-Host "`n        [+] $displayMsg" -ForegroundColor Green
            $foundDataShares += @{
                Path = "\\$Computer\$share"
                Computer = $Computer
                Share = $share
                Details = $result
            }
        } elseif (-not $result.IsAccessible -and -not $Quick) {
            Write-Host " - [Access Denied]" -ForegroundColor DarkYellow
        } elseif (-not $Quick) {
            Write-Host " - [No Data]" -ForegroundColor DarkGray
        }
    }
    
    return $foundDataShares
}

# ==================== MAIN LOGIC ====================
try {
    # If no DC specified, use current domain
    if (-not $DomainController) {
        try {
            $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers[0].Name
            Write-Host "[*] No DC specified, using: $DomainController" -ForegroundColor Yellow
        } catch {
            Write-Host "[!] Could not detect domain. Please specify -DomainController" -ForegroundColor Red
            exit
        }
    }
    
    # Step 1: Get computers from the DC
    $computers = Get-ComputersFromDC -DC $DomainController
    
    if (-not $computers -or $computers.Count -eq 0) {
        Write-Host "[!] No computers found in domain" -ForegroundColor Red
        exit
    }
    
    if ($TestOnly) {
        Write-Host "[+] Test successful. Found $($computers.Count) computers." -ForegroundColor Green
        Write-Host "    First 5 computers:" -ForegroundColor Cyan
        $computers[0..4] | ForEach-Object { Write-Host "      - $($_.Name) ($($_.OS))" -ForegroundColor White }
        exit
    }
    
    # Step 2: Scan for data-containing shares
    Write-Host "`n[*] Scanning for shares with data (this may take a few minutes)..." -ForegroundColor Cyan
    
    $allDataShares = @()
    $computersScanned = 0
    $computersWithData = 0
    
    foreach ($computer in $computers) {
        $computersScanned++
        
        if ($computersScanned -gt $MaxComputers) {
            Write-Host "[*] Reached max computers limit ($MaxComputers)" -ForegroundColor Yellow
            break
        }
        
        # Try multiple forms of computer name
        $computerNames = @()
        if ($computer.FQDN) { $computerNames += $computer.FQDN }
        if ($computer.DNSHostName) { $computerNames += $computer.DNSHostName }
        if ($computer.Name) { $computerNames += $computer.Name }
        
        $computerReachable = $false
        
        foreach ($compName in $computerNames | Select-Object -Unique) {
            Write-Host "`n  [$computersScanned/$($computers.Count)] Scanning: $compName" -ForegroundColor Cyan
            
            # Quick ping test
            if (Test-Connection -ComputerName $compName -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                Write-Host "    [+] Online" -ForegroundColor Green
                $computerReachable = $true
                
                # Scan for data shares
                $dataShares = Scan-ComputerForDataShares -Computer $compName -Quick:$QuickScan
                
                if ($dataShares.Count -gt 0) {
                    $computersWithData++
                    $allDataShares += $dataShares
                    Write-Host "    [+] Found $($dataShares.Count) shares with data" -ForegroundColor Green
                } else {
                    Write-Host "    [-] No data found in accessible shares" -ForegroundColor Gray
                }
                
                break
            }
        }
        
        if (-not $computerReachable) {
            Write-Host "    [-] Offline or unreachable" -ForegroundColor DarkGray
        }
    }
    
    # Step 3: Save results
    Write-Host "`n" + ("="*60) -ForegroundColor Cyan
    Write-Host "[*] SCAN COMPLETE" -ForegroundColor Green
    Write-Host ("="*60) -ForegroundColor Cyan
    
    if ($allDataShares.Count -gt 0) {
        # Sort by most data
        if (-not $QuickScan) {
            $allDataShares = $allDataShares | Sort-Object { $_.Details.TotalSizeMB } -Descending
        }
        
        # Generate report
        $report = @"
================================================================
DATA SHARES FOUND - SCAN REPORT
================================================================
Scan Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Domain Controller: $DomainController
Computers Scanned: $computersScanned
Computers with Data Shares: $computersWithData
Total Data Shares Found: $($allDataShares.Count)
Scan Mode: $(if($QuickScan){"Quick"}else{"Detailed"})
================================================================

DATA-CONTAINING SHARES:
$(($allDataShares | ForEach-Object { 
    if ($QuickScan) {
        "$($_.Path) - Items: $($_.Details.ItemCount), Sample: $($_.Details.SampleItem)"
    } else {
        "$($_.Path)"
        "  - Files: $($_.Details.FileCount), Folders: $($_.Details.FolderCount)"
        "  - Total Size: $($_.Details.TotalSizeMB) MB"
        "  - Recent Files (30 days): $($_.Details.RecentFilesCount)"
        "  - Top File Types: $($_.Details.TopFileTypes)"
        ""
    }
}) -join "`n")

================================================================
SUMMARY:
- Found $($allDataShares.Count) shares containing data
- $($allDataShares | Where-Object { $_.Share -match '\$$' } | Measure-Object).Count admin shares with data
- Largest shares: $(if(-not $QuickScan) { 
    ($allDataShares | Select-Object -First 3 | ForEach-Object { 
        "$($_.Share) ($($_.Details.TotalSizeMB) MB)" 
    }) -join ", "
})

RECOMMENDATIONS:
1. Review permissions on these shares
2. Check for sensitive data exposure
3. Ensure backups are configured for critical shares
4. Remove unnecessary data from shared locations
================================================================
"@
        
        $report | Out-File -FilePath $OutputPath -Encoding UTF8
        
        Write-Host "[+] Found $($allDataShares.Count) shares with data" -ForegroundColor Green
        
        # Show summary
        Write-Host "`n[+] Top Data Shares Found:" -ForegroundColor Cyan
        $topShares = $allDataShares | Select-Object -First 5
        foreach ($share in $topShares) {
            if ($QuickScan) {
                Write-Host "  - $($share.Path) ($($share.Details.ItemCount) items)" -ForegroundColor White
            } else {
                Write-Host "  - $($share.Path) ($($share.Details.TotalSizeMB) MB, $($share.Details.FileCount) files)" -ForegroundColor White
            }
        }
        
        # Warn about admin shares with data
        $adminSharesWithData = $allDataShares | Where-Object { $_.Share -match '\$$' }
        if ($adminSharesWithData.Count -gt 0) {
            Write-Host "`n[!] WARNING: Found $($adminSharesWithData.Count) admin shares with data!" -ForegroundColor Red
            foreach ($share in $adminSharesWithData | Select-Object -First 3) {
                Write-Host "    $($share.Path)" -ForegroundColor Yellow
            }
        }
        
    } else {
        Write-Host "[-] No shares with data found" -ForegroundColor Yellow
        "No data-containing shares found on scanned computers." | Out-File -FilePath $OutputPath
    }
    
    Write-Host "`n[+] Report saved to: $OutputPath" -ForegroundColor Green
    
} catch {
    Write-Host "`n[!] ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[*] Try running with -QuickScan for faster results" -ForegroundColor Yellow
}
