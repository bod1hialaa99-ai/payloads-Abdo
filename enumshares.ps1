# Save as Find-DomainShares.ps1
param(
    [string]$DomainController,
    [string]$OutputPath = "domain_shares.json",
    [int]$Threads = 10,
    [switch]$QuickScan,
    [switch]$DeepScan
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

# ==================== SHARE DISCOVERY FUNCTIONS ====================
function Get-NetworkComputers {
    param([string]$Domain)
    
    Write-Host "[*] Discovering network computers..." -ForegroundColor Green
    
    $computers = @()
    
    # Method 1: Query AD for computers
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(objectClass=computer)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
        
        $results = $searcher.FindAll()
        foreach ($result in $results) {
            if ($result.Properties["dNSHostName"]) {
                $computers += $result.Properties["dNSHostName"][0]
            }
        }
    } catch {
        Write-Host "  [-] AD query failed: $_" -ForegroundColor Yellow
    }
    
    # Method 2: Net view (fallback)
    if ($computers.Count -eq 0) {
        try {
            $netView = net view /domain 2>$null
            $computers = $netView | Where-Object { $_ -match '\\\\' } | ForEach-Object { 
                $_.Trim() -replace '\\\\', ''
            }
        } catch { }
    }
    
    Write-Host "  [+] Found $($computers.Count) potential targets" -ForegroundColor Green
    return $computers
}

function Test-SMBShare {
    param([string]$Computer, [string]$Share)
    
    try {
        $sharePath = "\\$Computer\$Share"
        
        # Test if we can list directory
        $test = Get-ChildItem -Path $sharePath -ErrorAction Stop | Select-Object -First 1
        return $true
    }
    catch {
        return $false
    }
}

function Get-CommonShares {
    param([string]$Computer)
    
    $commonShares = @()
    
    # Standard Windows shares
    $standardShares = @(
        "ADMIN$", "C$", "D$", "IPC$", 
        "NETLOGON", "SYSVOL", "Print$",
        "Users", "Public", "Share", "Data"
    )
    
    # Try to get shares via net view
    try {
        $shares = net view \\$Computer 2>$null | Where-Object { $_ -match 'Disk|Print' } | ForEach-Object {
            if ($_ -match '(.+)\s+(Disk|Print)') {
                $matches[1].Trim()
            }
        }
        
        $commonShares += $shares
    }
    catch { }
    
    # Add standard shares to check
    $commonShares += $standardShares | Sort-Object -Unique
    
    return $commonShares
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
    
    $sharesToTest = Get-CommonShares -Computer $Computer
    
    foreach ($share in $sharesToTest) {
        $results.TotalSharesTested++
        
        if (Test-SMBShare -Computer $Computer -Share $share) {
            Write-Host "    [+] ACCESSIBLE: \\$Computer\$share" -ForegroundColor Green
            
            $shareInfo = @{
                Name = $share
                Path = "\\$Computer\$share"
                Type = if ($share -match '\$$') { "Admin" } else { "Regular" }
            }
            
            # If it's accessible, try to get more info
            try {
                $items = Get-ChildItem -Path "\\$Computer\$share" -ErrorAction Stop | Select-Object -First 5
                $shareInfo.SampleFiles = @($items | ForEach-Object { $_.Name })
                $shareInfo.FileCount = (Get-ChildItem -Path "\\$Computer\$share" -Recurse -ErrorAction SilentlyContinue | Measure-Object).Count
            }
            catch {
                $shareInfo.SampleFiles = @()
                $shareInfo.FileCount = 0
            }
            
            $results.AccessibleShares += $shareInfo
            
            # In quick mode, stop after first accessible share
            if ($Quick -and $results.AccessibleShares.Count -gt 0) {
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
            $files = Get-ChildItem -Path $SharePath -Filter $pattern -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue | Select-Object -First $MaxFiles
            
            foreach ($file in $files) {
                $interestingFiles += @{
                    Name = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    LastWrite = $file.LastWriteTime
                    Extension = $file.Extension
                }
            }
        }
    }
    catch { }
    
    return $interestingFiles
}

# ==================== MAIN EXECUTION ====================
try {
    Write-Host "[*] Starting Domain Share Discovery" -ForegroundColor Green
    
    # Get current domain
    $domain = $env:USERDNSDOMAIN
    if (-not $domain) {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    
    Write-Host "[*] Domain: $domain" -ForegroundColor White
    
    # Discover computers in the domain
    $computers = Get-NetworkComputers -Domain $domain
    
    if ($computers.Count -eq 0) {
        Write-Host "[!] No computers found in domain" -ForegroundColor Red
        exit 1
    }
    
    # Limit computers for quick scan
    if ($QuickScan) {
        $computers = $computers | Select-Object -First 20
        Write-Host "[*] Quick scan mode: Testing first 20 computers" -ForegroundColor Yellow
    }
    
    # Scan for accessible shares
    $allResults = @()
    $accessibleComputers = 0
    
    Write-Host "`n[*] Scanning for accessible shares..." -ForegroundColor Green
    
    foreach ($computer in $computers) {
        try {
            # First, test if computer is online
            if (Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                $results = Scan-ComputerShares -Computer $computer -Quick:$QuickScan
                
                if ($results.AccessibleShares.Count -gt 0) {
                    $accessibleComputers++
                    
                    # If deep scan enabled, scan for interesting files
                    if ($DeepScan) {
                        Write-Host "    [*] Deep scanning accessible shares..." -ForegroundColor Gray
                        
                        foreach ($share in $results.AccessibleShares) {
                            $interestingFiles = Find-InterestingFiles -SharePath $share.Path
                            $share.InterestingFiles = $interestingFiles
                            $share.InterestingFileCount = $interestingFiles.Count
                        }
                    }
                }
                
                $allResults += $results
            }
        }
        catch {
            Write-Host "  [-] Error scanning $computer : $_" -ForegroundColor DarkYellow
        }
        
        # Display progress
        $current = $allResults.Count
        $total = $computers.Count
        Write-Progress -Activity "Scanning Computers" -Status "$current of $total" -PercentComplete (($current / $total) * 100)
    }
    
    Write-Progress -Activity "Scanning Computers" -Completed
    
    # Calculate statistics
    $totalAccessibleShares = ($allResults | ForEach-Object { $_.AccessibleShares.Count } | Measure-Object -Sum).Sum
    $totalInterestingFiles = ($allResults | ForEach-Object { 
        $_.AccessibleShares | ForEach-Object { $_.InterestingFileCount }
    } | Measure-Object -Sum).Sum
    
    # Build results structure
    $scanResults = @{
        Metadata = @{
            ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Domain = $domain
            ScanType = if ($DeepScan) { "Deep" } elseif ($QuickScan) { "Quick" } else { "Standard" }
            ComputersScanned = $computers.Count
            ScanDuration = ((Get-Date) - $startTime).ToString("hh\:mm\:ss")
        }
        Results = $allResults
        Statistics = @{
            TotalComputers = $computers.Count
            AccessibleComputers = $accessibleComputers
            TotalAccessibleShares = $totalAccessibleShares
            AdminSharesFound = ($allResults | ForEach-Object { 
                $_.AccessibleShares | Where-Object { $_.Type -eq "Admin" }
            }).Count
            TotalInterestingFiles = $totalInterestingFiles
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
                FileCount = $share.FileCount
                InterestingFiles = if ($share.InterestingFiles) { $share.InterestingFiles.Count } else { 0 }
            }
        }
    }
    
    # Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    $scanResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    # Display final summary
    Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
    Write-Host " SHARE DISCOVERY COMPLETE" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Cyan
    
    Write-Host "Domain: $domain" -ForegroundColor White
    Write-Host "Scan Duration: $($scanResults.Metadata.ScanDuration)" -ForegroundColor White
    
    Write-Host "`nSUMMARY STATISTICS:" -ForegroundColor Yellow
    Write-Host "  Computers scanned: $($computers.Count)" -ForegroundColor White
    Write-Host "  Computers with accessible shares: $accessibleComputers" -ForegroundColor $(if($accessibleComputers -gt 0){"Green"}else{"White"})
    Write-Host "  Total accessible shares: $totalAccessibleShares" -ForegroundColor $(if($totalAccessibleShares -gt 0){"Green"}else{"White"})
    Write-Host "  Admin shares found: $($scanResults.Statistics.AdminSharesFound)" -ForegroundColor $(if($scanResults.Statistics.AdminSharesFound -gt 0){"Red"}else{"White"})
    Write-Host "  Interesting files found: $totalInterestingFiles" -ForegroundColor $(if($totalInterestingFiles -gt 0){"Yellow"}else{"White"})
    
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
    
    Write-Host "`nOutput saved to: $OutputPath" -ForegroundColor Green
    
}
catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
}
