# Save as Find-SharesInDomain.ps1
param(
    [string]$DomainController,
    [string]$OutputPath = "domain_shares.txt",
    [int]$MaxComputers = 50,
    [switch]$TestOnly
)

Write-Host "[*] Domain Share Finder v2.0" -ForegroundColor Green
Write-Host "[*] Target: $DomainController" -ForegroundColor Cyan

# ==================== SIMPLE FUNCTIONS ====================
function Get-ComputersFromDC {
    param([string]$DC)
    
    Write-Host "[*] Getting computers from $DC..." -ForegroundColor Yellow
    
    try {
        # Connect to the DC and get domain info
        $rootDSE = [ADSI]"LDAP://$DC/RootDSE"
        $domainDN = $rootDSE.defaultNamingContext
        $domainName = $rootDSE.rootDomainNamingContext -replace 'DC=','' -replace ',','.' -replace 'DC=',''
        
        Write-Host "  [+] Domain: $domainName" -ForegroundColor Green
        Write-Host "  [+] Using DC: $DC" -ForegroundColor Green
        
        # Query for computers
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$DC/$domainDN")
        $searcher.Filter = "(objectClass=computer)"
        $searcher.PageSize = 1000
        $searcher.PropertiesToLoad.Add("name") | Out-Null
        $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
        
        $computers = @()
        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $compName = $result.Properties["name"][0]
            $dnsName = if ($result.Properties["dNSHostName"]) { $result.Properties["dNSHostName"][0] } else { $compName }
            
            $computers += @{
                Name = $compName
                DNSHostName = $dnsName
                FQDN = if ($dnsName.Contains('.')) { $dnsName } else { "$dnsName.$domainName" }
            }
        }
        
        Write-Host "  [+] Found $($computers.Count) computers" -ForegroundColor Green
        return $computers
        
    } catch {
        Write-Host "  [!] Error querying $DC : $_" -ForegroundColor Red
        return $null
    }
}

function Test-ShareAccess {
    param([string]$Computer, [string]$Share)
    
    $sharePath = "\\$Computer\$Share"
    
    try {
        # Try to list the share
        $test = Get-ChildItem -Path $sharePath -ErrorAction Stop 2>$null
        return $true
    } catch {
        return $false
    }
}

function Scan-ComputerShares {
    param([string]$Computer)
    
    $foundShares = @()
    $shares = @("C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "Users", "Public", "Share", "Data", "Backup", "IT")
    
    foreach ($share in $shares) {
        if (Test-ShareAccess -Computer $Computer -Share $share) {
            Write-Host "    [+] \\$Computer\$share" -ForegroundColor Green
            $foundShares += "\\$Computer\$share"
        }
    }
    
    return $foundShares
}

# ==================== MAIN LOGIC ====================
try {
    # If no DC specified, use current domain
    if (-not $DomainController) {
        $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers[0].Name
        Write-Host "[*] No DC specified, using: $DomainController" -ForegroundColor Yellow
    }
    
    # Step 1: Get computers from the DC
    $computers = Get-ComputersFromDC -DC $DomainController
    
    if (-not $computers) {
        Write-Host "[!] Failed to get computers from $DomainController" -ForegroundColor Red
        Write-Host "[*] Trying alternative method..." -ForegroundColor Yellow
        
        # Fallback: Use net view
        try {
            $netOutput = net view /domain 2>$null
            $computers = @()
            
            foreach ($line in $netOutput) {
                if ($line -match '\\\\') {
                    $compName = $line.Trim() -replace '\\\\', ''
                    $computers += @{Name = $compName; FQDN = $compName}
                }
            }
            
            if ($computers.Count -eq 0) {
                Write-Host "[!] No computers found" -ForegroundColor Red
                exit
            }
            
            Write-Host "[+] Found $($computers.Count) computers via net view" -ForegroundColor Green
        } catch {
            Write-Host "[!] All methods failed" -ForegroundColor Red
            exit
        }
    }
    
    if ($TestOnly) {
        Write-Host "[+] Test successful. Found $($computers.Count) computers." -ForegroundColor Green
        exit
    }
    
    # Step 2: Scan for shares
    Write-Host "`n[*] Scanning for accessible shares..." -ForegroundColor Cyan
    
    $allShares = @()
    $computerCount = 0
    
    foreach ($computer in $computers) {
        $computerCount++
        
        if ($computerCount -gt $MaxComputers) {
            Write-Host "[*] Reached max computers limit ($MaxComputers)" -ForegroundColor Yellow
            break
        }
        
        # Try multiple forms of computer name
        $computerNames = @()
        if ($computer.FQDN) { $computerNames += $computer.FQDN }
        if ($computer.DNSHostName) { $computerNames += $computer.DNSHostName }
        if ($computer.Name) { $computerNames += $computer.Name }
        
        $foundAny = $false
        
        foreach ($compName in $computerNames | Select-Object -Unique) {
            Write-Host "  [$computerCount/$($computers.Count)] Testing: $compName" -ForegroundColor Gray
            
            # Check if computer is online
            if (Test-Connection -ComputerName $compName -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                $shares = Scan-ComputerShares -Computer $compName
                $allShares += $shares
                $foundAny = $true
                break
            }
        }
        
        if (-not $foundAny) {
            Write-Host "    [-] Offline or unreachable" -ForegroundColor DarkGray
        }
    }
    
    # Step 3: Save results
    Write-Host "`n[*] Saving results to: $OutputPath" -ForegroundColor Green
    
    if ($allShares.Count -gt 0) {
        $results = @"
===============================================
DOMAIN SHARE SCAN RESULTS
Domain Controller: $DomainController
Scan Date: $(Get-Date)
Computers Scanned: $computerCount
Accessible Shares Found: $($allShares.Count)
===============================================

ACCESSIBLE SHARES:
$($allShares -join "`n")

SECURITY NOTES:
1. Admin shares (C$, ADMIN$) should be restricted
2. Review share permissions regularly
3. Monitor access to sensitive shares
4. Remove unnecessary shares

"@
        
        $results | Out-File -FilePath $OutputPath -Encoding UTF8
        
        Write-Host "[+] Found $($allShares.Count) accessible shares" -ForegroundColor Green
        
        # Show admin shares
        $adminShares = $allShares | Where-Object { $_ -match '\\\\.*\\[A-Z]\$$' }
        if ($adminShares.Count -gt 0) {
            Write-Host "`n[!] WARNING: Found $($adminShares.Count) admin shares!" -ForegroundColor Red
            foreach ($share in $adminShares) {
                Write-Host "    $share" -ForegroundColor Yellow
            }
        }
        
    } else {
        Write-Host "[-] No accessible shares found" -ForegroundColor Yellow
        "No accessible shares found on $DomainController" | Out-File -FilePath $OutputPath
    }
    
    Write-Host "`n[+] Scan completed!" -ForegroundColor Green
    
} catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
}
