# Save as Check-LDAPSigning.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$DomainDN,
    
    [Parameter(Mandatory=$false)]
    [string]$DomainController,
    
    [Parameter(Mandatory=$false)]
    [pscredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "ldap_signing_check.txt"
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host @"
=================================================
LDAP SIGNING SECURITY CHECK
=================================================
Target Domain: $DomainDN
$(if($DomainController){"Target DC: $DomainController"})
=================================================
"@ -ForegroundColor Cyan

# Build parameters
$params = @{}
if ($DomainController) { $params.Server = $DomainController }
if ($Credential) { $params.Credential = $Credential }

$results = @{
    DomainDN = $DomainDN
    DomainController = if($DomainController) { $DomainController } else { "Default" }
    ScanTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    DomainPolicy = @{}
    DomainControllers = @()
    VulnerableDCs = @()
    CompliantDCs = @()
    Summary = @{}
}

try {
    # METHOD 1: Check Domain Policy
    Write-Host "[*] Checking domain LDAP signing policy..." -ForegroundColor Yellow
    
    $domain = Get-ADObject -Identity $DomainDN -Properties @("distinguishedName", "ldapSigning", "ldapServerIntegrity") -ErrorAction SilentlyContinue
    
    $results.DomainPolicy = @{
        DistinguishedName = $domain.DistinguishedName
        ldapSigning = if ($domain.ldapSigning -ne $null) { $domain.ldapSigning } else { "Not Configured" }
        ldapServerIntegrity = if ($domain.ldapServerIntegrity -ne $null) { $domain.ldapServerIntegrity } else { "Not Configured" }
    }
    
    # Interpret domain policy
    if ($domain.ldapSigning -eq 2 -or $domain.ldapServerIntegrity -eq 2) {
        Write-Host "  [+] Domain requires LDAP signing" -ForegroundColor Green
        $domainRequiresSigning = $true
    } elseif ($domain.ldapSigning -eq 1 -or $domain.ldapServerIntegrity -eq 1) {
        Write-Host "  [!] Domain: LDAP signing is optional (may be vulnerable)" -ForegroundColor Yellow
        $domainRequiresSigning = $false
    } else {
        Write-Host "  [-] Domain: LDAP signing policy not configured (vulnerable)" -ForegroundColor Red
        $domainRequiresSigning = $false
    }
    
    # METHOD 2: Check Domain Controllers
    Write-Host "[*] Checking individual Domain Controllers..." -ForegroundColor Yellow
    
    $dcs = Get-ADDomainController -Filter * @params
    
    Write-Host "  [+] Found $($dcs.Count) domain controllers" -ForegroundColor Green
    
    foreach ($dc in $dcs) {
        Write-Host "`n  [*] Checking: $($dc.Name)" -ForegroundColor Cyan
        
        $dcInfo = @{
            Name = $dc.Name
            HostName = $dc.HostName
            IPv4Address = $dc.IPv4Address
            Site = $dc.Site
            IsReadOnly = $dc.IsReadOnly
            LDAPSigning = "Unknown"
            LDAPChannelBinding = "Unknown"
            IsVulnerable = $false
        }
        
        # Check LDAP signing via registry (requires admin on DC)
        try {
            $regPath = "\\$($dc.Name)\HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $dc.Name)
            $ntdsKey = $regKey.OpenSubKey("SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
            
            if ($ntdsKey) {
                $ldapServerIntegrity = $ntdsKey.GetValue("LDAPServerIntegrity")
                $ldapSigningReq = $ntdsKey.GetValue("ldap signing requirements")
                
                $dcInfo.LDAPSigning = @{
                    LDAPServerIntegrity = if ($ldapServerIntegrity -ne $null) { $ldapServerIntegrity } else { "Not Configured" }
                    LDAPSigningRequirements = if ($ldapSigningReq -ne $null) { $ldapSigningReq } else { "Not Configured" }
                }
                
                # Check if vulnerable
                if ($ldapServerIntegrity -eq 2 -or $ldapSigningReq -eq 2) {
                    Write-Host "    [+] LDAP signing required" -ForegroundColor Green
                    $dcInfo.IsVulnerable = $false
                    $results.CompliantDCs += $dcInfo
                } else {
                    Write-Host "    [-] LDAP signing NOT required - VULNERABLE!" -ForegroundColor Red
                    $dcInfo.IsVulnerable = $true
                    $results.VulnerableDCs += $dcInfo
                }
                
                # Check channel binding
                $ldapChannelBinding = $ntdsKey.GetValue("LdapEnforceChannelBinding")
                if ($ldapChannelBinding -ne $null) {
                    $dcInfo.LDAPChannelBinding = $ldapChannelBinding
                    if ($ldapChannelBinding -eq 2) {
                        Write-Host "    [+] LDAP channel binding enabled" -ForegroundColor Green
                    } elseif ($ldapChannelBinding -eq 1) {
                        Write-Host "    [!] LDAP channel binding: when supported" -ForegroundColor Yellow
                    } else {
                        Write-Host "    [-] LDAP channel binding disabled - VULNERABLE!" -ForegroundColor Red
                    }
                }
                
                $ntdsKey.Close()
                $regKey.Close()
            }
        } catch {
            Write-Host "    [!] Cannot access registry on $($dc.Name) - insufficient privileges" -ForegroundColor Yellow
            $dcInfo.LDAPSigning = "Access Denied"
            $dcInfo.IsVulnerable = "Unknown"
        }
        
        # Alternative: Check via LDAP query
        try {
            $dcObj = Get-ADObject -Identity $dc.DistinguishedName -Properties @("msDS-SupportedEncryptionTypes", "operatingSystem") @params -ErrorAction SilentlyContinue
            $dcInfo.OperatingSystem = $dcObj.operatingSystem
            
            if ($dcObj.'msDS-SupportedEncryptionTypes' -ne $null) {
                $encTypes = $dcObj.'msDS-SupportedEncryptionTypes'
                $dcInfo.SupportedEncryptionTypes = $encTypes
                
                if ($encTypes -band 2) {
                    Write-Host "    [+] Supports LDAP signing via encryption flags" -ForegroundColor Green
                }
            }
        } catch {}
        
        $results.DomainControllers += $dcInfo
    }
    
    # METHOD 3: Check Domain Controllers OU
    Write-Host "`n[*] Checking Domain Controllers OU policy..." -ForegroundColor Yellow
    
    try {
        $dcOU = Get-ADOrganizationalUnit -Identity "OU=Domain Controllers,$DomainDN" -Properties @("gpLink", "gpOptions") @params -ErrorAction SilentlyContinue
        
        if ($dcOU.gpLink) {
            Write-Host "  [+] Found GPOs linked to Domain Controllers OU" -ForegroundColor Green
            Write-Host "      GPO Links: $($dcOU.gpLink)" -ForegroundColor Gray
            $results.DCOU = @{
                DistinguishedName = $dcOU.DistinguishedName
                GPLink = $dcOU.gpLink
                GPOptions = $dcOU.gpOptions
            }
        }
    } catch {
        Write-Host "  [!] Could not access Domain Controllers OU" -ForegroundColor Yellow
    }
    
    # METHOD 4: Check via Get-ADDomainController
    try {
        Write-Host "`n[*] Testing LDAP signing requirements via PowerShell..." -ForegroundColor Yellow
        
        $ldapPolicy = Get-ADObject @params -LDAPFilter "(objectClass=domain)" -SearchBase $DomainDN -Properties @("ldapSigning", "ldapServerIntegrity")
        
        foreach ($policy in $ldapPolicy) {
            if ($policy.ldapSigning -eq 2 -or $policy.ldapServerIntegrity -eq 2) {
                Write-Host "  [+] Verified: Domain requires LDAP signing" -ForegroundColor Green
            } else {
                Write-Host "  [-] Verified: Domain does NOT require LDAP signing - VULNERABLE!" -ForegroundColor Red
            }
        }
    } catch {}
    
    # ================ SUMMARY ================
    $results.Summary = @{
        TotalDCs = $results.DomainControllers.Count
        VulnerableDCs = ($results.VulnerableDCs | Measure-Object).Count
        CompliantDCs = ($results.CompliantDCs | Measure-Object).Count
        UnknownDCs = $results.DomainControllers.Count - ($results.VulnerableDCs.Count + $results.CompliantDCs.Count)
        DomainRequiresSigning = if ($domainRequiresSigning) { "Yes" } else { "No" }
        OverallStatus = if ($results.VulnerableDCs.Count -gt 0 -or -not $domainRequiresSigning) { "VULNERABLE" } else { "COMPLIANT" }
        RiskLevel = if ($results.VulnerableDCs.Count -gt 0) { 
            "HIGH - $($results.VulnerableDCs.Count) DC(s) do not require LDAP signing" 
        } elseif (-not $domainRequiresSigning) {
            "MEDIUM - Domain policy does not require LDAP signing"
        } else {
            "LOW - LDAP signing is enforced"
        }
    }
    
    # ================ OUTPUT ================
    Write-Host "`n" + ("="*50) -ForegroundColor Cyan
    Write-Host "LDAP SIGNING ASSESSMENT COMPLETE" -ForegroundColor $(if($results.Summary.VulnerableDCs -gt 0){"Red"}else{"Green"})
    Write-Host ("="*50) -ForegroundColor Cyan
    
    Write-Host "`nDOMAIN: $DomainDN" -ForegroundColor White
    Write-Host "Domain Policy Requires Signing: $($results.Summary.DomainRequiresSigning)" -ForegroundColor $(if($domainRequiresSigning){"Green"}else{"Red"})
    Write-Host "Overall Status: $($results.Summary.OverallStatus)" -ForegroundColor $(if($results.Summary.VulnerableDCs -gt 0){"Red"}else{"Green"})
    Write-Host "Risk Level: $($results.Summary.RiskLevel)" -ForegroundColor $(if($results.Summary.VulnerableDCs -gt 0){"Red"}else{"Yellow"})
    
    Write-Host "`nDOMAIN CONTROLLERS:" -ForegroundColor Cyan
    Write-Host "  Total: $($results.Summary.TotalDCs)" -ForegroundColor White
    Write-Host "  Compliant: $($results.Summary.CompliantDCs)" -ForegroundColor Green
    Write-Host "  Vulnerable: $($results.Summary.VulnerableDCs)" -ForegroundColor $(if($results.Summary.VulnerableDCs -gt 0){"Red"}else{"Green"})
    
    if ($results.VulnerableDCs.Count -gt 0) {
        Write-Host "`n[!] VULNERABLE DOMAIN CONTROLLERS:" -ForegroundColor Red
        foreach ($dc in $results.VulnerableDCs) {
            Write-Host "    • $($dc.Name) ($($dc.HostName))" -ForegroundColor Red
            Write-Host "      LDAP Signing: NOT REQUIRED" -ForegroundColor Yellow
        }
    }
    
    if ($results.CompliantDCs.Count -gt 0) {
        Write-Host "`n[+] COMPLIANT DOMAIN CONTROLLERS:" -ForegroundColor Green
        foreach ($dc in $results.CompliantDCs | Select-Object -First 5) {
            Write-Host "    • $($dc.Name) - LDAP signing required" -ForegroundColor Green
        }
        if ($results.CompliantDCs.Count -gt 5) {
            Write-Host "      ... and $($results.CompliantDCs.Count - 5) more" -ForegroundColor Gray
        }
    }
    
    # ================ REMEDIATION ================
    if ($results.Summary.VulnerableDCs -gt 0 -or -not $domainRequiresSigning) {
        Write-Host "`n" + ("="*50) -ForegroundColor Yellow
        Write-Host "REMEDIATION STEPS:" -ForegroundColor Yellow
        Write-Host ("="*50) -ForegroundColor Yellow
        
        Write-Host @"
        
1. Enable LDAP Signing via Group Policy:
   - Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
   - "Domain controller: LDAP server signing requirements" = "Require signing"
   - "Network security: LDAP client signing requirements" = "Require signing"

2. Enable LDAP Channel Binding:
   - "Domain controller: LDAP server channel binding token requirements" = "Always"

3. Manual registry fix (per DC):
   - Open regedit
   - HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
   - Set "LDAPServerIntegrity" = 2 (DWORD)
   - Set "ldap signing requirements" = 2 (DWORD)
   - Set "LdapEnforceChannelBinding" = 2 (DWORD)
   - Reboot the DC

4. Apply to all Domain Controllers in the domain
5. Verify with this script after implementation

RISK:
LDAP signing vulnerabilities allow attackers to execute LDAP relay attacks,
potentially leading to Domain Admin compromise.

"@ -ForegroundColor Yellow
    }
    
    # Save to file
    $results | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "`n[+] Full report saved to: $OutputPath" -ForegroundColor Green
    
} catch {
    Write-Host "`n[!] ERROR: $_" -ForegroundColor Red
    Write-Host "[!] Make sure you have permissions and the domain DN is correct" -ForegroundColor Yellow
    exit 1
}
