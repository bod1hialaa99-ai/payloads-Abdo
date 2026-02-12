<#
.SYNOPSIS
    Checks LDAP signing and channel binding requirements for specified domains.
.DESCRIPTION
    Uses AD module to get domain controllers and remotely queries registry to determine
    if LDAP server signing is required and if channel binding is enforced.
.PARAMETER Domains
    One or more domain names (e.g. "contoso.local", "eu.contoso.local").
.PARAMETER ADModulePath
    Optional path to ActiveDirectory.psd1 if module is not installed (DLL import).
.EXAMPLE
    .\Check-LDAPSigning.ps1 -Domains "contoso.local"
.EXAMPLE
    .\Check-LDAPSigning.ps1 -Domains "contoso.local","fabrikam.com" -ADModulePath ".\ADModule\ActiveDirectory.psd1"
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$Domains,
    
    [string]$ADModulePath = $null,
    
    [switch]$Verbose
)

#region Module Loading
function Load-ADModule {
    param([string]$CustomPath)
    
    if (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        Write-Verbose "[+] ActiveDirectory module already loaded" -Verbose:$Verbose
        return $true
    }
    
    if ($CustomPath -and (Test-Path $CustomPath)) {
        try {
            Import-Module $CustomPath -ErrorAction Stop
            Write-Verbose "[+] Loaded AD module from custom path: $CustomPath" -Verbose:$Verbose
            return $true
        }
        catch {
            Write-Warning "[!] Failed to load module from custom path: $_"
        }
    }
    
    # Try default import
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Verbose "[+] Loaded ActiveDirectory module from system" -Verbose:$Verbose
        return $true
    }
    catch {
        Write-Error "[!] ActiveDirectory module not available. Please install RSAT or provide -ADModulePath"
        return $false
    }
}
#endregion

#region Registry Reading
function Get-RemoteRegistryValue {
    param(
        [string]$ComputerName,
        [string]$SubKey,
        [string]$ValueName
    )
    
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
        $key = $reg.OpenSubKey($SubKey)
        if ($key -ne $null) {
            $value = $key.GetValue($ValueName)
            $key.Close()
            $reg.Close()
            return $value
        }
    }
    catch {
        Write-Verbose "  [!] Cannot read registry on $ComputerName : $_" -Verbose:$Verbose
    }
    return $null
}
#endregion

#region LDAP Signing Interpretation
function Get-LDAPSigningStatus {
    param([int]$Value)
    
    switch ($Value) {
        0 { return "Not Required (0)" }
        1 { return "Required (1)" }
        2 { return "Required and Sealed (2)" }
        default { return "Unknown ($Value)" }
    }
}

function Get-ChannelBindingStatus {
    param([int]$Value)
    
    switch ($Value) {
        0 { return "Never (0)" }
        1 { return "When Supported (1)" }
        2 { return "Always (2)" }
        default { return "Unknown ($Value)" }
    }
}
#endregion

#region Main
function Main {
    if (-not (Load-ADModule -CustomPath $ADModulePath)) {
        return
    }
    
    $results = @()
    
    foreach ($domain in $Domains) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host " Checking Domain: $domain" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        
        try {
            # Get domain controllers
            $dcs = Get-ADDomainController -Filter * -Server $domain -ErrorAction Stop
            Write-Host "[*] Found $($dcs.Count) domain controller(s)" -ForegroundColor Yellow
            
            $domainResult = [PSCustomObject]@{
                Domain = $domain
                Controllers = @()
                OverallSigning = $null
                OverallChannelBinding = $null
            }
            
            foreach ($dc in $dcs) {
                $dcName = $dc.Name
                $dcHostName = $dc.HostName
                $signingValue = $null
                $channelValue = $null
                $signingStatus = "Unable to read"
                $channelStatus = "Unable to read"
                $registryAccess = $false
                
                Write-Host "`n[*] Checking DC: $dcHostName" -ForegroundColor Gray
                
                # Check LDAPServerIntegrity
                $signingValue = Get-RemoteRegistryValue -ComputerName $dcName -SubKey "SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LDAPServerIntegrity"
                if ($signingValue -ne $null) {
                    $registryAccess = $true
                    $signingStatus = Get-LDAPSigningStatus -Value $signingValue
                    Write-Host "  [>] LDAP Signing: $signingStatus" -ForegroundColor White
                }
                else {
                    Write-Host "  [!] Cannot read LDAPServerIntegrity (access denied or registry not accessible)" -ForegroundColor DarkYellow
                }
                
                # Check LdapEnforceChannelBinding
                $channelValue = Get-RemoteRegistryValue -ComputerName $dcName -SubKey "SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LdapEnforceChannelBinding"
                if ($channelValue -ne $null) {
                    $registryAccess = $true
                    $channelStatus = Get-ChannelBindingStatus -Value $channelValue
                    Write-Host "  [>] Channel Binding: $channelStatus" -ForegroundColor White
                }
                else {
                    Write-Host "  [!] Cannot read LdapEnforceChannelBinding" -ForegroundColor DarkYellow
                }
                
                $dcResult = [PSCustomObject]@{
                    Name = $dcHostName
                    IPv4Address = $dc.IPv4Address
                    Site = $dc.Site
                    LDAPSigning = $signingStatus
                    ChannelBinding = $channelStatus
                    RegistryAccessible = $registryAccess
                }
                
                $domainResult.Controllers += $dcResult
            }
            
            # Determine overall status (if any DC requires signing, domain is not fully secure)
            $requiredDCs = $domainResult.Controllers | Where-Object { 
                $_.LDAPSigning -like "*Required*" -and $_.RegistryAccessible 
            }
            $alwaysChannel = $domainResult.Controllers | Where-Object { 
                $_.ChannelBinding -like "*Always*" -and $_.RegistryAccessible 
            }
            
            if ($requiredDCs.Count -gt 0) {
                $domainResult.OverallSigning = "LDAP Signing IS required on some DCs"
                $signingColor = "Red"
            } elseif (($domainResult.Controllers | Where-Object { $_.RegistryAccessible }).Count -gt 0) {
                $domainResult.OverallSigning = "LDAP Signing is NOT required on accessible DCs"
                $signingColor = "Green"
            } else {
                $domainResult.OverallSigning = "Unable to determine (no registry access)"
                $signingColor = "Yellow"
            }
            
            if ($alwaysChannel.Count -gt 0) {
                $domainResult.OverallChannelBinding = "Channel Binding is enforced (Always) on some DCs"
                $channelColor = "Red"
            } elseif (($domainResult.Controllers | Where-Object { $_.RegistryAccessible }).Count -gt 0) {
                $domainResult.OverallChannelBinding = "Channel Binding is NOT enforced (Never/When Supported)"
                $channelColor = "Green"
            } else {
                $domainResult.OverallChannelBinding = "Unable to determine (no registry access)"
                $channelColor = "Yellow"
            }
            
            $results += $domainResult
            
            Write-Host "`n[+] Domain Summary for $domain" -ForegroundColor Yellow
            Write-Host "  → $($domainResult.OverallSigning)" -ForegroundColor $signingColor
            Write-Host "  → $($domainResult.OverallChannelBinding)" -ForegroundColor $channelColor
            
        }
        catch {
            Write-Error "[!] Failed to process domain $domain : $_"
        }
    }
    
    # Display final table
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host " FINAL ASSESSMENT" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    foreach ($res in $results) {
        Write-Host "`nDomain: $($res.Domain)" -ForegroundColor Cyan
        Write-Host "  LDAP Signing : $($res.OverallSigning)"
        Write-Host "  Channel Binding : $($res.OverallChannelBinding)"
        
        if ($res.Controllers | Where-Object { $_.RegistryAccessible -eq $false }) {
            Write-Host "  [!] Some DCs could not be assessed (permission/connectivity)" -ForegroundColor DarkYellow
        }
    }
    
    # Export results to CSV for documentation
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvPath = "LDAPSigning_Report_$timestamp.csv"
    
    $exportData = foreach ($res in $results) {
        foreach ($dc in $res.Controllers) {
            [PSCustomObject]@{
                Domain = $res.Domain
                DCName = $dc.Name
                IPv4Address = $dc.IPv4Address
                Site = $dc.Site
                LDAPSigningRequirement = $dc.LDAPSigning
                ChannelBindingEnforcement = $dc.ChannelBinding
                RegistryAccessible = $dc.RegistryAccessible
                OverallDomainSigning = $res.OverallSigning
                OverallDomainChannel = $res.OverallChannelBinding
            }
        }
    }
    
    if ($exportData) {
        $exportData | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[+] Detailed report saved to: $csvPath" -ForegroundColor Green
    }
}
#endregion

# Execute
Main
