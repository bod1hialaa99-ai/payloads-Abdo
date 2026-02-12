# Check-LDAPSigning.ps1
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainDN,
    
    [Parameter(Mandatory = $false)]
    [string]$Server
)

# Build parameters
$params = @{}
if ($Server) { $params.Server = $Server }

try {
    # Get the domain object using AD module cmdlets
    $domain = Get-ADObject -Identity $DomainDN -Properties "msDS-Other-Settings" @params -ErrorAction Stop

    # Check if LDAP signing is required (value "2")
    $ldapSigningRequired = $false
    if ($domain.'msDS-Other-Settings') {
        foreach ($setting in $domain.'msDS-Other-Settings') {
            if ($setting -match 'LDAPServerIntegrity:\s*2') {
                $ldapSigningRequired = $true
                break
            }
        }
    }

    # Output result
    if ($ldapSigningRequired) {
        Write-Host "[!] LDAP signing is REQUIRED for domain: $DomainDN" -ForegroundColor Red
    } else {
        Write-Host "[+] LDAP signing is NOT required for domain: $DomainDN" -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to query domain: $_"
}
