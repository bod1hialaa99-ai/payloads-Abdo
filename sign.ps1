# Check-LDAPSigning.ps1
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainDN,
    
    [Parameter(Mandatory = $false)]
    [string]$Server
)

# Import Active Directory module
Import-Module ActiveDirectory -ErrorAction Stop

# Build parameters
$params = @{}
if ($Server) { $params.Server = $Server }

try {
    # Get the domain object
    $domain = Get-ADObject -Identity $DomainDN -Properties msDS-Other-Settings @params -ErrorAction Stop

    # Extract the msDS-Other-Settings attribute
    $settings = $domain.'msDS-Other-Settings'

    # Check if LDAP signing is required (value "2")
    $ldapSigningRequired = $false
    if ($settings) {
        foreach ($line in $settings) {
            if ($line -match 'LDAPServerIntegrity:\s*2') {
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
