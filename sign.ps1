<#
.SYNOPSIS
    Checks if LDAP signing is required on domain controllers for a given domain.
.DESCRIPTION
    This script uses the Active Directory module (loaded from DLL if needed) and 
    System.DirectoryServices.Protocols to test whether LDAP signing is enforced.
    It accepts a domain name or distinguished name (e.g., DC=contoso,DC=com) and
    returns the status.
.PARAMETER Domain
    The target domain. Can be FQDN (contoso.com) or Distinguished Name (DC=contoso,DC=com).
.PARAMETER Credential
    Optional alternate credentials for LDAP bind. If not specified, current Windows identity is used.
.PARAMETER ADModulePath
    Optional path to ActiveDirectory.psd1 or Microsoft.ActiveDirectory.Management.dll if module not installed.
.PARAMETER Verbose
    Show detailed progress and error information.
.EXAMPLE
    .\Check-LdapSigning.ps1 -Domain "contoso.com"
.EXAMPLE
    .\Check-LdapSigning.ps1 -Domain "DC=contoso,DC=com" -Verbose
.EXAMPLE
    .\Check-LdapSigning.ps1 -Domain "contoso.com" -ADModulePath ".\ADModule\ActiveDirectory.psd1"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    
    [System.Management.Automation.PSCredential]$Credential,
    
    [string]$ADModulePath,
    
    [switch]$Verbose
)

#region Functions

function Write-Log {
    param([string]$Message, [string]$ForegroundColor = "Gray")
    if ($Verbose -or $ForegroundColor -ne "Gray") {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $ForegroundColor
    }
}

function Load-ADModule {
    param([string]$CustomPath)
    
    Write-Log "Checking for ActiveDirectory module..." -ForegroundColor Cyan
    
    # Already loaded?
    if (Get-Module -Name ActiveDirectory) {
        Write-Log "ActiveDirectory module already loaded." -ForegroundColor Green
        return $true
    }
    
    # Try to load from custom path
    if ($CustomPath) {
        if (Test-Path $CustomPath) {
            try {
                Write-Log "Loading from custom path: $CustomPath" -ForegroundColor Yellow
                Import-Module $CustomPath -ErrorAction Stop
                Write-Log "Successfully loaded ActiveDirectory module." -ForegroundColor Green
                return $true
            }
            catch {
                Write-Log "Failed to load from custom path: $_" -ForegroundColor Red
            }
        }
        else {
            Write-Log "Custom path not found: $CustomPath" -ForegroundColor Red
        }
    }
    
    # Try default system locations
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "Loaded ActiveDirectory module from system." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Log "ActiveDirectory module not available." -ForegroundColor Yellow
        Write-Log "Will attempt to continue with LDAP fallback methods." -ForegroundColor Yellow
        return $false
    }
}

function Convert-DomainDNtoFQDN {
    param([string]$DomainInput)
    
    # If it's already FQDN (no "DC="), return as is
    if ($DomainInput -notmatch "DC=") {
        return $DomainInput.Trim()
    }
    
    # Convert DN like "DC=contoso,DC=com" to "contoso.com"
    $parts = $DomainInput -split "," | ForEach-Object {
        if ($_ -match "^DC=(.+)$") {
            $matches[1]
        }
    }
    return ($parts -join ".").ToLower()
}

function Get-DomainController {
    param([string]$DomainFQDN)
    
    Write-Log "Locating domain controller for $DomainFQDN..." -ForegroundColor Cyan
    
    # Try AD module first
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        try {
            $dc = Get-ADDomainController -Discover -DomainName $DomainFQDN -ErrorAction Stop
            Write-Log "Found DC via AD module: $($dc.HostName)" -ForegroundColor Green
            return $dc.HostName
        }
        catch {
            Write-Log "AD module discovery failed: $_" -ForegroundColor Yellow
        }
    }
    
    # Fallback to DNS lookup
    try {
        $dc = [System.Net.Dns]::GetHostEntry("_ldap._tcp.dc._msdcs.$DomainFQDN").HostName
        if ($dc -is [array]) { $dc = $dc[0] }
        Write-Log "Found DC via DNS SRV: $dc" -ForegroundColor Green
        return $dc
    }
    catch {
        Write-Log "DNS SRV lookup failed: $_" -ForegroundColor Red
        return $null
    }
}

function Test-LdapSigning {
    param(
        [string]$Server,
        [string]$DomainFQDN,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    Write-Log "Testing LDAP signing requirement on $Server..." -ForegroundColor Cyan
    
    # Load required assembly
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to load System.DirectoryServices.Protocols: $_" -ForegroundColor Red
        return $null
    }
    
    # Prepare credentials
    $ldapCred = $null
    if ($Credential) {
        $ldapCred = New-Object System.Net.NetworkCredential($Credential.UserName, $Credential.GetNetworkCredential().Password)
    }
    else {
        # Use current Windows identity
        $ldapCred = [System.Net.CredentialCache]::DefaultNetworkCredentials
    }
    
    # Create LDAP connection
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, 389)
    $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $ldapCred, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
    
    try {
        # Disable signing requirement for this test
        $connection.SessionOptions.Signing = $false
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.Timeout = [TimeSpan]::FromSeconds(10)
        
        Write-Log "Attempting LDAP bind WITHOUT signing..." -ForegroundColor Gray
        $connection.Bind()
        
        # If we get here, bind succeeded without signing
        Write-Log "Bind succeeded without signing!" -ForegroundColor Green
        $requiresSigning = $false
    }
    catch {
        $ex = $_.Exception.InnerException -as [System.DirectoryServices.Protocols.DirectoryOperationException]
        if ($ex -and $ex.Response.ErrorMessage -match "Strong authentication required|8|00002028") {
            Write-Log "Bind failed: STRONG AUTHENTICATION REQUIRED (LDAP signing is enforced)." -ForegroundColor Red
            $requiresSigning = $true
        }
        else {
            Write-Log "Unexpected error during bind: $_" -ForegroundColor Red
            Write-Log "This may indicate connectivity issues or authentication problems." -ForegroundColor Yellow
            return $null
        }
    }
    finally {
        $connection.Dispose()
    }
    
    return $requiresSigning
}

function Get-LdapSigningStatus {
    param([string]$DomainInput)
    
    # Convert domain input to FQDN
    $domainFQDN = Convert-DomainDNtoFQDN -DomainInput $DomainInput
    Write-Log "Target domain FQDN: $domainFQDN" -ForegroundColor Cyan
    
    # Get a domain controller
    $dc = Get-DomainController -DomainFQDN $domainFQDN
    if (-not $dc) {
        Write-Error "Unable to find a domain controller for $domainFQDN"
        return $null
    }
    
    # Test LDAP signing
    $requiresSigning = Test-LdapSigning -Server $dc -DomainFQDN $domainFQDN -Credential $Credential
    
    if ($null -eq $requiresSigning) {
        Write-Error "LDAP signing test failed. Cannot determine status."
        return $null
    }
    
    return @{
        DomainFQDN = $domainFQDN
        DomainController = $dc
        LDAPSigningRequired = $requiresSigning
        LDAPSigningNotRequired = -not $requiresSigning
        TestTime = Get-Date
    }
}

#endregion

#region Main Execution

Clear-Host
Write-Host "========================================================" -ForegroundColor Green
Write-Host "       LDAP SIGNING REQUIREMENT CHECKER v1.0" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

# Parse domain input
$originalDomain = $Domain
$domainFQDN = Convert-DomainDNtoFQDN -DomainInput $Domain
Write-Host "[Input] Domain specified: $originalDomain" -ForegroundColor White
Write-Host "[Info] Normalized FQDN: $domainFQDN" -ForegroundColor White
Write-Host ""

# Load AD module (optional, improves DC discovery)
Load-ADModule -CustomPath $ADModulePath | Out-Null

# Perform the test
$result = Get-LdapSigningStatus -DomainInput $domainFQDN

# Output results
Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "                         RESULTS" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

if ($result) {
    Write-Host ""
    Write-Host "Domain               : $($result.DomainFQDN)" -ForegroundColor Cyan
    Write-Host "Domain Controller    : $($result.DomainController)" -ForegroundColor Cyan
    
    if ($result.LDAPSigningRequired) {
        Write-Host "LDAP Signing Required: YES" -ForegroundColor Red
        Write-Host "Status               : SECURE - LDAP signing is enforced." -ForegroundColor Yellow
        Write-Host "Recommendation       : No action needed (compliant)." -ForegroundColor Green
    }
    else {
        Write-Host "LDAP Signing Required: NO" -ForegroundColor Red
        Write-Host "Status               : VULNERABLE - LDAP signing is NOT required." -ForegroundColor Red
        Write-Host "Risk                 : Susceptible to LDAP man-in-the-middle attacks." -ForegroundColor Red
        Write-Host "Recommendation       : Enable 'Domain controller: LDAP server signing requirements' policy." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Test performed        : $($result.TestTime)" -ForegroundColor Gray
}
else {
    Write-Host ""
    Write-Host "Test failed. Could not determine LDAP signing status." -ForegroundColor Red
    Write-Host "Check connectivity, permissions, and domain name." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green

#endregion
