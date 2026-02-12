<#
.SYNOPSIS
    Checks if LDAP signing is required on domain controllers for a given domain.
.DESCRIPTION
    Uses the Active Directory module (loaded from DLL if needed) and direct LDAP binds
    to determine whether unsigned LDAP is allowed. Accepts domain names in FQDN or DN format.
.PARAMETER Domain
    Target domain. Can be FQDN (contoso.com) or Distinguished Name (DC=contoso,DC=com).
.PARAMETER Credential
    Optional alternate credentials for LDAP bind.
.PARAMETER ADModulePath
    Path to ActiveDirectory.psd1 or Microsoft.ActiveDirectory.Management.dll (if not installed).
.PARAMETER VerboseOutput
    Show detailed progress and diagnostic messages.
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "contoso.com"
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "DC=contoso,DC=com" -VerboseOutput
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "contoso.com" -ADModulePath ".\ADModule\ActiveDirectory.psd1"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Domain,
    
    [System.Management.Automation.PSCredential]$Credential,
    
    [string]$ADModulePath,
    
    [switch]$VerboseOutput
)

# Use Write-Verbose for verbose messages, but also provide console output when -VerboseOutput is used
function Write-Log {
    param(
        [string]$Message,
        [string]$ForegroundColor = "Gray",
        [switch]$IsVerbose
    )
    
    if ($IsVerbose -and -not $VerboseOutput) { return }
    
    $timeStamp = Get-Date -Format "HH:mm:ss"
    if ($VerboseOutput -or $ForegroundColor -ne "Gray") {
        Write-Host "[$timeStamp] $Message" -ForegroundColor $ForegroundColor
    }
    else {
        Write-Verbose $Message
    }
}

function Load-ADModule {
    param([string]$CustomPath)
    
    Write-Log "Checking for ActiveDirectory module..." -ForegroundColor Cyan
    
    if (Get-Module -Name ActiveDirectory) {
        Write-Log "ActiveDirectory module already loaded." -ForegroundColor Green
        return $true
    }
    
    if ($CustomPath -and (Test-Path $CustomPath)) {
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
    
    # Try default system locations
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "Loaded ActiveDirectory module from system." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Log "ActiveDirectory module not available. Will use DNS + LDAP fallback." -ForegroundColor Yellow
        return $false
    }
}

function Convert-DomainDNtoFQDN {
    param([string]$DomainInput)
    
    # Already FQDN?
    if ($DomainInput -notmatch "DC=") {
        return $DomainInput.Trim()
    }
    
    # Convert "DC=contoso,DC=com" -> "contoso.com"
    $parts = $DomainInput -split "," | ForEach-Object {
        if ($_ -match "^DC=(.+)$") { $matches[1] }
    }
    ($parts -join ".").ToLower()
}

function Get-DomainController {
    param([string]$DomainFQDN)
    
    Write-Log "Locating domain controller for $DomainFQDN..." -ForegroundColor Cyan -IsVerbose
    
    # Prefer AD module for DC discovery
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        try {
            $dc = Get-ADDomainController -Discover -DomainName $DomainFQDN -ErrorAction Stop
            Write-Log "Found DC via AD module: $($dc.HostName)" -ForegroundColor Green -IsVerbose
            return $dc.HostName
        }
        catch {
            Write-Log "AD module discovery failed: $_" -ForegroundColor Yellow -IsVerbose
        }
    }
    
    # Fallback to DNS SRV lookup
    try {
        $dc = [System.Net.Dns]::GetHostEntry("_ldap._tcp.dc._msdcs.$DomainFQDN").HostName
        if ($dc -is [array]) { $dc = $dc[0] }
        Write-Log "Found DC via DNS SRV: $dc" -ForegroundColor Green -IsVerbose
        return $dc
    }
    catch {
        Write-Log "DNS SRV lookup failed: $_" -ForegroundColor Red -IsVerbose
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
    
    # Ensure required assembly is loaded
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to load System.DirectoryServices.Protocols: $_" -ForegroundColor Red
        return $null
    }
    
    $ldapCred = if ($Credential) {
        New-Object System.Net.NetworkCredential($Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        [System.Net.CredentialCache]::DefaultNetworkCredentials
    }
    
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, 389)
    $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $ldapCred, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
    
    try {
        $connection.SessionOptions.Signing = $false
        $connection.SessionOptions.ProtocolVersion = 3
        $connection.Timeout = [TimeSpan]::FromSeconds(10)
        
        Write-Log "Attempting LDAP bind WITHOUT signing..." -ForegroundColor Gray -IsVerbose
        $connection.Bind()
        
        # Success → signing NOT required
        Write-Log "Bind succeeded without signing!" -ForegroundColor Green -IsVerbose
        return $false
    }
    catch {
        $ex = $_.Exception.InnerException -as [System.DirectoryServices.Protocols.DirectoryOperationException]
        if ($ex -and $ex.Response.ErrorMessage -match "Strong authentication required|8|00002028") {
            Write-Log "Bind failed: STRONG AUTHENTICATION REQUIRED (signing is enforced)." -ForegroundColor Red -IsVerbose
            return $true
        }
        else {
            Write-Log "Unexpected error during bind: $_" -ForegroundColor Red
            return $null
        }
    }
    finally {
        $connection.Dispose()
    }
}

# -------------------- MAIN --------------------
Clear-Host
Write-Host "========================================================" -ForegroundColor Green
Write-Host "       LDAP SIGNING REQUIREMENT CHECKER v1.1" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

# Normalize domain
$originalDomain = $Domain
$domainFQDN = Convert-DomainDNtoFQDN -DomainInput $Domain
Write-Host "[Input] Domain specified: $originalDomain" -ForegroundColor White
Write-Host "[Info] Normalized FQDN: $domainFQDN" -ForegroundColor White
Write-Host ""

# Try to load AD module
Load-ADModule -CustomPath $ADModulePath | Out-Null

# Get a domain controller
$dc = Get-DomainController -DomainFQDN $domainFQDN
if (-not $dc) {
    Write-Error "Unable to find a domain controller for $domainFQDN"
    exit 1
}

# Perform the test
$requiresSigning = Test-LdapSigning -Server $dc -DomainFQDN $domainFQDN -Credential $Credential

# Output results
Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "                         RESULTS" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

if ($null -ne $requiresSigning) {
    Write-Host ""
    Write-Host "Domain               : $domainFQDN" -ForegroundColor Cyan
    Write-Host "Domain Controller    : $dc" -ForegroundColor Cyan
    
    if ($requiresSigning) {
        Write-Host "LDAP Signing Required: YES" -ForegroundColor Green
        Write-Host "Status               : SECURE - LDAP signing is enforced." -ForegroundColor Green
        Write-Host "Recommendation       : No action needed." -ForegroundColor Gray
    }
    else {
        Write-Host "LDAP Signing Required: NO" -ForegroundColor Red
        Write-Host "Status               : VULNERABLE - LDAP signing is NOT required." -ForegroundColor Red
        Write-Host "Risk                 : Susceptible to LDAP man-in-the-middle attacks." -ForegroundColor Red
        Write-Host "Recommendation       : Enable 'Domain controller: LDAP server signing requirements' policy." -ForegroundColor Yellow
    }
}
else {
    Write-Host ""
    Write-Host "Test failed. Could not determine LDAP signing status." -ForegroundColor Red
    Write-Host "Check connectivity, permissions, and domain name." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
