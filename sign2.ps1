<#
.SYNOPSIS
    Checks if LDAP signing is required on domain controllers.
.DESCRIPTION
    Accepts domain names in FQDN or DN format (with or without spaces).
    Can target a specific domain controller via -Server.
.PARAMETER Domain
    Target domain (FQDN or DN). Example: "contoso.com" or "DC=contoso,DC=com".
.PARAMETER Server
    Optional domain controller hostname/IP (bypasses discovery).
.PARAMETER Credential
    Optional alternate credentials.
.PARAMETER ADModulePath
    Path to ActiveDirectory.psd1 or Microsoft.ActiveDirectory.Management.dll.
.PARAMETER VerboseOutput
    Show detailed progress.
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "DC=STADC6200,DC=RO2,DC=XLGS,DC=LOCAL"
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "STADC6200.RO2.XLGS.LOCAL" -Server "dc01.stadc6200.ro2.xlgs.local"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Domain,
    
    [string]$Server,
    
    [System.Management.Automation.PSCredential]$Credential,
    
    [string]$ADModulePath,
    
    [switch]$VerboseOutput
)

# -------------------- Helper Functions --------------------
function Write-Log {
    param([string]$Message, [string]$ForegroundColor = "Gray", [switch]$IsVerbose)
    if ($IsVerbose -and -not $VerboseOutput) { return }
    $timeStamp = Get-Date -Format "HH:mm:ss"
    if ($VerboseOutput -or $ForegroundColor -ne "Gray") {
        Write-Host "[$timeStamp] $Message" -ForegroundColor $ForegroundColor
    } else {
        Write-Verbose $Message
    }
}

function Load-ADModule {
    param([string]$CustomPath)
    if (Get-Module -Name ActiveDirectory) { return $true }
    if ($CustomPath -and (Test-Path $CustomPath)) {
        try { Import-Module $CustomPath -ErrorAction Stop; return $true }
        catch { Write-Log "Failed to load AD module from custom path: $_" -ForegroundColor Red }
    }
    try { Import-Module ActiveDirectory -ErrorAction Stop; return $true }
    catch { Write-Log "AD module not available. Using DNS/LDAP fallback." -ForegroundColor Yellow }
    return $false
}

# ============= ROBUST DN → FQDN CONVERTER =============
function Convert-DomainDNtoFQDN {
    param([string]$DomainInput)
    
    # 1. Remove ALL spaces
    $clean = $DomainInput -replace '\s+', ''
    # 2. Fix common typo: DE= -> DC= (case-insensitive)
    $clean = $clean -replace '(?i)DE=', 'DC='
    
    # Already FQDN? (no DC=)
    if ($clean -notmatch 'DC=') {
        return $clean.Trim()
    }
    
    # 3. Extract DC components (ignore anything else)
    $dcParts = @()
    $segments = $clean -split ','
    foreach ($seg in $segments) {
        if ($seg -match '^DC=(.+)$') {
            $dcParts += $matches[1]
        }
    }
    
    if ($dcParts.Count -eq 0) {
        Write-Log "No DC= components found in DN. Treating as FQDN." -ForegroundColor Yellow
        return $clean
    }
    
    return ($dcParts -join '.').ToLower()
}

# ============= DOMAIN CONTROLLER DISCOVERY =============
function Get-DomainController {
    param([string]$DomainFQDN, [string]$ManualServer)
    
    if ($ManualServer) {
        Write-Log "Using manually specified server: $ManualServer" -ForegroundColor Cyan -IsVerbose
        return $ManualServer
    }
    
    # 1. Try AD module discovery
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        try {
            $dc = Get-ADDomainController -Discover -DomainName $DomainFQDN -ErrorAction Stop
            Write-Log "Found DC via AD module: $($dc.HostName)" -ForegroundColor Green -IsVerbose
            return $dc.HostName
        }
        catch { Write-Log "AD module discovery failed: $_" -ForegroundColor Yellow -IsVerbose }
    }
    
    # 2. Try DNS SRV lookup
    try {
        $dc = [System.Net.Dns]::GetHostEntry("_ldap._tcp.dc._msdcs.$DomainFQDN").HostName
        if ($dc -is [array]) { $dc = $dc[0] }
        Write-Log "Found DC via DNS SRV: $dc" -ForegroundColor Green -IsVerbose
        return $dc
    }
    catch { Write-Log "DNS SRV lookup failed: $_" -ForegroundColor Yellow -IsVerbose }
    
    # 3. Last resort: try the domain FQDN itself (may resolve to a DC)
    try {
        [System.Net.Dns]::GetHostEntry($DomainFQDN) | Out-Null
        Write-Log "Domain FQDN resolves; using as server: $DomainFQDN" -ForegroundColor Yellow -IsVerbose
        return $DomainFQDN
    }
    catch { Write-Log "Domain FQDN does not resolve to a valid host." -ForegroundColor Red -IsVerbose }
    
    return $null
}

# ============= LDAP SIGNING TEST =============
function Test-LdapSigning {
    param([string]$Server, [string]$DomainFQDN, [PSCredential]$Credential)
    
    Write-Log "Testing LDAP signing on $Server..." -ForegroundColor Cyan
    try { Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop }
    catch { Write-Log "Failed to load required assembly: $_" -ForegroundColor Red; return $null }
    
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
        return $false
    }
    catch {
        $ex = $_.Exception.InnerException -as [System.DirectoryServices.Protocols.DirectoryOperationException]
        if ($ex -and $ex.Response.ErrorMessage -match "Strong authentication required|8|00002028") {
            Write-Log "Bind failed: STRONG AUTHENTICATION REQUIRED (signing enforced)." -ForegroundColor Red -IsVerbose
            return $true
        }
        else {
            Write-Log "Unexpected bind error: $_" -ForegroundColor Red
            return $null
        }
    }
    finally { $connection.Dispose() }
}

# -------------------- MAIN --------------------
Clear-Host
Write-Host "========================================================" -ForegroundColor Green
Write-Host "       LDAP SIGNING REQUIREMENT CHECKER v2.0" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

# Parse domain
$originalDomain = $Domain
$domainFQDN = Convert-DomainDNtoFQDN -DomainInput $Domain

if (-not $domainFQDN) {
    Write-Error "Could not parse domain name. Please provide a valid FQDN or DN."
    exit 1
}

Write-Host "[Input] Domain specified: $originalDomain" -ForegroundColor White
Write-Host "[Info] Normalized FQDN: $domainFQDN" -ForegroundColor White
Write-Host ""

# Load AD module (if possible)
Load-ADModule -CustomPath $ADModulePath | Out-Null

# Get domain controller
$dc = Get-DomainController -DomainFQDN $domainFQDN -ManualServer $Server
if (-not $dc) {
    Write-Error "`n[ERROR] Could not locate a domain controller for '$domainFQDN'."
    Write-Host "`nPossible solutions:" -ForegroundColor Yellow
    Write-Host " 1. Check that the domain name is correct and reachable."
    Write-Host " 2. Use the -Server parameter to specify a known DC manually."
    Write-Host " 3. Ensure DNS resolution works for this domain."
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
    Write-Host "Try using -VerboseOutput for more details." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
