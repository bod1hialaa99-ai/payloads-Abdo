<#
.SYNOPSIS
    Checks if LDAP signing is required on domain controllers.
    Accepts messy domain input, auto-corrects, and finds DCs reliably.
.PARAMETER Domain
    Domain name in any format: FQDN, DN, NetBIOS, or even with typos/spaces.
.PARAMETER DomainController
    Optional – specify a DC hostname/IP directly (bypass discovery).
.PARAMETER Credential
    Alternate credentials for LDAP bind.
.PARAMETER ADModulePath
    Path to AD module DLL/PSD1 (if not installed).
.PARAMETER VerboseOutput
    Show detailed diagnostic messages.
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "STADC6200. R02. XLGS. LOCAL"
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "DC=STADC6200,DC=RO2,DC=XLGS,DC=LOCAL"
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "STADC6200.RO2.XLGS.LOCAL" -DomainController "dc01.STADC6200.RO2.XLGS.LOCAL"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Domain,
    
    [string]$DomainController,
    
    [System.Management.Automation.PSCredential]$Credential,
    
    [string]$ADModulePath,
    
    [switch]$VerboseOutput
)

# ------------------------------------------------------------
# Enhanced logging – respects -VerboseOutput
# ------------------------------------------------------------
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
    } else {
        Write-Verbose $Message
    }
}

# ------------------------------------------------------------
# Load AD module (DLL support)
# ------------------------------------------------------------
function Load-ADModule {
    param([string]$CustomPath)
    if (Get-Module -Name ActiveDirectory) { return $true }
    if ($CustomPath -and (Test-Path $CustomPath)) {
        try { Import-Module $CustomPath -ErrorAction Stop; return $true } catch {}
    }
    try { Import-Module ActiveDirectory -ErrorAction Stop; return $true } catch {}
    return $false
}

# ------------------------------------------------------------
# INTELLIGENT DOMAIN NORMALIZATION
# Fixes spaces, "02" -> "RO2", removes stray dots, etc.
# ------------------------------------------------------------
function Normalize-DomainName {
    param([string]$InputString)
    
    # Remove all spaces
    $clean = $InputString -replace '\s+', ''
    
    # If it's already a DN (contains "DC="), just clean spaces and return
    if ($clean -match 'DC=') {
        return $clean
    }
    
    # Common typo: "02" should be "RO2" (likely your case)
    if ($clean -match '\.02\.') {
        $clean = $clean -replace '\.02\.', '.RO2.'
        Write-Log "Corrected '02' to 'RO2' → $clean" -ForegroundColor Yellow -IsVerbose
    }
    
    # Ensure it's lowercase for consistency
    $clean = $clean.ToLower()
    
    # Remove trailing dot if present
    $clean = $clean.TrimEnd('.')
    
    # If it still doesn't look like a FQDN (has at least one dot), try to make it one
    if ($clean -notmatch '\.') {
        Write-Log "Domain appears to be NetBIOS name; attempting to resolve..." -ForegroundColor Yellow -IsVerbose
        # We'll keep it as-is; later methods will try to resolve.
    }
    
    return $clean
}

# ------------------------------------------------------------
# DOMAIN CONTROLLER DISCOVERY – 5 methods
# ------------------------------------------------------------
function Resolve-DomainController {
    param([string]$DomainFQDN)
    
    # Method 1: User provided a DC manually
    if ($DomainController) {
        Write-Log "Using manually specified DC: $DomainController" -ForegroundColor Green -IsVerbose
        return $DomainController
    }
    
    # Method 2: AD module (Get-ADDomainController)
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        try {
            $dc = Get-ADDomainController -Discover -DomainName $DomainFQDN -ErrorAction Stop
            Write-Log "Method 2 (AD module) found: $($dc.HostName)" -ForegroundColor Green -IsVerbose
            return $dc.HostName
        } catch { Write-Log "Method 2 failed: $_" -ForegroundColor DarkGray -IsVerbose }
    }
    
    # Method 3: DNS SRV record (_ldap._tcp.dc._msdcs.<domain>)
    try {
        $dc = [System.Net.Dns]::GetHostEntry("_ldap._tcp.dc._msdcs.$DomainFQDN").HostName
        if ($dc -is [array]) { $dc = $dc[0] }
        Write-Log "Method 3 (DNS SRV) found: $dc" -ForegroundColor Green -IsVerbose
        return $dc
    } catch { Write-Log "Method 3 failed: $_" -ForegroundColor DarkGray -IsVerbose }
    
    # Method 4: DNS A record of the domain itself (if it's a DC)
    try {
        $dc = [System.Net.Dns]::GetHostEntry($DomainFQDN).HostName
        if ($dc -is [array]) { $dc = $dc[0] }
        Write-Log "Method 4 (DNS A) found: $dc" -ForegroundColor Green -IsVerbose
        return $dc
    } catch { Write-Log "Method 4 failed: $_" -ForegroundColor DarkGray -IsVerbose }
    
    # Method 5: LDAP query for rootDSE naming context
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction SilentlyContinue
        $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainFQDN, 389)
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
        $conn.SessionOptions.ProtocolVersion = 3
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $conn.Timeout = [TimeSpan]::FromSeconds(5)
        $request = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, "defaultNamingContext")
        $response = $conn.SendRequest($request)
        $conn.Dispose()
        Write-Log "Method 5 (LDAP ping) succeeded – DC is $DomainFQDN" -ForegroundColor Green -IsVerbose
        return $DomainFQDN
    } catch { Write-Log "Method 5 failed: $_" -ForegroundColor DarkGray -IsVerbose }
    
    return $null
}

# ------------------------------------------------------------
# LDAP SIGNING TEST (same reliable method)
# ------------------------------------------------------------
function Test-LdapSigning {
    param($Server, $DomainFQDN, $Credential)
    
    Write-Log "Testing LDAP signing requirement on $Server..." -ForegroundColor Cyan
    
    Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
    
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
        
        Write-Log "Bind succeeded without signing!" -ForegroundColor Green -IsVerbose
        return $false   # signing NOT required (vulnerable)
    }
    catch {
        $ex = $_.Exception.InnerException -as [System.DirectoryServices.Protocols.DirectoryOperationException]
        if ($ex -and $ex.Response.ErrorMessage -match "Strong authentication required|8|00002028") {
            Write-Log "Bind failed: STRONG AUTHENTICATION REQUIRED (signing enforced)." -ForegroundColor Red -IsVerbose
            return $true   # signing IS required (secure)
        }
        else {
            Write-Log "Unexpected error: $_" -ForegroundColor Red
            return $null
        }
    }
    finally {
        $connection.Dispose()
    }
}

# ------------------------------------------------------------
# MAIN EXECUTION
# ------------------------------------------------------------
Clear-Host
Write-Host "========================================================" -ForegroundColor Green
Write-Host "       LDAP SIGNING REQUIREMENT CHECKER v2.0" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

# Step 1: Normalize the domain input (remove spaces, fix typos)
$originalDomain = $Domain
$normalizedDomain = Normalize-DomainName -InputString $originalDomain
Write-Host "[Input]  : $originalDomain" -ForegroundColor White
Write-Host "[Normalized] : $normalizedDomain" -ForegroundColor White
Write-Host ""

# Step 2: Load AD module (optional – helps discovery)
Load-ADModule -CustomPath $ADModulePath | Out-Null

# Step 3: Find a domain controller
$dc = Resolve-DomainController -DomainFQDN $normalizedDomain
if (-not $dc) {
    Write-Error "`n[ERROR] Cannot locate a domain controller for '$normalizedDomain'."
    Write-Host "`nPossible fixes:" -ForegroundColor Yellow
    Write-Host "  • Use -DomainController <DC_NAME> to specify a DC manually." -ForegroundColor Cyan
    Write-Host "  • Check your network/DNS connectivity." -ForegroundColor Cyan
    Write-Host "  • Verify the domain name is correct (use FQDN like 'contoso.com')." -ForegroundColor Cyan
    exit 1
}
Write-Host "[DC]      : $dc" -ForegroundColor Green

# Step 4: Perform the LDAP signing test
$requiresSigning = Test-LdapSigning -Server $dc -DomainFQDN $normalizedDomain -Credential $Credential

# Step 5: Output results
Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "                         RESULTS" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

if ($null -ne $requiresSigning) {
    Write-Host ""
    Write-Host "Domain               : $normalizedDomain" -ForegroundColor Cyan
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
