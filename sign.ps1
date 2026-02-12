<#
.SYNOPSIS
    Tests if LDAP signing is required on a domain controller.
.DESCRIPTION
    Accepts messy domain names, auto-corrects typos, and uses multiple methods
    to locate a DC. Returns SECURE (signing required) or VULNERABLE (signing not required).
.PARAMETER Domain
    Domain name in any format: FQDN, DN, NetBIOS, or even with spaces/typos.
.PARAMETER DomainController
    Optional – specify a DC hostname or IP to bypass auto-discovery.
.PARAMETER Credential
    Optional alternate credentials.
.PARAMETER ADModulePath
    Path to ActiveDirectory.psd1 or Microsoft.ActiveDirectory.Management.dll.
.PARAMETER VerboseOutput
    Show detailed progress.
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "STADC6200. R02. XLGS. LOCAL"
.EXAMPLE
    .\Test-LdapSigning.ps1 -Domain "STADC6200.RO2.XLGS.LOCAL" -DomainController "dc01.stadc6200.ro2.xlgs.local"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Domain,

    [string]$DomainController,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$ADModulePath,

    [switch]$VerboseOutput
)

# ------------------------------------------------------------
# LOGGING – respects -VerboseOutput, plain ASCII only
# ------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [string]$ForegroundColor = "Gray",
        [switch]$IsVerbose
    )
    if ($IsVerbose -and -not $VerboseOutput) { return }
    $timestamp = Get-Date -Format "HH:mm:ss"
    if ($VerboseOutput -or $ForegroundColor -ne "Gray") {
        Write-Host "[$timestamp] $Message" -ForegroundColor $ForegroundColor
    } else {
        Write-Verbose $Message
    }
}

# ------------------------------------------------------------
# LOAD AD MODULE – supports DLL path
# ------------------------------------------------------------
function Load-ADModule {
    param([string]$CustomPath)

    if (Get-Module -Name ActiveDirectory) {
        Write-Log "ActiveDirectory module already loaded." -ForegroundColor Green -IsVerbose
        return $true
    }

    if ($CustomPath -and (Test-Path $CustomPath)) {
        try {
            Write-Log "Loading from custom path: $CustomPath" -ForegroundColor Yellow -IsVerbose
            Import-Module $CustomPath -ErrorAction Stop
            Write-Log "Successfully loaded ActiveDirectory module." -ForegroundColor Green -IsVerbose
            return $true
        } catch {
            Write-Log "Failed to load from custom path: $_" -ForegroundColor Red -IsVerbose
        }
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "Loaded ActiveDirectory module from system." -ForegroundColor Green -IsVerbose
        return $true
    } catch {
        Write-Log "ActiveDirectory module not available. Using DNS/LDAP fallback." -ForegroundColor Yellow -IsVerbose
        return $false
    }
}

# ------------------------------------------------------------
# DOMAIN NORMALIZATION – removes spaces, fixes "02" -> "RO2"
# ------------------------------------------------------------
function Normalize-DomainName {
    param([string]$InputString)

    # Remove all spaces
    $clean = $InputString -replace '\s+', ''

    # If DN (contains "DC="), clean and return
    if ($clean -match 'DC=') {
        return $clean
    }

    # Fix common typo: .02. -> .RO2.
    if ($clean -match '\.02\.') {
        $clean = $clean -replace '\.02\.', '.RO2.'
        Write-Log "Corrected '02' to 'RO2' -> $clean" -ForegroundColor Yellow -IsVerbose
    }

    # Lowercase, trim trailing dot
    $clean = $clean.ToLower().TrimEnd('.')

    return $clean
}

# ------------------------------------------------------------
# DOMAIN CONTROLLER DISCOVERY – 5 methods, full error handling
# ------------------------------------------------------------
function Resolve-DomainController {
    param([string]$DomainFQDN)

    # 1. Manual override
    if ($DomainController) {
        Write-Log "Using manually specified DC: $DomainController" -ForegroundColor Green -IsVerbose
        return $DomainController
    }

    # 2. AD module discovery
    if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
        try {
            $dc = Get-ADDomainController -Discover -DomainName $DomainFQDN -ErrorAction Stop
            Write-Log "Method 2 (AD module) found: $($dc.HostName)" -ForegroundColor Green -IsVerbose
            return $dc.HostName
        } catch {
            Write-Log "Method 2 failed: $_" -ForegroundColor DarkGray -IsVerbose
        }
    }

    # 3. DNS SRV record
    try {
        $dc = [System.Net.Dns]::GetHostEntry("_ldap._tcp.dc._msdcs.$DomainFQDN").HostName
        if ($dc -is [array]) { $dc = $dc[0] }
        Write-Log "Method 3 (DNS SRV) found: $dc" -ForegroundColor Green -IsVerbose
        return $dc
    } catch {
        Write-Log "Method 3 failed: $_" -ForegroundColor DarkGray -IsVerbose
    }

    # 4. DNS A record of the domain name
    try {
        $dc = [System.Net.Dns]::GetHostEntry($DomainFQDN).HostName
        if ($dc -is [array]) { $dc = $dc[0] }
        Write-Log "Method 4 (DNS A) found: $dc" -ForegroundColor Green -IsVerbose
        return $dc
    } catch {
        Write-Log "Method 4 failed: $_" -ForegroundColor DarkGray -IsVerbose
    }

    # 5. LDAP rootDSE ping
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainFQDN, 389)
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
        $conn.SessionOptions.ProtocolVersion = 3
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $conn.Timeout = [TimeSpan]::FromSeconds(5)
        $request = New-Object System.DirectoryServices.Protocols.SearchRequest("", "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, "defaultNamingContext")
        $null = $conn.SendRequest($request)
        $conn.Dispose()
        Write-Log "Method 5 (LDAP ping) succeeded – DC is $DomainFQDN" -ForegroundColor Green -IsVerbose
        return $DomainFQDN
    } catch {
        Write-Log "Method 5 failed: $_" -ForegroundColor DarkGray -IsVerbose
    }

    return $null
}

# ------------------------------------------------------------
# CORE LDAP SIGNING TEST – one-line regex, no pipeline issues
# ------------------------------------------------------------
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
    } catch {
        Write-Log "Failed to load System.DirectoryServices.Protocols: $_" -ForegroundColor Red
        return $null
    }

    # Prepare credentials
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

        # Bind succeeded → signing NOT required
        Write-Log "Bind succeeded without signing!" -ForegroundColor Green -IsVerbose
        return $false
    } catch {
        $ex = $_.Exception.InnerException -as [System.DirectoryServices.Protocols.DirectoryOperationException]
        # ONE LINE regex – no line breaks, no pipeline confusion
        if ($ex -and $ex.Response.ErrorMessage -match "Strong authentication required|8|00002028") {
            Write-Log "Bind failed: STRONG AUTHENTICATION REQUIRED (signing enforced)." -ForegroundColor Red -IsVerbose
            return $true
        } else {
            Write-Log "Unexpected error during bind: $_" -ForegroundColor Red
            return $null
        }
    } finally {
        if ($connection) { $connection.Dispose() }
    }
}

# ------------------------------------------------------------
# MAIN SCRIPT – pure ASCII, no stray characters
# ------------------------------------------------------------
Clear-Host
Write-Host "========================================================" -ForegroundColor Green
Write-Host "       LDAP SIGNING REQUIREMENT CHECKER v3.0" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""

# 1. Normalize domain
$originalDomain = $Domain
$normalizedDomain = Normalize-DomainName -InputString $originalDomain
Write-Host "[Input]      : $originalDomain" -ForegroundColor White
Write-Host "[Normalized] : $normalizedDomain" -ForegroundColor White
Write-Host ""

# 2. Load AD module (optional)
Load-ADModule -CustomPath $ADModulePath | Out-Null

# 3. Find a domain controller
$dc = Resolve-DomainController -DomainFQDN $normalizedDomain
if (-not $dc) {
    Write-Error "`n[ERROR] Cannot locate a domain controller for '$normalizedDomain'."
    Write-Host "`nPossible fixes:" -ForegroundColor Yellow
    Write-Host "  * Use -DomainController <DC_NAME> to specify a DC manually." -ForegroundColor Cyan
    Write-Host "  * Check network/DNS connectivity." -ForegroundColor Cyan
    Write-Host "  * Verify the domain name is correct (e.g., contoso.com)." -ForegroundColor Cyan
    exit 1
}
Write-Host "[DC]         : $dc" -ForegroundColor Green

# 4. Perform the LDAP signing test
$requiresSigning = Test-LdapSigning -Server $dc -DomainFQDN $normalizedDomain -Credential $Credential

# 5. Display results
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
    } else {
        Write-Host "LDAP Signing Required: NO" -ForegroundColor Red
        Write-Host "Status               : VULNERABLE - LDAP signing is NOT required." -ForegroundColor Red
        Write-Host "Risk                 : Susceptible to LDAP man-in-the-middle attacks." -ForegroundColor Red
        Write-Host "Recommendation       : Enable 'Domain controller: LDAP server signing requirements' policy." -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "Test failed. Could not determine LDAP signing status." -ForegroundColor Red
    Write-Host "Check connectivity, permissions, and domain name." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
