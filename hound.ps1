function Invoke-ADDiscovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DomainController,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter = '(objectClass=*)',
        
        [Parameter(Mandatory = $false)]
        [string]$BaseDN,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(100, 5000)]
        [int]$BatchSize = 1000,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseContainerPartitioning,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludePKIObjects,
        
        [Parameter(Mandatory = $false)]
        [switch]$VerboseOutput
    )
    
    # Import required modules
    $requiredModules = @('ActiveDirectory')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Warning "Module $module is not available. Some features may not work."
        }
    }
    
    # Initialize counters and tracking
    $stats = @{
        ObjectsProcessed = 0
        StartTime = Get-Date
        ContainersProcessed = @()
        ErrorsEncountered = @()
    }
    
    # Create output file with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fullOutputPath = Join-Path $OutputPath "AD_Discovery_$timestamp.txt"
    
    # Main discovery logic
    try {
        Write-Verbose "Starting Active Directory discovery..."
        
        if ($IncludePKIObjects) {
            Discover-PKIObjects -DomainController $DomainController `
                -Credential $Credential `
                -OutputPath $fullOutputPath `
                -Stats $stats
        }
        else {
            $searchParams = @{
                Filter = $Filter
                Properties = '*'
                ResultPageSize = $BatchSize
            }
            
            if ($DomainController) { $searchParams.Server = $DomainController }
            if ($BaseDN) { $searchParams.SearchBase = $BaseDN }
            if ($Credential) { $searchParams.Credential = $Credential }
            
            if ($UseContainerPartitioning) {
                Discover-ByContainers @searchParams -OutputPath $fullOutputPath -Stats $stats
            }
            else {
                Discover-Standard @searchParams -OutputPath $fullOutputPath -Stats $stats
            }
        }
        
        # Generate summary report
        Generate-SummaryReport -Stats $stats -OutputPath $fullOutputPath
        
    }
    catch {
        Write-Error "Discovery failed: $_"
        throw
    }
}

# Helper functions
function Discover-Standard {
    param(
        [hashtable]$SearchParams,
        [string]$OutputPath,
        [hashtable]$Stats
    )
    
    $batchCount = 0
    $writer = [System.IO.StreamWriter]::new($OutputPath, $true, [System.Text.Encoding]::UTF8)
    
    try {
        $objects = Get-ADObject @SearchParams -ErrorAction SilentlyContinue
        
        foreach ($object in $objects) {
            Format-ADObject -Object $object -Writer $writer
            $batchCount++
            $Stats.ObjectsProcessed++
            
            if ($batchCount % 1000 -eq 0) {
                Write-Progress -Activity "Processing AD Objects" `
                    -Status "Processed $batchCount objects" `
                    -PercentComplete (($batchCount / 10000) * 100)
                $writer.Flush()
            }
        }
    }
    finally {
        $writer.Flush()
        $writer.Close()
    }
}

function Discover-PKIObjects {
    param(
        [string]$DomainController,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$OutputPath,
        [hashtable]$Stats
    )
    
    $pkiObjectTypes = @(
        @{Type = 'Certificate Templates'; Filter = '(objectClass=pKICertificateTemplate)'}
        @{Type = 'Enrollment Services'; Filter = '(objectClass=pKIEnrollmentService)'}
        @{Type = 'Certificate Authorities'; Filter = '(objectClass=certificationAuthority)'}
    )
    
    foreach ($pkiType in $pkiObjectTypes) {
        Write-Verbose "Discovering $($pkiType.Type)..."
        
        $params = @{
            Filter = $pkiType.Filter
            Properties = '*'
        }
        
        if ($DomainController) { $params.Server = $DomainController }
        if ($Credential) { $params.Credential = $Credential }
        
        $objects = Get-ADObject @params -SearchBase (Get-ADRootDSE).ConfigurationNamingContext
        
        foreach ($object in $objects) {
            Format-PKIObject -Object $object -ObjectType $pkiType.Type -OutputPath $OutputPath
            $Stats.ObjectsProcessed++
        }
    }
}

function Format-ADObject {
    param(
        [PSObject]$Object,
        [System.IO.StreamWriter]$Writer
    )
    
    $output = @()
    $output += "DistinguishedName: $($Object.DistinguishedName)"
    $output += "ObjectClass: $($Object.ObjectClass)"
    $output += "Created: $($Object.Created)"
    $output += "Modified: $($Object.Modified)"
    
    # Add additional properties based on object type
    switch ($Object.ObjectClass) {
        'user' {
            $output += "SAMAccountName: $($Object.SAMAccountName)"
            $output += "UserPrincipalName: $($Object.UserPrincipalName)"
            if ($Object.LastLogonDate) {
                $output += "LastLogon: $($Object.LastLogonDate)"
            }
        }
        'group' {
            $output += "SAMAccountName: $($Object.SAMAccountName)"
            $output += "GroupCategory: $($Object.GroupCategory)"
            $output += "GroupScope: $($Object.GroupScope)"
        }
        'computer' {
            $output += "SAMAccountName: $($Object.SAMAccountName)"
            $output += "DNSHostName: $($Object.DNSHostName)"
            if ($Object.LastLogonDate) {
                $output += "LastLogon: $($Object.LastLogonDate)"
            }
        }
    }
    
    $output += "---"
    $Writer.WriteLine(($output -join "`n"))
}

function Generate-SummaryReport {
    param(
        [hashtable]$Stats,
        [string]$OutputPath
    )
    
    $summary = @"
========================================
Active Directory Discovery Summary
========================================
Start Time: $($Stats.StartTime)
End Time: $(Get-Date)
Duration: $((Get-Date) - $Stats.StartTime)
Objects Processed: $($Stats.ObjectsProcessed)
Containers Processed: $($Stats.ContainersProcessed.Count)
Errors: $($Stats.ErrorsEncountered.Count)
Output File: $OutputPath
========================================
"@
    
    Add-Content -Path $OutputPath -Value "`n`n$summary"
    Write-Output $summary
}

# Additional utility functions for authorized testing
function Test-LDAPConnectivity {
    param([string]$Server)
    
    try {
        $rootDSE = Get-ADRootDSE -Server $Server -ErrorAction Stop
        return @{
            Success = $true
            Domain = $rootDSE.DefaultNamingContext
            Forest = $rootDSE.RootDomainNamingContext
        }
    }
    catch {
        return @{Success = $false; Error = $_}
    }
}

function Get-ADReplicationStatus {
    param([string]$DomainController)
    
    $params = @{}
    if ($DomainController) { $params.Server = $DomainController }
    
    try {
        Get-ADReplicationPartnerMetadata @params | Select-Object Server, Partner, LastReplicationSuccess
    }
    catch {
        Write-Warning "Replication status unavailable: $_"
    }
}
