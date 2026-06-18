[CmdletBinding()]param()

if ($VerbosePreference -eq "Continue") {
	$global:VerbosePreference = "Continue"
} else {
	$global:VerbosePreference = "SilentlyContinue"
}
Import-Module ./FuryPsm/fury.psm1 -Force

$MainMenu = [ordered]@{
	"Title" = "Main Menu"
	"Options" = [ordered]@{
		"Forest/Domain Reports" = { New-Menu $DomainReportsMenu }
		"User/Group Reports" = { New-Menu $UserGroupReportsMenu }
		"Computer/Server Reports" = { New-Menu $ComputerServerReportsMenu }
		"Run All Reports" = { Get-AllInfo }
	}
}

$DomainReportsMenu = [ordered]@{
	"Title" = "Forest/Domain Reports"
	"Options" = [ordered]@{
		"Run all reports" = { Get-ForestDomainInfo -Reports All}
		"Forest and Domain Information" = { Get-ForestDomainInfo -Reports ForestAndDomains }
		"Domain Controllers" = { Get-ForestDomainInfo -Reports DomainControllers }
		"Group Policy Objects" = { Get-ForestDomainInfo -Reports GPOs }
		"Replication Health" = { Get-ForestDomainInfo -Reports ReplicationHealth }
		"AD Sites and Replication Links" = { Get-ForestDomainInfo -Reports Sites }
	}
}

$UserGroupReportsMenu = [ordered]@{
	"Title" = "User/Group Reports"
	"Options" = [ordered]@{
		"Run all reports" = { Get-UserGroupInfo -Reports All }
		"Get All User objects" = { Get-UserGroupInfo -Reports Users }
		"Get All Group objects" = { Get-UserGroupInfo -Reports Groups }
		"Get All Group Memberships" = { Get-UserGroupInfo -Reports GroupMemberships }
		"Get All Nested Groups" = { Get-UserGroupInfo -Reports NestedGroups }
	}
}

$ComputerServerReportsMenu = [ordered]@{
	"Title" = "Computer/Server Reports"
	"Options" = [ordered]@{
		"Run all reports" = { Get-ComputerServerInfo -Reports All }
		"Get All Computer objects" = { Get-ComputerServerInfo -Reports Computers }
		"Get All Server objects" = { Get-ComputerServerInfo -Reports Servers }
	}
}

function Write-Title {
	Param(
		[String]$PageTitle,
		[String]$AppendFunction
	)
	
	Clear-Host
	Write-Host -Fore Green "`n$($PageTitle.ToUpper())"
	
	If ( $AppendFunction ) {
		Invoke-Expression $AppendFunction
	}

	Write-Host ""
}

function New-Menu {
param(
	[Parameter(Mandatory=$true)]$MenuObject
)

	do {
		$IsMain = $MenuObject["Title"] -eq "Main Menu"

		Write-Title -PageTitle $MenuObject["Title"]

		$i = 1
		$actions = @()

		foreach ($option in $MenuObject["Options"].Keys) {
			Write-Host -Fore Yellow "$i. $option"
			$actions += [scriptblock]$MenuObject["Options"][$option]
			$i++
		}
		Write-Host -Fore Yellow "X. $(if ($IsMain) { "Exit" } else { "Back" })"

		$UserChoice = Read-Host "`nSelect [1 - $($MenuObject["Options"].Count), X]"

		while ( (1..$MenuObject["Options"].Count)+"X" -notcontains $UserChoice ) {
			$UserChoice = Read-Host "Invalid option. Try again [1 - $($MenuObject["Options"].Count), X]"
		}

		if ($UserChoice -eq "X") {
			$ExitMenu = $true
		} else {
			try {
				& $actions[$UserChoice - 1]
			} catch [Exception] {
				$_
				continue
			}
		}
	} while (-not $ExitMenu)

	if ($MenuObject["Title"] -eq "Main Menu") {
		Write-Host "Exiting..." -Fore Green
		Exit-Script
	} else {
		return
	}
}

# =========== DISCOVERY FUNCTIONS ===========
function Test-AdminPrivilege {
	# Well-known privileged SIDs (BUILTIN\Administrators) and RID suffixes for domain/forest privileged groups.
	$privilegedSids = @("S-1-5-32-544")
	$privilegedRids = @("512","519","518","516","521") # Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers, Read-only Domain Controllers

	try {
		if ($global:CredSplat -and $global:CredSplat["Credential"]) {
			$rawName = $global:CredSplat["Credential"].UserName
			if ($rawName -match "@") {
				$samAccount = ($rawName -split "@")[0]
			} elseif ($rawName -match "\\") {
				$samAccount = ($rawName -split "\\")[-1]
			} else {
				$samAccount = $rawName
			}
		} else {
			$samAccount = [Environment]::UserName
		}

		Write-Log "Testing admin privileges for $samAccount"
		$adUser = Get-ADUser -Identity $samAccount | Get-ADUser -Identity $_.DistinguishedName -Properties "tokenGroups","memberOf" @CredSplat @eaSplat

		# tokenGroups expands all (including nested) group memberships present in the user's token.
		foreach ($sid in @($adUser.tokenGroups | ForEach-Object { $_.Value })) {
			if ($privilegedSids -contains $sid) { return $true }
			if ($sid -match '-(\d+)$' -and $privilegedRids -contains $Matches[1]) { return $true }
		}

		# Fallback: inspect the direct memberOf DNs by name in case tokenGroups could not be evaluated.
		foreach ($groupDn in $adUser.memberOf) {
			if ($groupDn -match '^CN=(Domain Admins|Enterprise Admins|Schema Admins|Administrators),') { return $true }
		}

		return $false
	} catch {
		Write-Log "Unable to determine whether the current identity is privileged; assuming standard (non-privileged) rights. The specific error is: $_" -Level WARNING
		return $false
	}
}

function Get-RemoteSystemInfo {
	<#
		Connects to a remote computer over CIM/WMI (DCOM) and returns an ordered hashtable of local
		system facts (CPU, RAM, storage, uptime). Returns the hashtable with $null values on failure
		so callers can merge it into a record unconditionally.
	#>
	param(
		[Parameter(Mandatory=$true)][string]$ComputerName
	)

	$info = [ordered]@{
		"CPU Cores" = $null
		"Total RAM (GB)" = $null
		"Total Storage (GB)" = $null
		"Free Storage (GB)" = $null
		"Last Boot" = $null
		"Uptime (Days)" = $null
	}

	$session = $null
	try {
		$sessionParams = @{ ComputerName = $ComputerName; ErrorAction = "Stop" }
		if ($global:CredSplat -and $global:CredSplat["Credential"]) {
			$sessionParams["Credential"] = $global:CredSplat["Credential"]
		}
		$session = New-CimSession @sessionParams

		$os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
		$cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop
		$disks = Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop

		$info["CPU Cores"] = $cs.NumberOfLogicalProcessors
		$info["Total RAM (GB)"] = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
		$info["Total Storage (GB)"] = [math]::Round((($disks | Measure-Object -Property Size -Sum).Sum) / 1GB, 1)
		$info["Free Storage (GB)"] = [math]::Round((($disks | Measure-Object -Property FreeSpace -Sum).Sum) / 1GB, 1)
		$info["Last Boot"] = $os.LastBootUpTime
		$info["Uptime (Days)"] = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
	} catch {
		Write-Log "Failed to collect remote system information from $ComputerName via CIM/WMI. The specific error is: $_" -Level WARNING
	} finally {
		if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
	}

	return $info
}

function Get-GPOLinks {
	<#
		Returns the locations (sites, domains, OUs) a GPO is linked to by parsing its XML report.
		Each entry is a string of the form "<SOMPath> [Enabled|Disabled][, Enforced]".
		Returns an empty array if the GPO is not linked anywhere.
	#>
	param(
		[Parameter(Mandatory=$true)][guid]$Guid,
		[Parameter(Mandatory=$true)][string]$Domain,
		[string]$Server
	)

	$links = @()
	try {
		$reportParams = @{ Guid = $Guid; ReportType = "Xml"; Domain = $Domain; ErrorAction = "Stop" }
		if ($Server) { $reportParams["Server"] = $Server }

		[xml]$report = Get-GPOReport @reportParams

		# A GPO's <LinksTo> nodes each describe one container the policy is linked to. SOMPath is the
		# linked container (e.g. "contoso.com/Sales/Workstations"), Enabled reflects whether the link is
		# active, and NoOverride indicates the link is enforced.
		foreach ($link in $report.GPO.LinksTo) {
			if (-not $link.SOMPath) { continue }
			$state = $(if ($link.Enabled -eq "true") { "Enabled" } else { "Disabled" })
			if ($link.NoOverride -eq "true") { $state += ", Enforced" }
			$links += "$($link.SOMPath) [$state]"
		}
	} catch {
		Write-Log "Failed to retrieve GPO link information for GPO $Guid in $Domain. The specific error is: $_" -Level WARNING
		return @("Unknown (link query failed)")
	}

	return $links
}

function Get-BasicInfo {

	if (Get-Variable CredSplat) {
		Write-Log "CredSplat is set to: $($CredSplat.Keys)"
	}

	# Get primary domain for discovery
	if (-not $global:Variables["SourceDomain"]) {
		Write-Log "No domain specified in settings file (SourceDomain variable), attempting to determine domain from environment." -Level "WARNING"
		try {
			$global:Variables["SourceDomain"] = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
			Write-Log "Domain determined to be $($global:Variables["SourceDomain"]) from environment." -Level "INFO"
		} catch {
			Write-Log "Failed to determine domain from environment. Please specify a domain in the settings file." -Level ERROR -Fatal
		}
	}

	try {
		Write-Log "Enumerating AD forest $($global:Variables["SourceDomain"])..."
		$script:Forest = Get-AdForest # TODO: When run in the script, it complains that the Identity cannot be null; for some reason it's not auto-detecting the domain/forest of the workstation/user, or CredSplat is throwing it off.
	} catch {
		Write-Log "Unable to enumerate forest. The specific error is: $_" -Level ERROR -Fatal
	}

	# Get Preferred Domain Controller for each domain
	$script:PreferredDCs = @{}
	foreach ($domain in $script:Forest.Domains) {
		$script:PreferredDCs.Add($domain, (Get-DC -Domain $domain -ReturnDCNameOnly))
		Write-Log "Setting $($script:PreferredDCs[$domain]) as the preferred (nearest) DC for $domain"
	}

	# Determine whether the executing identity has elevated rights in the domain/forest. This gates remote
	# management features (e.g. WMI/CIM collection from domain controllers) elsewhere in the script.
	Write-Log "Determining whether the current identity has elevated (privileged) rights in the domain/forest..."
	if ($Settings["UseAdminCredentials"] -and $Settings["AdminIsPrivileged"]) { # We could skip this and test it regardless, I guess.
		$global:Variables["RunPrivilegedActions"] = $true
	}
	if (-not $Settings["UseAdminCredentials"]) {
		$global:Variables["RunPrivilegedActions"] = Test-AdminPrivilege
	}

	if ($global:Variables["RunPrivilegedActions"]) {
		Write-Log "The executing identity appears to hold privileged group membership. Remote management features will be enabled."
	} else {
		Write-Log "The executing identity does not appear to hold privileged group membership. Remote management features will be skipped." -Level WARNING
	}
}

function Get-ForestDomainInfo {
	param(
		[Parameter()][string[]]$Reports
	)

	if ($Reports -contains 'All') { $Reports = @("ForestAndDomains","DomainControllers","GPOs","ReplicationHealth","Sites") }

	Write-Title "Forest/Domain Discovery"

	if ($Reports -contains "ForestAndDomains") {
		Write-Log "Gathering forest information..."

		try {
			$AllDomains = $script:Forest.Domains | foreach { Get-AdDomain $_ @CredSplat }
			Write-Log "- Found $($AllDomains.Count) domains in forest $($script:Forest.DnsRoot)."
			Write-Log "- Found $($AllDomains.ReplicaDirectoryServers.Count) domain controllers in forest $($script:Forest.DnsRoot)."
		} catch {
			Write-Log " - Unable to enumerate domains. The specific error is: $_" -Level ERROR
			return
		}

		# Forest Information - Functional Level, Alternative UPN suffixes, AD Sites and replication links, Global Catalogs, AD Recycle Bin, FRS/DFS-R Status
		$script:ForestData = [ordered]@{
			"Root Domain" = $script:Forest.RootDomain;
			"Functional Level" = $script:Forest.ForestMode | Split-CamelCaseString;
			"Child Domains" = $script:Forest.Domains.Count-1;
			"Global Catalog Count" = $script:Forest.GlobalCatalogs.Count;
			"FSMO - Schema Master" = $script:Forest.SchemaMaster;
			"FSMO - Domain Naming Master" = $script:Forest.DomainNamingMaster;
			"AD Site Count" = $script:Forest.Sites.Count;
			"Schema Level" = $SchemaLevel;
			"Alternative UPN Suffixes" = $script:Forest.UPNSuffixes -join ", "
		}

		$script:ForestData | Write-Data -OutputFile "Forest Summary - $global:ScriptExecutionTimestamp.csv"

		# Domain List - Collection of following for each domain: FQDNs, NETBIOS name, Parent Domain, Functional Level, FSMO role holders, number of domain controllers
		$DomainData = @()
		foreach ($domain in $AllDomains) {
			Write-Log "Gathering domain information for $($domain.DNSRoot)..."
			$domainInfo = [ordered]@{
				"Domain DNS Name" = $domain.DNSRoot;
				"Parent Domain" = $domain.ParentDomain;
				"Functional Level" = $domain.DomainMode | Split-CamelCaseString;
				"Domain Controller Count" = $domain.ReplicaDirectoryServers.Count;
				"FSMO - PDC Emulator" = $domain.PDCEmulator;
				"FSMO - RID Master" = $domain.RIDMaster;
				"FSMO - Infrastructure Master" = $domain.InfrastructureMaster;
			}

			try {
				$DefaultPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $domain.PDCEmulator @CredSplat
				$FineGrainedPasswordPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -Server $domain.PDCEmulator @CredSplat

				$domainInfo["Password Policy - Minimum Age"] = $DefaultPasswordPolicy.MinPasswordAge.Days.ToString() + " Day(s)"
				$domainInfo["Password Policy - Maximum Age"] = $DefaultPasswordPolicy.MaxPasswordAge.Days.ToString() + " Day(s)"
				$domainInfo["Password Policy - Minimum Length"] = $DefaultPasswordPolicy.MinPasswordLength
				$domainInfo["Password Policy - Complexity Required"] =$DefaultPasswordPolicy.ComplexityEnabled
				$domainInfo["Password Policy - Fine Grained Policies Present"] = $($null -ne $FineGrainedPasswordPolicies)
			} catch {
				Write-Log "- Failed to retrieve password policy for $($domain.DNSRoot). The specific error is: $_" -Level ERROR
			}

			$DomainData += ,$domainInfo
		}

		$DomainData | Write-Data -OutputFile "Domain Summary - $global:ScriptExecutionTimestamp.csv"

		Write-Log "Enumerating Organizational Units (OUs)..."
		foreach ($domain in $AllDomains) {
			$OUs = Get-ADOrganizationalUnit -Filter * -Properties CanonicalName,Description -Server $script:PreferredDCs[$domain.DNSRoot] @CredSplat
			
			$OUs | Select CanonicalName,Name,Description | Write-Data -OutputFile "OUs - $($domain.DNSroot) - $global:ScriptExecutionTimestamp.csv"
		}

		# Trust Information - per-domain, source/target, directionality, type, whether target domain is active, creation, and modification
		Write-Log "Gathering AD trust information..."
		$DomainTrusts = @{}
		foreach ($domain in $AllDomains) {
			try {
				$trusts = Get-ADTrust -Filter * -Server $script:PreferredDCs[$domain.DNSRoot] @CredSplat -Properties Created, Modified, ForestTransitive -ErrorAction Stop | Select-Object *, TargetDomainUnreachable
				foreach ($trust in $trusts) {
					if ($trust.Target -notin $AllDomains.DNSRoot) {
						try {
							$target = Get-ADDomain $trust.Target @CredSplat -ErrorAction Stop
							$trust.TargetDomainUnreachable = $false
						} catch {
							$trust.TargetDomainUnreachable = $true
						}
					}
				}
				$DomainTrusts.Add($domain, $trusts)
			} catch {
				Write-Log "Failed to enumerate trusts in domain $domain. The specific error is: $_" -Level ERROR
			}
		}
		Write-Log "- Found $($DomainTrusts.Count) trusts across the forest"

		$TrustData = @()
		foreach ($domain in $DomainTrusts.Keys) {
			foreach ($trust in $DomainTrusts[$domain]) {
				if (-not $trust.IntraForest) {
					$TrustData += ,[ordered]@{
						"Source Domain" = $trust.Source -replace 'DC=','' -replace ',','.';
						"Target Domain" = $trust.Target;
						"Direction" = $trust.Direction;
						"Trust Type" = $trust.TrustType;
						"Transitive" = $trust.ForestTransitive;
						"Created" = $trust.Created;
						"Modified" = $trust.Modified;
					}
				}
			}
		}
		if (-not $TrustData.Count) {
			$TrustData += @{
				"Trust Discovery" = "No extra-forest (non-implicit) trusts detected";
			}
		}
		$TrustData | Write-Data -OutputFile "Trust Summary - $global:ScriptExecutionTimestamp.csv"

		# Schema Information - Whether any custom schema attributes exist (Compare against baselineschema.csv as a list of standard attributes to ignore)
		Write-Log "Analyzing schema..."
		try {
			$SchemaPartition = $script:Forest.PartitionsContainer.Replace("CN=Partitions","CN=Schema")
			$SchemaObjectVersion = (Get-ADObject -Server $script:Forest.RootDomain -Identity $SchemaPartition @CredSplat -Properties objectVersion).objectVersion
		} catch {
			Write-Log "Failed to retrieve schema information from $($script:Forest.RootDomain). The specific error is: $_" -Level ERROR
		}

		$SchemaLevels = @{
			13 = "Windows 2000 Server";
			30 = "Windows Server 2003";
			31 = "Windows Server 2003 R2";
			44 = "Windows Server 2008";
			47 = "Windows Server 2008 R2";
			51 = "Windows Server 8 Developers Preview";
			52 = "Windows Server 8 Beta";
			56 = "Windows Server 2012";
			69 = "Windows Server 2012 R2";
			87 = "Windows Server 2016";
			88 = "Windows Server 2019/2022";
		}
		$SchemaLevel = $(if ($SchemaLevels[$SchemaObjectVersion]) { $SchemaLevels[$SchemaObjectVersion]} else { "Unknown version: $SchemaObjectVersion" })

		Write-Log "- Comparing schema to baseline attributes"
		try {
			$SchemaAttributes = Get-ADObject -SearchBase (Get-ADRootDSE -Server $script:Forest.RootDomain).schemaNamingContext -LDAPFilter "(objectClass=attributeSchema)" -Properties Name,lDAPDisplayName,Created,Modified,attributeID,attributeSyntax @CredSplat -Server $script:Forest.RootDomain
			Write-Log "- - Read $($SchemaAttributes.Count) attributes from the forest schema"

			if (Test-Path .\baselineschema.csv) {
				$BaselineAttributes = Import-Csv .\baselineschema.csv
				Write-Log "- - Read $($BaselineAttributes.Count) records from baselineattributes.csv"
				$SchemaAttributes = $SchemaAttributes | where {$_.attributeID -notin $BaselineAttributes.attributeID}
				Write-Log "Removed baseline attributes from forest schema list, leaving $($SchemaAttributes.Count) attributes"
			}
		} catch {
			Write-Log "- Failed to enumerate schema attributes in $($script:Forest.RootDomain). The specific error is: $_" -Level ERROR
		}

		# Filter additional known attributes
		$SchemaAttributes = $SchemaAttributes | where {$_.name -notlike "msExch*" -and $_.name -notlike "ms*"}

		if ($SchemaAttributes.Count) {
			$SchemaData = $SchemaAttributes | Select Name,Created,Modified,@{n="Attribute ID"; e={$_.attributeID}}
		} else {
			$SchemaData = @{"Schema Discovery" = "No custom schema attributes detected"}
		}
		$SchemaData | Write-Data -OutputFile "Schema Summary - $global:ScriptExecutionTimestamp.csv"
	}

	if ($Reports -contains "DomainControllers") {
		Write-Log "Analyzing domain controllers..."
		$DCs = Get-AllDcs -ForestWide -DirectReturn -UseCachedData
		
		# Domain Controllers - include CPU, RAM, Storage, Uptime, OS, Patch Level, NIC-level DNS configuration, DNS Server conditional forwarding and zones
		$DCData = @()
		foreach ($dc in $DCs) {
			$dcInfo = [ordered]@{
				"Domain" = $dc.Domain;
				"Host Name" = $dc.HostName;
				"Operating System" = $dc.OperatingSystem;
				"IPv4 Address" = $dc.IPv4Address;
				"AD Site" = $dc.Site;
				"Global Catalog" = $dc.IsGlobalCatalog;
				"RODC" = $dc.IsReadOnly;
			}

			if ($Settings["AdminIsPrivileged"]) {
				Write-Log "- Collecting remote system information from $($dc.HostName)..." -Level VERBOSE
				$remoteInfo = Get-RemoteSystemInfo -ComputerName $dc.HostName
				foreach ($key in $remoteInfo.Keys) {
					$dcInfo[$key] = $remoteInfo[$key]
				}
			}

			$DCData += ,$dcInfo
		}

		$DCData | Write-Data -OutputFile "Domain Controllers - $global:ScriptExecutionTimestamp.csv"
	}

	if ($Reports -contains "GPOs") {
		Write-Log "Enumerating Group Policy Objects..."

		if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
			Write-Log "The GroupPolicy module is not available on this system. Skipping GPO discovery. Install the RSAT Group Policy Management Tools to enable it." -Level WARNING
		} else {
			Import-Module GroupPolicy -ErrorAction SilentlyContinue

			foreach ($domain in $script:Forest.Domains) {
				# Note: Get-GPO does not support -Credential; it runs in the current security context.
				try {
					$GPOs = Get-GPO -All -Domain $domain -Server $script:PreferredDCs[$domain] -ErrorAction Stop
					Write-Log "- Detected $($GPOs.Count) GPOs in $domain."
				} catch {
					Write-Log "- Failed to enumerate GPOs in $domain. The specific error is: $_" -Level ERROR
					continue
				}

				$GPOData = foreach ($gpo in $GPOs) {
					$links = @(Get-GPOLinks -Guid $gpo.Id -Domain $domain -Server $script:PreferredDCs[$domain])

					[ordered]@{
						"Domain" = $domain;
						"Display Name" = $gpo.DisplayName;
						"GPO Status" = $gpo.GpoStatus;
						"Created" = $gpo.CreationTime;
						"Modified" = $gpo.ModificationTime;
						"Computer Version" = $gpo.Computer.DSVersion;
						"User Version" = $gpo.User.DSVersion;
						"Owner" = $gpo.Owner;
						"GUID" = $gpo.Id;
						"Link Count" = $links.Count;
						"Linked To" = $(if ($links.Count) { $links -join "; " } else { "(unlinked)" });
						"WMI Filter" = $gpo.WmiFilter;
					}
				}

				$GPOData | Write-Data -OutputFile "Group Policy Objects - $domain - $global:ScriptExecutionTimestamp.csv"
			}
		}
	}

	if ($Reports -contains "ReplicationHealth") {
		Write-Log "Analyzing Active Directory replication health..."

		$DCs = Get-AllDcs -ForestWide -DirectReturn -UseCachedData

		$ReplData = @()
		foreach ($dc in $DCs) {
			$dcName = $dc.HostName
			
			Write-Log "- Processing $dcName"

			$dcInfo = [ordered]@{
				"Domain" = $dc.Domain;
				"Domain Controller" = $dcName;
				"Site" = $dc.Site;
				"Global Catalog" = $dc.IsGlobalCatalog;
			}

			$dcReachable = (Test-Connection -ComputerName $dc -count 3 -Quiet)
			if (-not $dcReachable) {
				Write-Log "- - Unable to connect to $dcName" -Level WARNING
				$dcInfo["Status"] = "Unreachable"
				$ReplData += ,$dcInfo
				continue
			}

			Write-Log "- - Running DCDiag tests"

			$dcDiagTests = @("Advertising","FrsEvent","MachineAccount","ObjectReplicated","VerifyReferences")
			if ($Settings["RunPrivilegedActions"]) {
				$dcDiagTests += @("NetLogons","DFSREvent","SysVolCheck","KccEvent","SystemLog")
			}
			
			foreach ($test in $dcDiagTests) {
				$dcdiagResult = dcdiag /test:$test /s:$dcName
				if ($dcdiagResult -match "passed test $test") {
					$dcInfo["DCDIAG - $test"] = "OK"
				}
				else {
					$dcInfo["DCDIAG - $test"] = (($dcdiagResult | Select-String "error", "warning" | foreach { $_.Line.Trim() }) -join "`n")
				}
			}

			try {
				Write-Log "- - Reading replication info from $dcName"
				$failures = Get-ADReplicationFailure -Target $dcName @CredSplat -ErrorAction Stop
				$partnerData = Get-ADReplicationPartnerMetadata -Target $dcName -Partition * @CredSplat -ErrorAction Stop
				$lastSuccess = ($partnerData | Sort-Object LastReplicationSuccess -Descending | Select-Object -First 1).LastReplicationSuccess
				$dcInfo["Replication Failures"] = @($failures).Count;
				$dcInfo["Replication Failure Types"] = $failures.FailureType -join "; ";
				$dcInfo["Last Replication Success"] = $lastSuccess;
			} catch {
				Write-Log "- - Failed to retrieve replication data from $dcName. The specific error is: $_" -Level ERROR
				$dcInfo["Status"] = "Error";
				$dcInfo["Replication Failures"] = "Unknown";
				$dcInfo["Last Replication Success"] = "Unknown";
			}

			$dcInfo["Status"] = "Reachable";

			$ReplData += ,$dcInfo
		}
		$ReplData | Write-Data -OutputFile "Replication Health - $global:ScriptExecutionTimestamp.csv"
		Write-Log "- Analyzed replication for $(@($DCs).Count) domain controllers"

		Write-Log "Checking for conflict objects..."
		if (-not $AllDomains.Count) {
			$AllDomains = $script:Forest.Domains | foreach { Get-AdDomain $_ @CredSplat }
		}
		foreach ($domain in $AllDomains) {
			try {
				$ConflictObjects = Get-ADObject -LDAPFilter "(cn=*\0ACNF:*)" -SearchBase $domain.DistinguishedName -SearchScope SubTree -Server $script:PreferredDCs[$domain.DNSRoot] @CredSplat

				if ($ConflictObjects.Count) {
					Write-Log "- Detected $($ConflictObjects.Count) conflict objects in $($domain.DNSRoot)"
					$ConflictObjects | Write-Data -OutputFile "Conflict Objects - $($domain.DNSRoot) - $global:ScriptExecutionTimestamp.csv"
				} else {
					Write-Log "- No conflict objects detected in $($domain.DNSRoot)"
				}
			} catch {
				Write-Log "- Failed to query for lingering/conflict objects in $($domain.DNSRoot). The specific error is: $_" -Level ERROR
			}
		}

		Write-Log "Checking for orphaned objects..."
		if (-not $AllDomains.Count) {
			$AllDomains = $script:Forest.Domains | foreach { Get-AdDomain $_ @CredSplat }
		}
		foreach ($domain in $AllDomains) {
			try {
				$OrphanedObjects = Get-ADObject -Filter * -SearchBase "cn=LostAndFound,$($domain.DistinguishedName)" -SearchScope OneLevel -Server $script:PreferredDCs[$domain.DNSRoot] @CredSplat

				if ($OrphanedObjects.Count) {
					Write-Log "- Detected $($OrphanedObjects.Count) conflict objects in $($domain.DNSRoot)"
					$OrphanedObjects | Write-Data -OutputFile "Orphaned Objects - $($domain.DNSRoot) - $global:ScriptExecutionTimestamp.csv"
				} else {
					Write-Log "- No orphan objects detected in $($domain.DNSRoot)"
				}
			} catch {
				Write-Log "- Failed to query for lingering/conflict objects in $($domain.DNSRoot). The specific error is: $_" -Level ERROR
			}
		}

	}

	if ($Reports -contains "Sites") {
		Write-Log "Enumerating AD sites and replication topology..."

		# Build a site -> subnet lookup so each site can list the subnets associated with it.
		try {
			$subnets = Get-ADReplicationSubnet -Filter * -Properties Location -Server $script:PreferredDCs[$script:Forest.RootDomain] @CredSplat -ErrorAction Stop
		} catch {
			Write-Log "Failed to enumerate AD subnets. The specific error is: $_" -Level ERROR
			$subnets = @()
		}

		$subnetsBySite = @{}
		foreach ($subnet in $subnets) {
			$siteName = $(if ($subnet.Site) { ($subnet.Site -split ",")[0] -replace "^CN=","" } else { "<Unassigned>" })
			if (-not $subnetsBySite.ContainsKey($siteName)) { $subnetsBySite[$siteName] = @() }
			$subnetsBySite[$siteName] += $subnet.Name
		}

		# AD Sites
		try {
			$sites = Get-ADReplicationSite -Filter * -Properties Description,whenCreated,whenChanged -Server $script:PreferredDCs[$script:Forest.RootDomain] @CredSplat -ErrorAction Stop
		} catch {
			Write-Log "Failed to enumerate AD sites. The specific error is: $_" -Level ERROR
			$sites = @()
		}

		$SiteData = foreach ($site in $sites) {
			$siteSubnets = $subnetsBySite[$site.Name]
			[ordered]@{
				"Site Name"    = $site.Name;
				"Description"  = $site.Description;
				"Subnet Count" = @($siteSubnets).Count;
				"Subnets"      = $(if ($siteSubnets) { $siteSubnets -join "; " } else { "(none)" });
				"Created"      = $site.whenCreated;
				"Modified"     = $site.whenChanged;
			}
		}

		$SiteData | Write-Data -OutputFile "AD Sites - $global:ScriptExecutionTimestamp.csv"
		Write-Log "- Found $(@($sites).Count) AD sites and $($subnets.Count) subnets"

		# Replication site links
		try {
			$siteLinks = Get-ADReplicationSiteLink -Filter * -Properties Description,Options -Server $script:PreferredDCs[$script:Forest.RootDomain] @CredSplat -ErrorAction Stop
		} catch {
			Write-Log "Failed to enumerate AD replication site links. The specific error is: $_" -Level ERROR
			$siteLinks = @()
		}

		$LinkData = foreach ($link in $siteLinks) {
			# SitesIncluded holds the DNs of the sites this link connects; reduce each to its site name.
			$memberSites = foreach ($dn in $link.SitesIncluded) { ($dn -split ",")[0] -replace "^CN=","" }
			# The 0x1 bit of Options enables change notification (near-real-time intersite replication).
			$changeNotification = [bool]($link.Options -band 1)

			[ordered]@{
				"Site Link Name"             = $link.Name;
				"Description"                = $link.Description;
				"Cost"                       = $link.Cost;
				"Replication Interval (Min)" = $link.ReplicationFrequencyInMinutes;
				"Transport"                  = $link.InterSiteTransportProtocol;
				"Change Notification"        = $changeNotification;
				"Member Site Count"          = @($memberSites).Count;
				"Linked Sites"               = $memberSites -join "; ";
			}
		}

		$LinkData | Write-Data -OutputFile "AD Replication Site Links - $global:ScriptExecutionTimestamp.csv"
		Write-Log "- Found $(@($siteLinks).Count) replication site links"
	}

	Start-ConfirmationTimer -Message "Forest/Domain discovery complete"
}

function Get-UserGroupInfo {
	param(
		[Parameter()][string[]]$Reports
	)

	Write-Title "User/Group Discovery"

	if ($Reports -contains 'All') { $Reports = @("Users","Groups","GroupMemberships","NestedGroups") }

	if ($Reports -contains "Users") {
		$UserAttributes = @(
			"Name",
			"DisplayName",
			"sAMAccountName",
			"UserPrincipalName",
			"EmailAddress",
			"Created",
			"Modified",
			"LastLogonDate",
			"Enabled",
			"CanonicalName",
			"AccountExpirationDate",
			"PasswordExpired",
			"PasswordLastSet",
			"LockedOut",
			"AdminCount",
			"EmployeeID",
			"EmployeeNumber",
			"EmployeeType",
			"Manager"
		)

		if ($Variables["AdditionalUserAttributes"]) {
			$UserAttributes += $Variables["AdditionalUserAttributes"]
		}

		foreach ($domain in $script:Forest.Domains) {
			Write-Log "Enumerating AD user objects in $domain..."
			try {
				$Users = Get-ADUser -Filter * -Properties $UserAttributes -Server $script:PreferredDCs[$domain] @CredSplat -ErrorAction Stop | Select-Object @{n="Domain";e={$domain}},*
			} catch {
				Write-Log "Failed to enumerate user objects in $domain. The specific error is: $_" -Level ERROR
				continue
			}

			$Users | Write-Data -OutputFile "User Accounts - $domain - $global:ScriptExecutionTimestamp.csv"

			$UserSummary = [PSCustomObject]@{
				"Domain Name" = $domain
				"Total User Count" = @($Users).Count
				"Privileged Accounts (AdminCount)" = @($Users | Where-Object {$_.AdminCount}).Count
				"Disabled Accounts" = @($Users | Where-Object {-not $_.Enabled}).Count
				"Password Expired" = @($Users | Where-Object { $_.PasswordExpired -eq $true }).Count
				"Expired Account" = @($Users | Where-Object { $null -ne $_.AccountExpirationDate -and $_.AccountExpirationDate -lt (Get-Date)}).Count
 		}
			Write-Log $UserSummary -Silent
			$UserSummary | Out-Host
		}
	}

	if ($Reports -contains "Groups") {
		foreach ($domain in $script:Forest.Domains) {
			Write-Log "Enumerating AD group objects in $domain..."
			try {
				$Groups = Get-ADGroup -Filter * -Properties Description,ManagedBy,Created,Modified,AdminCount,member -Server $script:PreferredDCs[$domain] @CredSplat -ErrorAction Stop |
					Select-Object @{n="Domain";e={$domain}},Name,sAMAccountName,GroupCategory,GroupScope,Description,ManagedBy,Created,Modified,AdminCount,@{n="Member Count";e={@($_.member).Count}}
			} catch {
				Write-Log "Failed to enumerate group objects in $domain. The specific error is: $_" -Level ERROR
				continue
			}

			$Groups | Write-Data -OutputFile "Groups - $domain - $global:ScriptExecutionTimestamp.csv"
			Write-Log "- Found $($Groups.Count) groups in $domain"
		}
	}

	if ($Reports -contains "GroupMemberships") {
		foreach ($domain in $script:Forest.Domains) {
			Write-Log "Enumerating AD group memberships in $domain..."

			try {
				$Groups = Get-ADGroup -Filter * -Properties Name -Server $script:PreferredDCs[$domain] @CredSplat -ErrorAction Stop
				Write-Log "- Enumerated $(@($Groups).Count) groups in $domain."
			} catch {
				Write-Log "- Failed to enumerate groups in $domain. The specific error is: $_" -Level ERROR
				continue
			}

			$membershipMapping = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new()

			foreach ($group in $Groups) {
				$escapedGroupDN = $group.DistinguishedName -replace '(?=[()\\\*])', '\'

				$ldapFilter = "(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$escapedGroupDN))"

				try {
					$members = Get-ADUser -LDAPFilter $ldapFilter -Server $script:PreferredDCs[$domain]

					foreach ($member in $members) {
						$userDN = $member.DistinguishedName

						if (-not $membershipMapping.ContainsKey($userDN)) {
							$membershipMapping[$userDN] = [System.Collections.Generic.List[string]]::new()
						}

						$membershipMapping[$userDN].Add($group.Name)
					}
				} catch {
					Write-Log "- Failed to enumerate group membership for $($group.Name). The specific error is: $_" -Level ERROR
				}
			}

			$MembershipData = [System.Collections.Generic.List[PSCustomObject]]::new()

			foreach  ($mapping in $membershipMapping.GetEnumerator()) {
				$userSamAccountName = ($mapping.Key -split ',*..=')[1]

				foreach ($group in $mapping.Value) {
					$MembershipData.Add([PSCustomObject]@{
						"User SAMAccountName" =$userSamAccountName;
						"Group" = $group;
					})
				}
			}

			$MembershipData | Write-Data -OutputFile "Group Membership By User - $domain - $global:ScriptExecutionTimestamp.csv"

		}
	}

	if ($Reports -contains "NestedGroups") {
		Write-Log "Enumerating Nested Groups"

		foreach ($domain in $script:Forest.Domains) {
			$nestedGroups = Get-ADGroup -Filter {$MemberOf -like "*"} -Properties MemberOf @CredSplat -Server $script:PreferredDCs[$domain]
			Write-Log "Found $(@($nestedGroups).Count) nested groups in $domain"

			$nestedGroups | Select Name,DistinguishedName, GroupScope, GroupCategory, @{n="Member Of";e={$_.MemberOf -join "; "}} | Write-Data -Outputfile "Nested Groups - $domain - $global:ScriptExecutionTimestamp.csv"
		}
	}

	Start-ConfirmationTimer -Message "User/Group discovery complete"
}

function Get-ComputerServerInfo {
	param(
		[Parameter()][string[]]$Reports
	)

	Write-Title "Computer / Server Discovery"

	if ($Reports -contains 'All') { $Reports = @("Computers","Servers") }

	$computerAttributes = @(
		"Name","DNSHostName","CanonicalName","Created","Modified","Description","Enabled",
		"LastLogonDate","OperatingSystem","OperatingSystemVersion","IPv4Address","PasswordLastSet"
	)

	if ($Variables["AdditionalComputerAttributes"]) {
		$computerAttributes += $Variables["AdditionalComputerAttributes"]
	}

	foreach ($domain in $script:Forest.Domains) {
		Write-Log "Enumerating AD computer objects in $domain..."
		try {
			$Computers = Get-ADComputer -Filter * -Properties $computerAttributes -Server $script:PreferredDCs[$domain] @CredSplat -ErrorAction Stop |
				Select-Object @{n="Domain";e={$domain}},*
		} catch {
			Write-Log "Failed to enumerate computer objects in $domain. The specific error is: $_" -Level ERROR
			continue
		}

		# Partition the results: a "Server" runs a server OS; everything else is treated as a workstation/client.
		$Servers = $Computers | Where-Object { $_.OperatingSystem -like "*Server*" }
		$Workstations = $Computers | Where-Object { $_.OperatingSystem -notlike "*Server*" }

		if ($Reports -contains "Servers") {
			if ($Servers) {
				$Servers | Write-Data -OutputFile "Servers - $domain - $global:ScriptExecutionTimestamp.csv"
			}
			Write-Log "- Found $(@($Servers).Count) server objects in $domain"
		}

		if ($Reports -contains "Computers") {
			if ($Workstations) {
				$Workstations | Write-Data -OutputFile "Computers - $domain - $global:ScriptExecutionTimestamp.csv"
			}
			Write-Log "- Found $(@($Workstations).Count) workstation/client objects in $domain"
		}
	}

	Start-ConfirmationTimer -Message "Computer/Server discovery complete"
}

function Get-AllInfo {
	# Convenience wrapper for the "Run All Reports" main-menu option: runs every report in every category.
	Get-ForestDomainInfo -Reports All
	Get-UserGroupInfo -Reports All
	Get-ComputerServerInfo -Reports All
}

# ============ MAIN PROGRAM ==============

Get-BasicInfo

New-Menu $MainMenu