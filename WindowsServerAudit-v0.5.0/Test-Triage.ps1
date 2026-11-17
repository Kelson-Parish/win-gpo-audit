#Requires -Version 5.1
<# Dependency-free fixture tests. Parses the audit and imports function definitions
only. Does not invoke the audit entry point, query SQL Server or change settings. #>
[CmdletBinding()]
param([string]$ScriptPath=(Join-Path $PSScriptRoot 'Invoke-WindowsServerAudit.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){$parseErrors | Format-List | Out-Host;throw 'PowerShell syntax validation failed.'}
$definitions=@{}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
    $definitions[$definition.Name]=$definition.Extent.Text
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:Passed=0
function Assert-True {param([bool]$Value,[string]$Message='Assertion failed') if(-not $Value){throw $Message}}
function Assert-Throws {param([scriptblock]$Action) $threw=$false;try{& $Action | Out-Null}catch{$threw=$true};Assert-True $threw 'Expected exception.'}
function Test-Case {param([string]$Name,[scriptblock]$Action) & $Action;$script:Passed++;Write-Host ('PASS '+$Name)}
function New-FixtureIntent {
    [pscustomobject]@{Schema='WindowsServerAudit.Intent';Version=2;Computer='TEST';DomainController=$false;Roles=[pscustomobject]@{Known=$true;Complete=$false;Values=@()};Inbound=[pscustomobject]@{Mode='Defaults';Ports=@()};Outbound=[pscustomobject]@{Mode='Defaults';Ports=@()};BaselinePath=''}
}
function New-FixtureData {
    $intent=New-FixtureIntent
    $services=@(Get-ServiceReference $intent @() | ForEach-Object {[pscustomobject]@{Name=$_.Name;DisplayName=$_.DisplayName;State=$_.States[0];StartMode=$_.StartModes[0];StartName=$_.Account}})
    [pscustomobject]@{Discovery=[pscustomobject]@{Role='Member Server'};Services=$services;Admins=@();Firewall=[pscustomobject]@{Networks=@([pscustomobject]@{NetworkCategory='DomainAuthenticated'});Profiles=@(Get-FirewallReference | ForEach-Object {[pscustomobject]@{Name=$_.Profile;Enabled=$_.Enabled;DefaultInboundAction=$_.DefaultInboundAction;DefaultOutboundAction=$_.DefaultOutboundAction;AllowInboundRules=$_.AllowInboundRules;AllowLocalFirewallRules=$_.AllowLocalFirewallRules}});Rules=@()};Live=[pscustomobject]@{Tcp=@();Udp=@();Processes=@()};Artifacts=@();Defender=@();Sql=[pscustomobject]@{Records=@()}}
}
$directory=Join-Path ([IO.Path]::GetTempPath()) ('TriageFixtures-'+[guid]::NewGuid())
$null=New-Item -ItemType Directory -Path $directory
try {
    $script:Coverage=New-Object 'System.Collections.Generic.List[object]';$script:Files=@{}
    foreach($collection in @('Services','TCP/Final','UDP/Final')){Add-Coverage $collection 'Collected' 'fixture' $true}
    Test-Case 'New profile is valid; old schema is rejected' {$i=New-FixtureIntent;Assert-True (Test-IntentProfile $i);$i.Version=1;Assert-Throws {Test-IntentProfile $i}}
    Test-Case 'Port ranges reject invalid values' {foreach($bad in @('0','65536','200-100','1.5','Any')){Assert-True (-not (Test-ValidPortRange $bad))};Assert-True (Test-ValidPortRange '49152-65535')}
    Test-Case 'Simple port input preserves defaults, none and unknown' {
        $script:Answers=New-Object 'System.Collections.Generic.Queue[string]'
        foreach($text in @('','none','unknown','TCP:443,UDP:53,TCP:5000-5010')){$script:Answers.Enqueue($text)}
        function script:Ask-Text {param($Prompt) $script:Answers.Dequeue()}
        Assert-True ((Read-SimplePorts 'test').Mode -eq 'Defaults')
        Assert-True ((Read-SimplePorts 'test').Mode -eq 'None')
        Assert-True ((Read-SimplePorts 'test').Mode -eq 'Unknown')
        Assert-True ((Read-SimplePorts 'test').Ports.Count -eq 3)
    }
    Test-Case 'Quick wizard requires no per-service answers' {
        $discovery=[pscustomobject]@{Computer='TEST';Caption='Fixture';Role='Member Server';Services=@()}
        foreach($text in @('n','none','','')){$script:Answers.Enqueue($text)}
        $intent=New-IntentWizard $discovery
        Assert-True ($intent.DomainController -eq $false -and $intent.Roles.Complete -and $intent.Inbound.Mode -eq 'Defaults')
        Assert-True ($script:Answers.Count -eq 0)
    }
    Test-Case 'Windows firewall defaults generate no abnormal findings' {
        $f=@(Get-RequirementFindings (New-FixtureIntent) (New-FixtureData))
        Assert-True ($f.Count -eq 0)
    }
    Test-Case 'Not configured is unknown, not an unsafe firewall default' {
        $d=New-FixtureData;$d.Firewall.Profiles[0].DefaultInboundAction='NotConfigured';$d.Firewall.Profiles[0].AllowLocalFirewallRules='NotConfigured'
        Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
        $comparison=@(Get-FirewallComparison $d.Firewall | Where-Object {$_.Profile -eq 'Domain' -and $_.Setting -eq 'DefaultInboundAction'})
        Assert-True ($comparison[0].Comparison -like 'Unknown*')
    }
    Test-Case 'Managed local-rule policy is information, not an abnormality' {
        $d=New-FixtureData;$d.Firewall.Profiles[0].AllowLocalFirewallRules='False'
        $f=@(Get-RequirementFindings (New-FixtureIntent) $d)
        Assert-True ($f.Count -eq 1 -and $f[0].Kind -eq 'Information')
    }
    Test-Case 'Disabled firewall and inbound allow defaults remain review findings' {
        $d=New-FixtureData;$d.Firewall.Profiles[0].Enabled='False';$d.Firewall.Profiles[0].DefaultInboundAction='Allow'
        $f=@(Get-RequirementFindings (New-FixtureIntent) $d)
        Assert-True ($f.Count -eq 2 -and @($f | Where-Object Priority -ne 'High').Count -eq 0)
    }
    Test-Case 'Active website role accepts manual process activation startup' {
        $i=New-FixtureIntent;$i.Roles.Values=@('Web');$d=New-FixtureData
        $d.Services+=@([pscustomobject]@{Name='W3SVC';DisplayName='World Wide Web Publishing Service';State='Running';StartMode='Auto';StartName='LocalSystem'},[pscustomobject]@{Name='WAS';DisplayName='Windows Process Activation Service';State='Running';StartMode='Manual';StartName='LocalSystem'})
        Assert-True (@(Get-RequirementFindings $i $d).Count -eq 0)
        $d.Services[-1].StartName='TEST\unexpected';Assert-True (@(Get-RequirementFindings $i $d | Where-Object Identity -eq 'Service:WAS').Count -eq 1)
    }
    Test-Case 'Domain-controller assumptions include directory services' {
        $i=New-FixtureIntent;$i.DomainController=$true;$names=@(Get-ServiceReference $i @() | ForEach-Object Name)
        Assert-True ($names -contains 'NTDS' -and $names -contains 'Kdc' -and $names -contains 'ADWS')
        $i.DomainController=$false;Assert-True (@(Get-ServiceReference $i @() | Where-Object Name -eq 'NTDS').Count -eq 0)
    }
    Test-Case 'Unknown services are not assumed to need disabling' {
        $d=New-FixtureData;$d.Services+=@([pscustomobject]@{Name='BusinessApp';State='Running';StartMode='Auto';StartName='TEST\svc'})
        Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
    }
    Test-Case 'Custom database accounts and stopped job agents are not false positives' {
        $i=New-FixtureIntent;$i.Roles.Values=@('Database');$d=New-FixtureData
        $d.Services+=@([pscustomobject]@{Name='MSSQL$NAMED';State='Running';StartMode='Auto';StartName='TEST\custom$'},[pscustomobject]@{Name='SQLAgent$NAMED';State='Stopped';StartMode='Manual';StartName='TEST\agent$'})
        Assert-True (@(Get-RequirementFindings $i $d).Count -eq 0)
    }
    Test-Case 'Unexpected listening port is reviewed; loopback is skipped' {
        $d=New-FixtureData;$d.Live.Tcp=@([pscustomobject]@{State='Listen';LocalAddress='0.0.0.0';LocalPort=4444;OwningProcess=99})
        Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d | Where-Object Identity -like 'Listener:*').Count -eq 1)
        $d.Live.Tcp[0].LocalAddress='127.2.3.4';Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
    }
    Test-Case 'Dynamic datagram sockets are informational rather than assumed servers' {
        $d=New-FixtureData;$d.Live.Udp=@([pscustomobject]@{LocalAddress='0.0.0.0';LocalPort=55001;OwningProcess=77})
        $f=@(Get-RequirementFindings (New-FixtureIntent) $d)
        Assert-True ($f.Count -eq 1 -and $f[0].Kind -eq 'Information')
    }
    Test-Case 'Outbound compares remote destination rather than temporary source' {
        $i=New-FixtureIntent;$i.Outbound=[pscustomobject]@{Mode='Custom';Ports=@([pscustomobject]@{Protocol='TCP';Specification='443'})}
        $d=New-FixtureData;$d.Live.Tcp=@([pscustomobject]@{State='Established';LocalAddress='10.0.0.1';LocalPort=55001;RemoteAddress='198.51.100.10';RemotePort=443;OwningProcess=50})
        Assert-True (@(Get-RequirementFindings $i $d | Where-Object Identity -like 'Connection:*').Count -eq 0)
        $d.Live.Tcp[0].RemotePort=4444;Assert-True (@(Get-RequirementFindings $i $d | Where-Object Identity -like 'Connection:*').Count -eq 1)
    }
    Test-Case 'Accepted inbound connection is not called outbound' {
        $i=New-FixtureIntent;$i.Outbound.Mode='None';$d=New-FixtureData
        $d.Live.Tcp=@([pscustomobject]@{State='Listen';LocalAddress='0.0.0.0';LocalPort=443;OwningProcess=50},[pscustomobject]@{State='Established';LocalAddress='10.0.0.1';LocalPort=443;RemoteAddress='198.51.100.10';RemotePort=55001;OwningProcess=50})
        Assert-True (@(Get-RequirementFindings $i $d | Where-Object Identity -like 'Connection:*').Count -eq 0)
    }
    Test-Case 'Common labels expand abbreviations' {Assert-True ((Expand-AuditText 'ADWS TCP ACL') -eq 'ADWS (Active Directory Web Services) TCP (Transmission Control Protocol) ACL (Access Control List)')}
    Test-Case 'Broad permission checks preserve deny and inheritance uncertainty' {
        $allow=[pscustomobject]@{Sid='S-1-1-0';Type='Allow';Mask=2;Inherited=$true;InheritOnly=$false;Conditional=$false}
        Assert-True (@(Get-BroadAclSignals @($allow) 'File').Count -eq 1)
        $allow.InheritOnly=$true;Assert-True (@(Get-BroadAclSignals @($allow) 'File').Count -eq 0)
        $allow.InheritOnly=$false;$deny=[pscustomobject]@{Sid='S-1-1-0';Type='Deny';Mask=2;Inherited=$false;InheritOnly=$false;Conditional=$false}
        Assert-True ((Get-BroadAclSignals @($allow,$deny) 'File').Weight -eq 10)
    }
    Test-Case 'Baseline removal requires the last successful enumeration' {
        $m=[pscustomobject]@{Year='2022';Role='Member Server';EditionSku=7;Build='20348.1'}
        $a=[pscustomobject]@{Identity='Service:x';Collection='Services';Fields=[pscustomobject]@{Command='C:\x.exe';Account='LocalSystem'}}
        $r=[pscustomobject]@{Schema='WindowsServerAudit.TriageSnapshot';Version=1;Machine=$m;Artifacts=@($a);Files=@();Collections=@()}
        $c=[pscustomobject]@{Machine=$m;Artifacts=@();Files=@();Collections=@([pscustomobject]@{Name='Services';Complete=$true},[pscustomobject]@{Name='Services';Complete=$false})}
        Assert-True (@(Compare-TriageSnapshot $c $r).Count -eq 0)
        $c.Collections=@([pscustomobject]@{Name='Services';Complete=$true});Assert-True (@(Compare-TriageSnapshot $c $r).Count -eq 1)
    }
    Test-Case 'Generated report escapes evidence and includes functional filter hooks' {
        $script:Files=@{};$report=Join-Path $directory 'index.html';$hostile='<script>window.injected=1</script>'
        $f=New-TriageFinding 'Review' 'High' $hostile $hostile '' '' '' ''
        $discovery=[pscustomobject]@{Computer='TEST';Caption='Server';Role='Member Server';Build='fixture'}
        $d=New-FixtureData
        Write-TriageReport -Path $report -Discovery $discovery -Intent (New-FixtureIntent) -Findings @($f) -Assessments @() -Coverage @() -Artifacts @() -Firewall $d.Firewall -Services $d.Services
        $html=Get-Content -LiteralPath $report -Raw
        Assert-True (-not $html.Contains($hostile) -and $html.Contains('&lt;script&gt;'))
        Assert-True ($html.Contains('resetFilters') -and $html.Contains('rows[i].style.display'))
    }
    Write-Host ('Passed '+$script:Passed+' fixture groups. Windows collector integration is not covered.') -ForegroundColor Green
}finally{Remove-Item -LiteralPath $directory -Recurse -Force}
