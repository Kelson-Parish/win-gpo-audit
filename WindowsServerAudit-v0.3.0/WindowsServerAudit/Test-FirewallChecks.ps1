#Requires -Version 5.1
<#
Pure fixture tests. Parse the audit script, load ONLY its two finding functions,
and supply invented objects. Do not run an audit or access/change any firewall.
Run this file in Windows PowerShell to perform the syntax and fixture checks.
#>
[CmdletBinding()]
param([string]$AuditScript=(Join-Path $PSScriptRoot 'Invoke-WindowsServerAudit.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($AuditScript,[ref]$tokens,[ref]$parseErrors)
if(@($parseErrors).Count){throw ($parseErrors | Out-String)}
foreach($functionName in @('New-Finding','Get-FirewallContextFindings')) {
    $definitions=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object {$_.Name -eq $functionName})
    if($definitions.Count -ne 1){throw ('Expected exactly one function '+$functionName)}
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
function Assert-Equal {
    param($Actual,$Expected,[string]$Case)
    if($Actual -cne $Expected){throw ('FAILED '+$Case+': expected ['+$Expected+'], got ['+$Actual+']')}
}
function New-TestProfile {
    param([string]$Name='Domain',[string]$Merge='False')
    [pscustomobject]@{Name=$Name;AllowLocalFirewallRules=$Merge;Enabled='True';DefaultInboundAction='Block';AllowInboundRules='True'}
}
$domainNetwork=[pscustomobject]@{InterfaceAlias='DomainNIC';NetworkCategory='DomainAuthenticated'}
$publicNetwork=[pscustomobject]@{InterfaceAlias='PublicNIC';NetworkCategory='Public'}
$settings=@{EffectiveProfiles=@(New-TestProfile);NetworkProfiles=@($domainNetwork);NetworkProfilesKnown=$true;LocalRules=@([pscustomobject]@{Enabled='True';Profile='Any'});LocalRulesKnown=$true;EffectiveRules=@();EffectiveRulesKnown=$true;RequiredLocalMergeProfiles=@('Domain');DomainJoined=$true}

$findings=@(Get-FirewallContextFindings @settings)
$item=@($findings | Where-Object Id -eq 'Firewall/Domain/RequiredLocalRules')[0]
Assert-Equal $item.Status 'Fail' '1 required local rules rejected'
Assert-Equal $item.Priority 'High' '1 active Domain priority'

$settings.EffectiveProfiles=@(New-TestProfile -Merge 'True')
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Domain/RequiredLocalRules')[0].Status) 'Pass' '2 allowed local merging'

$settings.EffectiveProfiles=@(New-TestProfile -Merge 'NotConfigured')
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Domain/RequiredLocalRules')[0].Status) 'Review' '3 unresolved is never Pass'

$settings.EffectiveProfiles=@(New-TestProfile -Name 'Public')
$settings.NetworkProfiles=@($publicNetwork)
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Public/LocalRulesDisabled')[0].Status) 'Review' '4 unspecified Public requirement is not Fail'

$settings.EffectiveProfiles=@(New-TestProfile)
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Domain/RequiredLocalRules')[0].Priority) 'Medium' '5 inactive Domain priority'

$settings.NetworkProfiles=@($domainNetwork,$publicNetwork)
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Domain/RequiredLocalRules')[0].Priority) 'High' '6 multiple adapters retain Domain context'

$settings.LocalRulesKnown=$false
$findings=@(Get-FirewallContextFindings @settings)
$item=@($findings | Where-Object Id -eq 'Firewall/Domain/RequiredLocalRules')[0]
Assert-Equal $item.Status 'Fail' '7 failed inventory does not hide explicit mismatch'
Assert-Equal ($item.Evidence -match 'Unknown: local rule inventory failed') $true '7 unknown rule count'
$settings.LocalRulesKnown=$true

$settings.NetworkProfiles=@($publicNetwork)
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/DomainNetworkDetection')[0].Status) 'Review' '8 domain network detection lead'

$settings.EffectiveRules=@([pscustomobject]@{Name='FixtureRule';DisplayName='Fixture rule';Enabled='True';PrimaryStatus='Error';EnforcementStatus='Fixture';Status='Fixture';PolicyStoreSource='Fixture GPO';PolicyStoreSourceType='GroupPolicy'})
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'FirewallRule/FixtureRule')[0].Status) 'Review' '9 rule health error'
$settings.EffectiveRules=@()

$settings.EffectiveProfiles=@()
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal $findings.Count 1 '10 missing evidence returns one finding'
Assert-Equal $findings[0].Status 'Unavailable' '10 missing profiles cannot pass'

$settings.EffectiveProfiles=@(New-TestProfile)
$settings.RequiredLocalMergeProfiles=@()
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Domain/RequiredLocalRules').Count) 0 '11 explicit empty requirement list'

$fixtureProfile=New-TestProfile;$fixtureProfile.AllowInboundRules='False'
$settings.EffectiveProfiles=@($fixtureProfile)
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Domain/InboundRulesIgnored')[0].Status) 'Review' '12 intentional shields-up is Review'

$fixtureProfile=New-TestProfile;$fixtureProfile.DefaultInboundAction='Allow'
$settings.EffectiveProfiles=@($fixtureProfile)
$findings=@(Get-FirewallContextFindings @settings)
Assert-Equal (@($findings | Where-Object Id -eq 'Firewall/Domain/DefaultInboundAllow')[0].Status) 'Fail' '13 permissive inbound default'

Write-Host 'PASS: audit script parsed; 13 firewall fixture scenarios passed. No firewall or audit was run.'
