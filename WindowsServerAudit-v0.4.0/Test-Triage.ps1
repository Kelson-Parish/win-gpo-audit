#Requires -Version 5.1
<#
Fixture tests. Loads function definitions through the PowerShell parser only;
never runs the audit entry point, changes system configuration or queries SQL.
Run from an elevated or ordinary 64-bit Windows PowerShell console.
#>
[CmdletBinding()]
param([string]$ScriptPath=(Join-Path $PSScriptRoot 'Invoke-WindowsServerAudit.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){$parseErrors | Format-List | Out-Host;throw 'Audit script failed PowerShell syntax validation.'}
$definitions=@{}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
    $definitions[$definition.Name]=$definition.Extent.Text
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:Passed=0
function Assert-True {param([bool]$Value,[string]$Message='Assertion failed') if(-not $Value){throw $Message}}
function Assert-Throws {param([scriptblock]$Action) $threw=$false;try {& $Action | Out-Null}catch{$threw=$true};Assert-True $threw 'Expected an exception.'}
function Test-Case {param([string]$Name,[scriptblock]$Action) & $Action;$script:Passed++;Write-Host ('PASS '+$Name)}
function Empty-List {[pscustomobject]@{Known=$false;Complete=$false;Values=@()}}
function New-FixtureIntent {
    [pscustomobject]@{Schema='WindowsServerAudit.Intent';Version=1;Computer='TEST';Roles=(Empty-List);Services=@();NetworkKnown=$false;NetworkComplete=$false;Network=@();Administrators=(Empty-List);AdminIdentities=@();ManagementTools=(Empty-List);ExpectedTasks=(Empty-List);DefenderExclusions=(Empty-List);LocalRuleMerging=[pscustomobject]@{Domain=$null;Private=$null;Public=$null};SqlAdministrators=(Empty-List);Exceptions=@();BaselinePath=''}
}
function New-FixtureData {
    [pscustomobject]@{Discovery=[pscustomobject]@{Role='Member Server'};Services=@();Admins=@();Firewall=[pscustomobject]@{Networks=@();Profiles=@();Rules=@()};Live=[pscustomobject]@{Tcp=@();Udp=@()};Artifacts=@();Defender=@();Sql=[pscustomobject]@{Records=@()}}
}
$testDirectory=Join-Path ([IO.Path]::GetTempPath()) ('TriageFixtures-'+[guid]::NewGuid())
$null=New-Item -ItemType Directory -Path $testDirectory
try {
    Test-Case 'Tri-state preserves false and unknown' {
        $script:Answers=New-Object 'System.Collections.Generic.Queue[string]'
        foreach($answer in @('n','u','y')){$script:Answers.Enqueue($answer)}
        function script:Ask-Text {param($Prompt) $script:Answers.Dequeue()}
        Assert-True ((Ask-TriState 'test') -eq $false)
        Assert-True ($null -eq (Ask-TriState 'test'))
        Assert-True ((Ask-TriState 'test') -eq $true)
    }
    Test-Case 'Unknown, none and partial lists stay distinct' {
        foreach($answer in @('','none','one,two','n')){$script:Answers.Enqueue($answer)}
        $unknown=Read-IntentList 'test';$none=Read-IntentList 'test';$partial=Read-IntentList 'test'
        Assert-True (-not $unknown.Known -and -not $unknown.Complete)
        Assert-True ($none.Known -and $none.Complete -and $none.Values.Count -eq 0)
        Assert-True ($partial.Known -and -not $partial.Complete -and $partial.Values.Count -eq 2)
    }
    Test-Case 'Intent accepts unknown requirements' {Assert-True (Test-IntentProfile (New-FixtureIntent))}
    Test-Case 'Intent rejects unknown complete approvals' {$i=New-FixtureIntent;$i.ExpectedTasks.Complete=$true;Assert-Throws {Test-IntentProfile $i}}
    Test-Case 'Intent rejects malformed SQL approval metadata' {$i=New-FixtureIntent;$i.SqlAdministrators=$null;Assert-Throws {Test-IntentProfile $i}}
    Test-Case 'Intent rejects fractional and Boolean ports' {
        foreach($port in @(3.5,$true,0,65536)){$i=New-FixtureIntent;$i.NetworkKnown=$true;$i.Network=@([pscustomobject]@{Protocol='TCP';Port=$port;Required=$true;SourcesKnown=$false;Sources=@()});Assert-Throws {Test-IntentProfile $i}}
    }
    Test-Case 'Intent rejects wildcard exception suppression' {$i=New-FixtureIntent;$i.Exceptions=@([pscustomobject]@{Identity='Service:*';Reason='test'});Assert-Throws {Test-IntentProfile $i}}
    Test-Case 'IPv4 subnet subset and broader network' {
        Assert-True ((Test-AddressSubset '10.4.2.1' @('10.4.0.0/16')) -eq $true)
        Assert-True ((Test-AddressSubset '10.0.0.0/8' @('10.4.0.0/16')) -eq $false)
        Assert-True ((Test-AddressSubset 'Any' @('10.4.0.0/16')) -eq $false)
    }
    Test-Case 'IPv6, dynamic keyword and invalid prefix' {
        Assert-True ((Test-AddressSubset '2001:db8::1' @('2001:db8::/32')) -eq $true)
        Assert-True ($null -eq (Test-AddressSubset 'LocalSubnet' @('10.0.0.0/8')))
        Assert-True ($null -eq (ConvertTo-AddressRange '10.1.1.1/33'))
    }
    Test-Case 'Port range does not treat RPC keyword as a match' {
        Assert-True ((Test-PortSpec @('1000-2000') 1433) -eq $true)
        Assert-True ((Test-PortSpec @('80') 1433) -eq $false)
        Assert-True ($null -eq (Test-PortSpec @('RPC') 1433))
    }
    Test-Case 'Encoded arguments are recognized as text only' {Assert-True (@(Get-TextSignals 'powershell.exe -enc ZgA=').Count -eq 1);Assert-True (@(Get-TextSignals '"C:\Windows\powershell.exe" -NoProfile -EncodedCommand ZgA=').Count -eq 1)}
    Test-Case 'Account aliases normalize' {Assert-True ((Canonical-Account '.\svc' 'TEST') -eq 'test\svc');Assert-True ((Canonical-Account 'LocalSystem' 'TEST') -eq 's-1-5-18')}
    Test-Case 'Last failed collection defeats earlier success' {
        $script:Coverage=New-Object 'System.Collections.Generic.List[object]'
        Add-Coverage 'Services' 'Collected' 'initial' $true;Add-Coverage 'Services' 'Unavailable' 'final'
        Assert-True (-not (Is-Collected 'Services'))
    }
    Test-Case 'ACL inheritance, denies and narrow principals' {
        $allow=[pscustomobject]@{Sid='S-1-1-0';Type='Allow';Mask=2;Inherited=$true;InheritOnly=$false;Conditional=$false}
        Assert-True (@(Get-BroadAclSignals @($allow) 'File').Count -eq 1)
        $allow.InheritOnly=$true;Assert-True (@(Get-BroadAclSignals @($allow) 'File').Count -eq 0)
        $allow.InheritOnly=$false;$deny=[pscustomobject]@{Sid='S-1-1-0';Type='Deny';Mask=2;Inherited=$false;InheritOnly=$false;Conditional=$false}
        Assert-True ((Get-BroadAclSignals @($allow,$deny) 'File').Weight -eq 10)
        $allow.Sid='S-1-5-32-544';Assert-True (@(Get-BroadAclSignals @($allow) 'File').Count -eq 0)
        Assert-True ((Get-BroadAclSignals @() 'Service' -NullDacl $true).Code -eq 'NullDacl')
    }
    Test-Case 'Command parsing extracts executable and script without execution' {
        $result=Get-CommandPaths '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -File "C:\ProgramData\sample.ps1"'
        Assert-True ($result.Paths -contains 'C:\ProgramData\sample.ps1')
        Assert-True ((Get-CommandPaths 'C:\Program Files\Example\svc.exe -x').UnquotedSpaces)
        Assert-True ((Get-CommandPaths '\\untrusted\share\svc.exe').RemoteReference)
        Assert-True ((Resolve-ObservedPath '\\untrusted\share\svc.exe') -eq '')
    }
    Test-Case 'Script path correlation needs a token boundary' {
        $a=New-Observation 'Task:\x' 'Task' '\x' '' '' 'Tasks' $null
        $paths=[pscustomobject]@{Executable='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';Paths=@('C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','C:\data\test.ps1')}
        $processes=@([pscustomobject]@{ProcessId=1;ExecutablePath=$paths.Executable;CommandLine='powershell.exe -file C:\data\test.ps1.old'},[pscustomobject]@{ProcessId=2;ExecutablePath=$paths.Executable;CommandLine='powershell.exe -file "C:\data\test.ps1"'})
        $linked=@(Get-LinkedProcesses $a $processes $paths)
        Assert-True ($linked.Count -eq 1 -and $linked[0].ProcessId -eq 2)
    }
    Test-Case 'Requirement mismatch detects local firewall merging' {
        $i=New-FixtureIntent;$i.LocalRuleMerging.Domain=$true;$d=New-FixtureData
        $d.Firewall.Networks=@([pscustomobject]@{NetworkCategory='DomainAuthenticated'})
        $d.Firewall.Profiles=@([pscustomobject]@{Name='Domain';Enabled='True';AllowLocalFirewallRules='False';DefaultInboundAction='Block';AllowInboundRules='True'})
        $f=@(Get-RequirementFindings $i $d | Where-Object Identity -eq 'FirewallMerge:Domain')
        Assert-True ($f.Count -eq 1 -and $f[0].Kind -eq 'RequirementViolation')
        $i.LocalRuleMerging.Domain=$null;Assert-True (@(Get-RequirementFindings $i $d | Where-Object Identity -eq 'FirewallMerge:Domain').Count -eq 0)
    }
    Test-Case 'Partial admin approvals never declare unmatched identities unapproved' {
        $script:Coverage=New-Object 'System.Collections.Generic.List[object]';Add-Coverage 'Administrators' 'Collected' 'fixture' $true
        $i=New-FixtureIntent;$i.Administrators=[pscustomobject]@{Known=$true;Complete=$false;Values=@('S-1-5-21-1-2-3-1001')};$i.AdminIdentities=@([pscustomobject]@{Name='S-1-5-21-1-2-3-1001';Sid='S-1-5-21-1-2-3-1001';Resolved=$true})
        $d=New-FixtureData;$d.Admins=@([pscustomobject]@{Name='TEST\other';Sid='S-1-5-21-1-2-3-1002'})
        $f=@(Get-RequirementFindings $i $d | Where-Object Identity -like 'Administrator:*');Assert-True ($f[0].Kind -eq 'Review')
        $i.Administrators.Complete=$true;$f=@(Get-RequirementFindings $i $d | Where-Object Identity -like 'Administrator:*');Assert-True ($f[0].Kind -eq 'RequirementViolation')
        $i.AdminIdentities[0].Resolved=$false;$f=@(Get-RequirementFindings $i $d | Where-Object Identity -like 'Administrator:*');Assert-True ($f[0].Kind -eq 'Review')
    }
    Test-Case 'Signals corroborate without trusting a management label or exception' {
        function script:Get-FileEvidence {param($Path) [pscustomobject]@{Status='Observed';SignatureStatus='NotSigned';Acl=$null;ParentAcl=$null;ContentSignals=@()}}
        $i=New-FixtureIntent;$i.ManagementTools.Values=@('helper');$i.Exceptions=@([pscustomobject]@{Identity='Service:fixture';Reason='test annotation'})
        $a=New-Observation 'Service:fixture' 'Service' 'fixture' 'C:\Users\Public\helper.exe' 'LocalSystem' 'Services' ([pscustomobject]@{Aces=@();NullDacl=$false})
        $assessment=Get-ArtifactAssessment $a $i @() @()
        Assert-True ($assessment.Score -eq 45 -and $assessment.ManagementContext.Count -eq 1 -and $assessment.Exceptions.Count -eq 1)
        $a.Command='C:\Trusted\app.exe';$a.Account='';$assessment=Get-ArtifactAssessment $a $i @() @();Assert-True ($assessment.Score -eq 0)
        . ([scriptblock]::Create($definitions['Get-FileEvidence']))
    }
    Test-Case 'Baseline failures do not imply mass removal' {
        $machine=[pscustomobject]@{Year='2022';Role='Member Server';EditionSku=7;Build='20348.1'}
        $artifact=[pscustomobject]@{Identity='Service:x';Collection='Services';Fields=[pscustomobject]@{Command='C:\x.exe';Account='LocalSystem'}}
        $reference=[pscustomobject]@{Schema='WindowsServerAudit.TriageSnapshot';Version=1;Machine=$machine;Artifacts=@($artifact);Files=@();Collections=@()}
        $current=[pscustomobject]@{Schema='WindowsServerAudit.TriageSnapshot';Version=1;Machine=$machine;Artifacts=@();Files=@();Collections=@([pscustomobject]@{Name='Services';Complete=$true},[pscustomobject]@{Name='Services';Complete=$false})}
        Assert-True (@(Compare-TriageSnapshot $current $reference).Count -eq 0)
        $current.Collections=@([pscustomobject]@{Name='Services';Complete=$true});Assert-True (@(Compare-TriageSnapshot $current $reference).Count -eq 1)
        $reference.Schema='old';Assert-Throws {Compare-TriageSnapshot $current $reference}
    }
    Test-Case 'HTML escapes evidence rather than creating executable markup' {
        $hostile='<script>alert("fixture")</script>'
        Assert-True ((Encode-Html $hostile) -notmatch '<script>')
        $discovery=[pscustomobject]@{Computer='TEST';Caption='Server';Role='Member Server';Build='fixture'}
        $finding=New-TriageFinding 'Review' 'High' $hostile $hostile '' '' '' ''
        $script:Files=@{}
        $report=Join-Path $testDirectory 'report.html'
        Write-TriageReport $report $discovery (New-FixtureIntent) @($finding) @() @() @()
        $html=Get-Content -LiteralPath $report -Raw
        Assert-True ($html -notmatch [regex]::Escape($hostile))
        Assert-True ($html.Contains('&lt;script&gt;'))
    }
    Write-Host ('All '+$script:Passed+' fixture groups passed. No Windows collector or SQL integration test was run.') -ForegroundColor Green
}finally{Remove-Item -LiteralPath $testDirectory -Recurse -Force}
