#Requires -Version 5.1
<#
Parses the main script and tests only pure comparison helpers with invented data.
No audit, service query, scheduled task, Defender query or network call is run.
The baseline-import scenarios create and remove files in an owned temp folder.
#>
[CmdletBinding()]
param([string]$AuditScript=(Join-Path $PSScriptRoot 'Invoke-WindowsServerAudit.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($AuditScript,[ref]$tokens,[ref]$parseErrors)
if(@($parseErrors).Count){throw ($parseErrors | Out-String)}
$names=@('Html','New-Finding','ConvertTo-ConfigurationPlainValue','ConvertTo-ConfigurationJson','New-ConfigurationCollection','New-ConfigurationItem','Get-DocumentedConfigurationDefaults','Get-ConfigurationItemIndex','Test-ConfigurationBaselineCompatibility','Get-ConfigurationDefaultFindings','Compare-ConfigurationSnapshots','Get-ConfigurationInvestigationFindings','Read-ConfigurationBaseline')
foreach($functionName in $names){
    $definitions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) | Where-Object Name -eq $functionName)
    if($definitions.Count -ne 1){throw ('Expected one function '+$functionName)}
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}
$script:Passed=0
function Assert-Condition {param([bool]$Condition,[string]$Case) if(-not $Condition){throw ('FAILED: '+$Case)};$script:Passed++}
function Copy-Fixture {param($Value) ConvertTo-Json -InputObject $Value -Depth 30 | ConvertFrom-Json}
function New-FixtureSnapshot {
    param([string]$Category='Services')
    $collection=New-ConfigurationCollection $Category
    $collection.Items=@(New-ConfigurationItem 'Example' @{PathName='C:\Windows\System32\example.exe';StartMode='Manual'} 'fixture')
    [pscustomobject]@{Schema='WindowsServerAudit.ConfigurationSnapshot';SchemaVersion=1;CollectorVersion='0.3.0';CreatedUtc='2026-11-16T00:00:00Z';Label='Fixture';Machine=[pscustomobject]@{Year='2022';Role='Member Server';EditionSku=8;Architecture='64-bit';Build='20348.1000';Computer='Fixture'};Collections=@($collection)}
}
function Invoke-FixtureCompare {param($Current,$Reference,[switch]$AllowBuildMismatch) @(Compare-ConfigurationSnapshots $Current $Reference 'fixture baseline' -AllowBuildMismatch:$AllowBuildMismatch)}

$a=[pscustomobject]@{B=2;A=@(1)};$b=[pscustomobject]@{A=@(1);B=2}
Assert-Condition ((ConvertTo-ConfigurationJson $a) -ceq (ConvertTo-ConfigurationJson $b)) 'property ordering does not create a difference'
$roundTrip=[pscustomobject]@{Single=@('one');Empty=@();Nested=@{Duration=[TimeSpan]::FromMinutes(3);Date=[datetime]'2026-11-16T00:00:00Z'}}
Assert-Condition ((ConvertTo-ConfigurationJson $roundTrip) -ceq (ConvertTo-ConfigurationJson (Copy-Fixture (ConvertTo-ConfigurationPlainValue $roundTrip)))) 'single-element/empty arrays and time values survive JSON round trip'

$reference=New-FixtureSnapshot;$current=Copy-Fixture $reference
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition ($findings.Count -eq 0) 'identical reference produces no changes'

$current.Collections[0].Items[0].Fields.PathName='C:\Temp\changed.exe'
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition (@($findings | Where-Object {$_.Title -like 'Changed:*' -and $_.Priority -eq 'High' -and $_.Evidence -match 'Changed fields: PathName'}).Count -eq 1) 'changed service path has field-level evidence'

$current=Copy-Fixture $reference;$current.Collections[0].Items+=New-ConfigurationItem 'NewService' @{PathName='C:\example.exe'} 'fixture'
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition (@($findings | Where-Object Title -like 'Added:*').Count -eq 1) 'new service is compared against a complete reference'

$current=Copy-Fixture $reference;$current.Collections[0].Items=@()
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition (@($findings | Where-Object Title -like 'Removed:*').Count -eq 1) 'removal requires successful current enumeration'

$current.Collections[0].Status='Unavailable';$current.Collections[0].EnumerationComplete=$false
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition (@($findings | Where-Object Title -like 'Removed:*').Count -eq 0 -and @($findings | Where-Object Status -eq 'Unavailable').Count -gt 0) 'failed collector is not interpreted as mass removal'

$current=Copy-Fixture $reference;$current.Collections[0].Items[0].ReadStatus='Unavailable'
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition (@($findings | Where-Object Title -like 'Changed:*').Count -eq 0 -and @($findings | Where-Object Status -eq 'Unavailable').Count -gt 0) 'unreadable item is not treated as a change'

$current=Copy-Fixture $reference;$current.Collections[0].Items=@();$current.Collections[0].Status='Partial';$current.Collections[0].EnumerationComplete=$false
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition (@($findings | Where-Object Title -like 'Removed:*').Count -eq 0) 'incomplete current enumeration suppresses unproven removal'

$partialReference=Copy-Fixture $reference;$partialReference.Collections[0].Items=@();$partialReference.Collections[0].Status='Partial';$partialReference.Collections[0].EnumerationComplete=$false
$findings=@(Invoke-FixtureCompare $reference $partialReference)
Assert-Condition (@($findings | Where-Object Title -like 'Added:*').Count -eq 0) 'incomplete reference suppresses unproven addition'

$current=Copy-Fixture $reference;$current.Machine.Role='Domain Controller'
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition ($findings.Count -eq 1 -and $findings[0].Status -eq 'Unavailable') 'different server roles are not silently compared'

$current=Copy-Fixture $reference;$current.Machine.Build='20348.2000'
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition ($findings.Count -eq 1 -and $findings[0].Status -eq 'Unavailable') 'build mismatch requires explicit override'
$findings=@(Invoke-FixtureCompare $current $reference -AllowBuildMismatch)
Assert-Condition (@($findings | Where-Object Id -eq 'Baseline/BuildMismatch').Count -eq 1 -and @($findings | Where-Object Title -like 'Changed:*').Count -eq 0) 'explicitly allowed build mismatch is disclosed'

$current=Copy-Fixture $reference;$current.Collections[0].Scope='DifferentUser'
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition ($findings.Count -eq 1 -and $findings[0].Id -eq 'Baseline/Services/Scope') 'different user scopes are not compared'

$current=New-FixtureSnapshot 'SecurityRegistry';$ntlmKey='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinServerSec'
$current.Collections[0].Items=@(New-ConfigurationItem $ntlmKey @{Presence='Present';Kind='DWord';Value=537395200} 'fixture')
$findings=@(Get-ConfigurationDefaultFindings $current)
$hardening=@($findings | Where-Object {$_.Id -like '*NTLMMinServerSec*' -and $_.Priority -eq 'Informational' -and $_.Evidence -match 'Additional hardening'})
Assert-Condition ($hardening.Count -eq 1) 'additional NTLM hardening is not labeled weakened protection'
$current.Collections[0].Items[0].Fields.Presence='Absent'
$findings=@(Get-ConfigurationDefaultFindings $current)
Assert-Condition (@($findings | Where-Object {$_.Id -like '*NTLMMinServerSec*' -and $_.Observed -match 'absent'}).Count -eq 1) 'absent registry value is not assumed to have the documented effective value'

$current=New-FixtureSnapshot 'DefenderExclusions';$current.Collections[0].EnumerationComplete=$false
$reference=Copy-Fixture $current;$reference.Collections[0].Items=@()
$findings=@(Invoke-FixtureCompare $current $reference)
Assert-Condition (@($findings | Where-Object Title -like 'Newly visible*').Count -eq 1 -and @($findings | Where-Object Title -like 'Added:*').Count -eq 0) 'limited Defender visibility is explicitly labeled'

$current=New-FixtureSnapshot 'ScheduledTasks';$current.Collections[0].Items[0].CommandText='powershell.exe -EncodedCommand QUJD'
$findings=@(Get-ConfigurationInvestigationFindings $current)
Assert-Condition (@($findings | Where-Object Id -like 'Pattern/EncodedCommand/*').Count -eq 1) 'encoded task command is observed without execution'
Assert-Condition ((Html '<script>alert(1)</script>') -notmatch '<script>') 'machine-supplied text is HTML encoded'

$directory=Join-Path ([IO.Path]::GetTempPath()) ('AuditComparisonTest-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $directory
try {
    $path=Join-Path $directory 'Baseline.json';$reference=New-FixtureSnapshot
    ConvertTo-Json -InputObject $reference -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $read=Read-ConfigurationBaseline -Path $path -ExpectedSha256 $hash
    Assert-Condition ($read.Sha256 -eq $hash -and $read.Snapshot.SchemaVersion -eq 1) 'baseline import verifies and parses the same hashed bytes'
    $rejected=$false;try{$null=Read-ConfigurationBaseline -Path $path -ExpectedSha256 ('0'*64)}catch{$rejected=$true}
    Assert-Condition $rejected 'incorrect trusted hash rejects the reference'
    $reference.SchemaVersion=99;ConvertTo-Json -InputObject $reference -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8
    $rejected=$false;try{$null=Read-ConfigurationBaseline -Path $path}catch{$rejected=$true}
    Assert-Condition $rejected 'unsupported baseline schema is rejected'
    $reference=New-FixtureSnapshot;$reference.Collections[0].Items+=Copy-Fixture $reference.Collections[0].Items[0]
    ConvertTo-Json -InputObject $reference -Depth 30 | Set-Content -LiteralPath $path -Encoding UTF8
    $rejected=$false;try{$null=Read-ConfigurationBaseline -Path $path}catch{$rejected=$true}
    Assert-Condition $rejected 'duplicate case-insensitive item identities are rejected'
} finally {Remove-Item -LiteralPath $directory -Recurse -Force}

Write-Host ('PASS: script parsed and '+$script:Passed+' configuration comparison assertions passed. No live audit was performed.')
