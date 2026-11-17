#Requires -Version 5.1
<# Fixture tests only: parse the script and import function definitions without
running the audit entry point, directory queries or antivirus queries. #>
[CmdletBinding()]
param([string]$ScriptPath=(Join-Path $PSScriptRoot 'Invoke-WindowsServerAudit.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){$errors | Format-List | Out-Host;throw 'PowerShell syntax validation failed.'}
foreach($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($definition.Extent.Text))}
$script:Passed=0;$script:Coverage=New-Object 'System.Collections.Generic.List[object]';$script:Files=@{}
function Assert-True {param([bool]$Value) if(-not $Value){throw 'Assertion failed.'}}
function Test-Case {param([string]$Name,[scriptblock]$Body) & $Body;$script:Passed++;Write-Host ('PASS '+$Name)}
function New-FixtureIntent {[pscustomobject]@{Computer='TEST';DomainController=$false;Inbound=[pscustomobject]@{Mode='Defaults';Ports=@()};Outbound=[pscustomobject]@{Mode='Defaults';Ports=@()}}}
function New-FixtureData {
    [pscustomobject]@{
        Discovery=[pscustomobject]@{Role='Member Server'}
        Services=@([pscustomobject]@{Name='MpsSvc';State='Running'})
        Firewall=[pscustomobject]@{Networks=@([pscustomobject]@{NetworkCategory='DomainAuthenticated'});Profiles=@([pscustomobject]@{Name='Domain';Enabled='True';DefaultInboundAction='Block';DefaultOutboundAction='Allow';AllowLocalFirewallRules='True'});Rules=@()}
        DomainSecurity=[pscustomobject]@{Domain='DC=example,DC=invalid';Status='Collected';PwdProperties=1;ReversibleEncryption=$false;FineGrainedPolicies=@();UserOverrides=@()}
        Defender=@();DefenderSecurity=[pscustomobject]@{Status=@([pscustomobject]@{AMRunningMode='Normal';AntivirusEnabled=$true;RealTimeProtectionEnabled=$true});Threats=@()}
        Sql=[pscustomobject]@{Records=@()}
    }
}
function New-Assessment {param($Type,$Codes) [pscustomobject]@{Identity=$Type+':fixture';Type=$Type;Score=30;Command='fixture';Signals=@($Codes | ForEach-Object {[pscustomobject]@{Code=$_;Text=$_}});LinkedProcesses=@();Connections=@()}}
$directory=Join-Path ([IO.Path]::GetTempPath()) ('FocusedTriageTests-'+[guid]::NewGuid());$null=New-Item -ItemType Directory -Path $directory
try {
    Test-Case 'Normal firewall profiles and broad rules do not generate findings' {
        $d=New-FixtureData;$d.Firewall.Rules=@([pscustomobject]@{Action='Allow';Protocol='Any';LocalPort=@('Any');Program='Any';Service='Any';RemoteAddress=@('Any')})
        Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
    }
    Test-Case 'Firewall off is one prominent finding even with multiple disabled profiles' {
        $d=New-FixtureData;$d.Firewall.Profiles[0].Enabled='False';$d.Firewall.Profiles+=@([pscustomobject]@{Name='Public';Enabled='False'})
        $f=@(Get-RequirementFindings (New-FixtureIntent) $d);Assert-True ($f.Count -eq 1 -and $f[0].Identity -eq 'Firewall:Disabled' -and $f[0].Priority -eq 'High')
    }
    Test-Case 'Stopped firewall service is caught even if profile switches are enabled' {
        $d=New-FixtureData;$d.Services[0].State='Stopped';$f=@(Get-RequirementFindings (New-FixtureIntent) $d)
        Assert-True ($f.Count -eq 1 -and $f[0].Priority -eq 'High')
    }
    Test-Case 'Unknown firewall values are not interpreted as off' {
        $d=New-FixtureData;$d.Firewall.Profiles[0].Enabled='NotConfigured';Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
    }
    Test-Case 'Domain reversible encryption is high priority; unavailable evidence is not guessed' {
        $d=New-FixtureData;$d.DomainSecurity.ReversibleEncryption=$true;$d.DomainSecurity.PwdProperties=17
        $f=@(Get-RequirementFindings (New-FixtureIntent) $d);Assert-True ($f.Count -eq 1 -and $f[0].Priority -eq 'High')
        $d.DomainSecurity.Status='NotAssessed';Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
    }
    Test-Case 'Fine-grained and user reversible-encryption settings are separate checks' {
        $d=New-FixtureData;$d.DomainSecurity.FineGrainedPolicies=@([pscustomobject]@{Name='ExamplePolicy'})
        $d.DomainSecurity.UserOverrides=@([pscustomobject]@{Name='example';Disabled=$false})
        $f=@(Get-RequirementFindings (New-FixtureIntent) $d);Assert-True ($f.Count -eq 2)
    }
    Test-Case 'Defender exclusions are grouped into one exact-evidence finding' {
        $d=New-FixtureData;$d.Defender=@([pscustomobject]@{Type='ExclusionPath';Value='C:\AppData'},[pscustomobject]@{Type='ExclusionExtension';Value='py'})
        $f=@(Get-RequirementFindings (New-FixtureIntent) $d);Assert-True ($f.Count -eq 1 -and $f[0].Priority -eq 'High' -and $f[0].Observed.Contains('C:\AppData'))
    }
    Test-Case 'Inactive threat history is not presented as an active threat' {
        $d=New-FixtureData;$d.DefenderSecurity.Threats=@([pscustomobject]@{ThreatID=1;ThreatName='fixture';IsActive=$false})
        Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
        $d.DefenderSecurity.Threats[0].IsActive=$true;Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 1)
    }
    Test-Case 'Passive antivirus mode is not called disabled active protection' {
        $d=New-FixtureData;$d.DefenderSecurity.Status[0].RealTimeProtectionEnabled=$false;$d.DefenderSecurity.Status[0].AMRunningMode='Passive'
        Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 0)
        $d.DefenderSecurity.Status[0].AMRunningMode='Normal';Assert-True (@(Get-RequirementFindings (New-FixtureIntent) $d).Count -eq 1)
    }
    Test-Case 'Unsigned location and inherited-permission clues alone stay out of the main findings' {
        Assert-True (-not (Test-ProminentArtifact (New-Assessment 'Service' @('UnusualExecutionPath','UnsignedCorroboration','SystemContext','NetworkCorroboration'))))
        Assert-True (-not (Test-ProminentArtifact (New-Assessment 'Service' @('BroadDirectoryRights'))))
        Assert-True (Test-ProminentArtifact (New-Assessment 'Task' @('EncodedPowerShell')))
    }
    Test-Case 'A lone keyboard API name is insufficient; coherent capture patterns are a lead' {
        Assert-True (@(Get-TextSignals 'GetAsyncKeyState' | Where-Object Code -eq 'KeyboardCapturePatterns').Count -eq 0)
        Assert-True (@(Get-TextSignals 'from pynput import keyboard; keyboard.Listener(on_press=handle)' | Where-Object Code -eq 'KeyboardCapturePatterns').Count -eq 1)
        Assert-True (-not (Test-ProminentArtifact (New-Assessment 'Process' @('PeriodicNetworkCode'))))
    }
    Test-Case 'Runtime detection distinguishes scripts, ordinary processes and cron' {
        Assert-True ((Get-ScriptRuntime 'C:\Python\python3.11.exe' '' '') -eq 'Python')
        Assert-True ((Get-ScriptRuntime '' 'cron.exe' '') -eq 'Nonstandard Windows scheduler')
        Assert-True ((Get-ScriptRuntime '' 'svchost.exe' '') -eq '')
        Assert-True ((Get-ScriptRuntime '' 'powershell.exe' 'powershell.exe') -eq '')
    }
    Test-Case 'Identical running script workers are grouped and the audit process is excluded' {
        $p=@([pscustomobject]@{ProcessId=77;ExecutablePath='C:\Python\python.exe';Name='python.exe';CommandLine='python.exe C:\Data\app.py'},[pscustomobject]@{ProcessId=78;ExecutablePath='C:\Python\python.exe';Name='python.exe';CommandLine='python.exe C:\Data\app.py'})
        $f=@(Get-FocusedArtifactFindings @() @() $p @() -AuditProcessId 999)
        Assert-True ($f.Count -eq 1 -and $f[0].Kind -eq 'RunningScript')
        Assert-True (@(Get-FocusedArtifactFindings @() @() @($p[0]) @() -AuditProcessId 77).Count -eq 0)
    }
    Test-Case 'Enabled Python task is a review lead; disabled task stays in supporting evidence' {
        $a=New-Assessment 'Task' @();$task=New-Observation 'Task:fixture' 'Task' '\Company\fixture' '' '' 'Tasks' ([pscustomobject]@{Enabled=$true;Actions=@([pscustomobject]@{Execute='C:\Python\python.exe';Arguments='C:\Data\app.py';WorkingDirectory=''})})
        $f=@(Get-FocusedArtifactFindings @($a) @($task) @() @());Assert-True ($f.Count -eq 1 -and $f[0].Kind -eq 'Persistence')
        $task.Details.Enabled=$false;Assert-True (@(Get-FocusedArtifactFindings @($a) @($task) @() @()).Count -eq 0)
    }
    Test-Case 'Shared Python executable does not associate a task with every Python process' {
        $a=New-Observation 'Task:x' 'Task' '\x' '' '' 'Tasks' $null
        $paths=[pscustomobject]@{Executable='C:\Python\python.exe';Paths=@('C:\Python\python.exe','C:\Data\one.py')}
        $p=@([pscustomobject]@{ProcessId=1;Name='python.exe';ExecutablePath='C:\Python\python.exe';CommandLine='python.exe C:\Data\one.py'},[pscustomobject]@{ProcessId=2;Name='python.exe';ExecutablePath='C:\Python\python.exe';CommandLine='python.exe C:\Data\two.py'})
        $found=@(Get-LinkedProcesses $a $p $paths);Assert-True ($found.Count -eq 1 -and $found[0].ProcessId -eq 1)
    }
    Test-Case 'Short report escapes evidence and omits raw inventory and serialized dumps' {
        $script:Files=@{test=[pscustomobject]@{NeverEmbedThisValue='raw cache'}}
        $report=Join-Path $directory 'index.html';$hostile='<script>window.injected=1</script>'
        $f=New-TriageFinding 'SecurityWeakness' 'High' 'fixture' 'Fixture' '' $hostile 'Evidence' 'Verify'
        $discovery=[pscustomobject]@{Computer='TEST';Caption='Server';Role='Member Server'}
        Write-TriageReport -Path $report -Discovery $discovery -Intent (New-FixtureIntent) -Findings @($f) -Coverage @() -Artifacts @([pscustomobject]@{Command='NeverEmbedThisValue'})
        $html=Get-Content -LiteralPath $report -Raw
        Assert-True (-not $html.Contains($hostile) -and $html.Contains('&lt;script&gt;'))
        Assert-True (-not $html.Contains('NeverEmbedThisValue') -and -not $html.Contains('<pre>'))
    }
    Write-Host ('Passed '+$script:Passed+' fixture groups. Live Windows and directory integration were not tested.') -ForegroundColor Green
}finally{Remove-Item -LiteralPath $directory -Recurse -Force}
