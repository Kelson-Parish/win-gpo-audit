#Requires -Version 5.1
<#
.SYNOPSIS
Interactive Windows Server intent setup and read-only implant triage.
.DESCRIPTION
Version 0.4.0. Collects evidence, asks what should be present, and writes a
prioritized HTML report. Findings are leads, not malware verdicts. Configuration,
firewall rules, services, users, tasks and audit settings are never changed.
.EXAMPLE
.\Invoke-WindowsServerAudit.ps1
.EXAMPLE
.\Invoke-WindowsServerAudit.ps1 -ConfigPath C:\Audit\ServerIntent.json
.EXAMPLE
.\Invoke-WindowsServerAudit.ps1 -ConfigPath C:\Audit\ServerIntent.json -NonInteractive
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NonInteractive,
    [string]$OutputDirectory=(Join-Path (Get-Location) ('ServerTriage-{0}-{1}' -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [switch]$SkipSql,
    [switch]$CaptureBaseline,
    [switch]$AllowBaselineBuildMismatch,
    [ValidateRange(1,1024)][int]$MaxFileSizeMB=128
)

# Read operator answers from the console; pipeline execution is unsupported.
function Ask-Text {
    param([string]$Prompt)
    (Read-Host $Prompt).Trim()
}
function Ask-TriState {
    param([string]$Prompt)
    while($true){
        $answer=(Ask-Text ($Prompt+' [y/n/u; Enter=unknown]')).ToLowerInvariant()
        switch($answer){'y'{return $true}'yes'{return $true}'n'{return $false}'no'{return $false}'u'{return $null}'unknown'{return $null}''{return $null}}
        Write-Host 'Please enter y, n, or u.'
    }
}
# A blank answer is unknown. Only an explicit complete list supports unapproved-member checks.
function Read-IntentList {
    param([string]$Prompt)
    $answer=Ask-Text ($Prompt+' [comma-separated; none; Enter=unknown]')
    if(-not $answer -or $answer -ieq 'unknown' -or $answer -ieq 'u'){return [pscustomobject]@{Known=$false;Complete=$false;Values=@()}}
    if($answer -ieq 'none'){return [pscustomobject]@{Known=$true;Complete=$true;Values=@()}}
    $values=@($answer -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_} | Select-Object -Unique)
    $complete=Ask-TriState 'Is that the COMPLETE approved list'
    [pscustomobject]@{Known=$true;Complete=($complete -eq $true);Values=$values}
}
function Resolve-IntentIdentity {
    param([string]$Name)
    try {
        if($Name -match '^S-\d-(?:\d+-)+\d+$'){$sid=New-Object Security.Principal.SecurityIdentifier($Name)}
        else {$sid=(New-Object Security.Principal.NTAccount($Name)).Translate([Security.Principal.SecurityIdentifier])}
        [pscustomobject]@{Name=$Name;Sid=$sid.Value;Resolved=$true}
    } catch {[pscustomobject]@{Name=$Name;Sid='';Resolved=$false}}
}
function Canonical-Account {
    param([string]$Name,[string]$Computer)
    $n=$Name.Trim().ToLowerInvariant()
    if($n -in @('localsystem','nt authority\system','system','s-1-5-18')){return 's-1-5-18'}
    if($n -in @('nt authority\localservice','localservice','s-1-5-19')){return 's-1-5-19'}
    if($n -in @('nt authority\networkservice','networkservice','s-1-5-20')){return 's-1-5-20'}
    if($n.StartsWith('.\')){$n=$Computer.ToLowerInvariant()+'\'+$n.Substring(2)}
    $n
}
function ConvertTo-AddressRange {
    param([string]$Text)
    if($Text -ieq 'Any'){return [pscustomobject]@{Any=$true;Family=0;Low=@();High=@()}}
    $parts=$Text -split '/'
    if($parts.Count -gt 2){return $null}
    $address=$null
    if(-not [Net.IPAddress]::TryParse($parts[0],[ref]$address)){return $null}
    if($parts[0] -match '%'){return $null}
    $bytes=$address.GetAddressBytes();$bits=$bytes.Length*8;$prefix=$bits
    if($parts.Count -eq 2){
        if($parts[1] -notmatch '^\d+$'){return $null}
        $prefix=[int]$parts[1];if($prefix -lt 0 -or $prefix -gt $bits){return $null}
    }
    $low=New-Object byte[] $bytes.Length;$high=New-Object byte[] $bytes.Length
    for($i=0;$i -lt $bytes.Length;$i++){
        $remaining=$prefix-8*$i
        $mask=if($remaining -ge 8){255}elseif($remaining -le 0){0}else{256-[int][Math]::Pow(2,8-$remaining)}
        $low[$i]=$bytes[$i] -band $mask;$high[$i]=$low[$i] -bor (255-$mask)
    }
    [pscustomobject]@{Any=$false;Family=$bytes.Length;Low=$low;High=$high}
}
function Compare-Bytes {
    param([byte[]]$Left,[byte[]]$Right)
    for($i=0;$i -lt $Left.Length;$i++){if($Left[$i] -lt $Right[$i]){return -1};if($Left[$i] -gt $Right[$i]){return 1}}
    return 0
}
function Test-AddressSubset {
    param([string]$Candidate,[string[]]$Allowed)
    # A null result means a keyword/range cannot be evaluated here. Never turn
    # LocalSubnet, RPC keywords or other unresolved conditions into a match.
    if($Allowed -icontains 'Any'){return $true}
    $range=ConvertTo-AddressRange $Candidate
    if($null -eq $range){return $null}
    if($range.Any){return $false}
    foreach($text in $Allowed){
        $expected=ConvertTo-AddressRange $text
        if($null -ne $expected -and $expected.Family -eq $range.Family -and (Compare-Bytes $range.Low $expected.Low) -ge 0 -and (Compare-Bytes $range.High $expected.High) -le 0){return $true}
    }
    return $false
}
function Test-PortSpec {
    param([object[]]$Specifications,[int]$Port)
    $unknown=$false
    foreach($spec in $Specifications){
        foreach($part in ([string]$spec -split ',')){
            $p=$part.Trim()
            if($p -ieq 'Any'){return $true}
            if($p -match '^\d+$' -and [int]$p -eq $Port){return $true}
            elseif($p -match '^(\d+)-(\d+)$'){if($Port -ge [int]$matches[1] -and $Port -le [int]$matches[2]){return $true}}
            elseif($p -notmatch '^\d+$'){$unknown=$true}
        }
    }
    if($unknown){return $null};return $false
}
# Reject malformed profiles before they influence comparisons. Profiles contain no executable logic.
function Test-IntentProfile {
    param([object]$Profile)
    if($Profile.Schema -ne 'WindowsServerAudit.Intent' -or $Profile.Version -ne 1){throw 'Unsupported intended-configuration profile.'}
    foreach($key in @('Roles','Administrators','ManagementTools','ExpectedTasks','DefenderExclusions','SqlAdministrators')){
        $list=$Profile.$key
        if($null -eq $list -or $list.Known -isnot [bool] -or $list.Complete -isnot [bool]){throw ('Invalid '+$key+' list metadata.')}
        if(-not $list.Known -and ($list.Complete -or @($list.Values).Count)){throw ('Unknown '+$key+' cannot be a complete/nonempty list.')}
        foreach($value in @($list.Values)){if($value -isnot [string] -or -not $value.Trim() -or $value.Length -gt 4096){throw ('Invalid '+$key+' list value.')}}
    }
    if($null -eq $Profile.LocalRuleMerging){throw 'Missing firewall merge requirements object.'}
    foreach($group in @(@($Profile.Services | Group-Object Name),@($Profile.Network | Group-Object Protocol,Port))){foreach($duplicate in $group){if($duplicate.Count -gt 1){throw 'Duplicate service or network requirement.'}}}
    if(@($Profile.AdminIdentities).Count -ne @($Profile.Administrators.Values).Count){throw 'Administrator resolution metadata must match the approved names.'}
    foreach($identity in @($Profile.AdminIdentities)){
        if($Profile.Administrators.Values -inotcontains $identity.Name -or $identity.Resolved -isnot [bool] -or ($identity.Resolved -and $identity.Sid -notmatch '^S-\d-(?:\d+-)+\d+$')){throw 'Invalid administrator identity metadata.'}
    }
    foreach($service in @($Profile.Services)){
        if(-not $service.Name -or $service.State -notin @('Running','Stopped','Unknown') -or $service.Startup -notin @('Auto','Manual','Disabled','Unknown')){throw 'Invalid required service entry.'}
    }
    if($Profile.NetworkKnown -isnot [bool] -or $Profile.NetworkComplete -isnot [bool]){throw 'Invalid network completeness metadata.'}
    if(-not $Profile.NetworkKnown -and ($Profile.NetworkComplete -or @($Profile.Network).Count)){throw 'Unknown network requirements cannot be complete/nonempty.'}
    foreach($rule in @($Profile.Network)){
        if($rule.Protocol -notin @('TCP','UDP') -or $rule.Port -isnot [ValueType] -or $rule.Port -is [bool] -or [double]$rule.Port -ne [math]::Truncate([double]$rule.Port) -or [double]$rule.Port -lt 1 -or [double]$rule.Port -gt 65535 -or $rule.SourcesKnown -isnot [bool] -or $rule.Required -isnot [bool]){throw 'Invalid network requirement.'}
        if($rule.SourcesKnown -and -not @($rule.Sources).Count){throw 'Known source scope must include IPs/CIDRs or Any.'}
        foreach($source in @($rule.Sources)){if($null -eq (ConvertTo-AddressRange $source)){throw ('Invalid address/CIDR: '+$source)}}
    }
    foreach($p in @('Domain','Private','Public')){if($null -ne $Profile.LocalRuleMerging.$p -and $Profile.LocalRuleMerging.$p -isnot [bool]){throw 'Firewall merge requirements must be true, false or null.'}}
    foreach($entry in @($Profile.Exceptions)){if(-not $entry.Identity -or -not $entry.Reason -or $entry.Identity -match '[*?]'){throw 'Exceptions require an exact artifact identity and a reason.'}}
    return $true
}
function Show-IntentSummary {
    param([object]$Profile)
    Write-Host "`nINTENDED CONFIGURATION - operator answers, not discovered approvals" -ForegroundColor Cyan
    foreach($name in @('Roles','Administrators','ManagementTools','ExpectedTasks','DefenderExclusions','SqlAdministrators')){
        $list=$Profile.$name
        $state=if(-not $list.Known){'UNKNOWN'}elseif(-not @($list.Values).Count){'NONE'}else{@($list.Values) -join ', '}
        Write-Host ('{0}: {1} (complete={2})' -f $name,$state,$list.Complete)
    }
    foreach($s in @($Profile.Services)){Write-Host ('Service {0}: state={1}; startup={2}; account={3}' -f $s.Name,$s.State,$s.Startup,$s.Account)}
    if(-not $Profile.NetworkKnown){Write-Host 'Inbound requirements: UNKNOWN'}
    foreach($r in @($Profile.Network)){$sources=if($r.SourcesKnown){$r.Sources -join ', '}else{'UNKNOWN'};Write-Host ('Inbound {0}:{1}: sources={2}; listener required={3}' -f $r.Protocol,$r.Port,$sources,$r.Required)}
    Write-Host ('Complete inbound port list: '+$Profile.NetworkComplete)
    Write-Host ('Local rule merging: Domain={0}; Private={1}; Public={2}' -f $Profile.LocalRuleMerging.Domain,$Profile.LocalRuleMerging.Private,$Profile.LocalRuleMerging.Public)
    Write-Host ('Baseline: '+$Profile.BaselinePath)
    Write-Host 'Declared exceptions annotate evidence; they never suppress findings.'
}
function New-IntentWizard {
    param([object]$Discovery)
    Write-Host "`nWINDOWS SERVER TRIAGE SETUP" -ForegroundColor Cyan
    Write-Host ($Discovery.Computer+' | '+$Discovery.Caption+' | '+$Discovery.Role+' | build '+$Discovery.Build)
    Write-Host ('Detected role candidates: '+($Discovery.DetectedRoles -join ', '))
    Write-Host 'Discovery is not approval. Enter unknown when unsure; none means explicitly none.'
    $roles=Read-IntentList 'Intended roles (SQL, IIS, FileServer, DNS, DomainController, Other)'
    $candidates=@($Discovery.Services | Where-Object {$_.Name -match '^(MSSQLSERVER|MSSQL\$.+|SQLSERVERAGENT|SQLAgent\$.+|W3SVC|WAS|LanmanServer|DNS|NTDS|Kdc|Netlogon|ADWS|MpsSvc|WinDefend|Sense)$'} | Sort-Object Name)
    Write-Host "`nREQUIRED SERVICES"
    for($i=0;$i -lt $candidates.Count;$i++){Write-Host ('{0}. {1} [{2}] - {3}, {4}' -f ($i+1),$candidates[$i].DisplayName,$candidates[$i].Name,$candidates[$i].State,$candidates[$i].StartMode)}
    $services=@()
    while($true){
        $selection=Ask-Text 'Required services: numbers or exact service names, comma-separated; ? lists all; Enter=unknown'
        if($selection -ne '?'){break}
        $Discovery.Services | Sort-Object Name | Format-Table Name,DisplayName,State -AutoSize | Out-Host
    }
    if($selection -and $selection -notin @('unknown','none','u')){
        foreach($token in @($selection -split ',' | ForEach-Object {$_.Trim()} | Where-Object {$_} | Select-Object -Unique)){
            $name=$token
            if($token -match '^\d+$'){
                if([int]$token -lt 1 -or [int]$token -gt $candidates.Count){throw 'Selected service number is out of range. Restart setup.'}
                $name=$candidates[[int]$token-1].Name
            }
            if(-not @($Discovery.Services | Where-Object Name -eq $name).Count){Write-Host ('Not discovered: '+$name+'. It will be treated as an expected missing service, subject to collection coverage.')}
            do {$state=Ask-Text ($name+' expected state [r=running/s=stopped/u=unknown; Enter=running]')}while($state -notin @('','r','s','u'))
            $state=switch($state){'s'{'Stopped'}'u'{'Unknown'}default{'Running'}}
            do {$startup=Ask-Text ($name+' expected startup [a=automatic/m=manual/d=disabled/u=unknown; Enter=unknown]')}while($startup -notin @('','a','m','d','u'))
            $startup=switch($startup){'a'{'Auto'}'m'{'Manual'}'d'{'Disabled'}default{'Unknown'}}
            $account=Ask-Text ($name+' expected service account [Enter=unknown]')
            $services+=[pscustomobject]@{Name=$name;State=$state;Startup=$startup;Account=$account}
        }
    }
    Write-Host "`nEXPECTED INBOUND ACCESS"
    Write-Host 'Use individual ports such as TCP:1433,TCP:3389,UDP:53. Include dynamic/RPC requirements only if you know the intended complete port list.'
    $network=@();$networkKnown=$false;$networkComplete=$false
    while($true){
        $ports=Ask-Text 'Expected inbound ports [none; Enter=unknown]'
        if(-not $ports -or $ports -in @('unknown','u')){break}
        if($ports -ieq 'none'){$networkKnown=$true;$networkComplete=$true;break}
        $tokens=@($ports -split ',' | ForEach-Object {$_.Trim().ToUpperInvariant()} | Select-Object -Unique)
        if(@($tokens | Where-Object {$_ -notmatch '^(TCP|UDP):\d+$' -or [int]($_ -split ':')[1] -lt 1 -or [int]($_ -split ':')[1] -gt 65535}).Count){Write-Host 'Invalid port list. Try again.';continue}
        $networkKnown=$true
        foreach($token in $tokens){
            $parts=$token -split ':';$sources=@();$sourcesKnown=$false
            while($true){
                $text=Ask-Text ($token+' allowed source IPs/CIDRs, comma-separated; Any; Enter=unknown')
                if(-not $text -or $text -in @('unknown','u')){break}
                $sources=@($text -split ',' | ForEach-Object {$_.Trim()} | Select-Object -Unique)
                if(@($sources | Where-Object {$null -eq (ConvertTo-AddressRange $_)}).Count){Write-Host 'Use IP addresses, CIDRs or Any.';continue}
                $sourcesKnown=$true;break
            }
            $required=Ask-TriState ($token+' should have a listening service now')
            $network+=[pscustomobject]@{Protocol=$parts[0];Port=[int]$parts[1];SourcesKnown=$sourcesKnown;Sources=$sources;Required=($required -eq $true)}
        }
        $networkComplete=((Ask-TriState 'Is that the COMPLETE approved inbound port list') -eq $true);break
    }
    Write-Host "`nACCESS AND APPROVED TOOLS"
    if($Discovery.AdminMembers.Count){$Discovery.AdminMembers | Format-Table Name,Sid -AutoSize | Out-Host}
    $admins=Read-IntentList 'Approved direct Administrators members (DOMAIN\name, COMPUTER\name or SID)'
    $identities=@();foreach($name in $admins.Values){$resolved=Resolve-IntentIdentity $name;$identities+=$resolved;if(-not $resolved.Resolved){Write-Host ('Could not resolve '+$name+' to a SID; unmatched membership checks will remain uncertain.')}}
    $tools=Read-IntentList 'Approved management tool names (for context only; e.g. Automox, CrowdStrike)'
    $tasks=Read-IntentList 'Approved custom task FULL paths (e.g. \Company\Backup); skip if unsure'
    $exclusions=Read-IntentList 'Approved Defender exclusions as Type|Value (e.g. ExclusionPath|C:\Data); skip if unsure'
    $merging=[ordered]@{}
    foreach($name in @('Domain','Private','Public')){$merging[$name]=Ask-TriState ('Must local firewall rules apply on the '+$name+' profile')}
    $sqlAdmins=Read-IntentList 'Approved SQL sysadmin login names across local instances; skip if unsure'
    $exceptions=@()
    Write-Host 'Optional exception annotations use an exact artifact identity, such as Task:\Company\Backup or Service:Example. They do not suppress detection.'
    while($true){$id=Ask-Text 'Exception identity [Enter=done]';if(-not $id){break};$reason=Ask-Text 'Business reason';if($reason -and $id -notmatch '[*?]'){$exceptions+=[pscustomobject]@{Identity=$id;Reason=$reason}}else{Write-Host 'Exact identity and a reason are required.'}}
    $baseline=Ask-Text 'Optional baseline from this focused triage version [Enter=skip]'
    $profile=[pscustomobject]@{Schema='WindowsServerAudit.Intent';Version=1;CreatedUtc=(Get-Date).ToUniversalTime().ToString('o');Computer=$Discovery.Computer;Roles=$roles;Services=$services;NetworkKnown=$networkKnown;NetworkComplete=$networkComplete;Network=$network;Administrators=$admins;AdminIdentities=$identities;ManagementTools=$tools;ExpectedTasks=$tasks;DefenderExclusions=$exclusions;LocalRuleMerging=[pscustomobject]$merging;SqlAdministrators=$sqlAdmins;Exceptions=$exceptions;BaselinePath=$baseline}
    $null=Test-IntentProfile $profile
    return $profile
}

function New-Observation {
    param([string]$Identity,[string]$Type,[string]$Name,[string]$Command,[string]$Account,[string]$Collection,[object]$Details,[int[]]$ProcessIds=@())
    [pscustomobject]@{Identity=$Identity;Type=$Type;Name=$Name;Command=$Command;Account=$Account;Collection=$Collection;Details=$Details;ProcessIds=$ProcessIds;Evidence=$Collection+': '+$Name}
}
function Add-Coverage {
    param([string]$Name,[string]$Status,[string]$Detail,[bool]$Complete=$false)
    $script:Coverage.Add([pscustomobject]@{Name=$Name;Status=$Status;Detail=$Detail;Complete=$Complete;TimeUtc=(Get-Date).ToUniversalTime().ToString('o')})
}
# A failed enumeration is a coverage gap, never an empty collection certified as complete.
function Collect-Read {
    param([string]$Name,[scriptblock]$Read)
    try {$result=@(& $Read);Add-Coverage $Name 'Collected' ($result.Count.ToString()+' entries') $true;return $result}
    catch {Add-Coverage $Name 'Unavailable' $_.Exception.Message $false;return @()}
}
function Is-Collected {
    param([string]$Name)
    $latest=$script:Coverage | Where-Object Name -eq $Name | Select-Object -Last 1
    return ($null -ne $latest -and $latest.Complete -eq $true)
}
# Resolve evidence text conservatively; never run it or search an attacker-controlled PATH.
function Resolve-ObservedPath {
    param([string]$Path,[string]$WorkingDirectory='')
    $p=[Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"').Trim("'"))
    if($p.StartsWith('\??\')){$p=$p.Substring(4)}
    if($p.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)){$p=$env:windir+$p.Substring(11)}
    # Do not touch UNC/device paths or resolve names through untrusted PATH entries.
    if($p.StartsWith('\\') -or $p -match '^[a-z]+://'){return ''}
    if($p -match '^[A-Za-z]:\\'){
        try {return [IO.Path]::GetFullPath($p)}catch{return ''}
    }
    if($WorkingDirectory -match '^[A-Za-z]:\\' -and $p -notmatch '[:\\]'){
        return [IO.Path]::GetFullPath((Join-Path $WorkingDirectory $p))
    }
    if($p -notmatch '[:\\]'){
        if($p -notmatch '\.[A-Za-z0-9]+$'){$p+='.exe'}
        foreach($folder in @((Join-Path $env:windir 'System32'),$env:windir,(Join-Path $env:windir 'System32\WindowsPowerShell\v1.0'),(Join-Path $env:ProgramFiles 'PowerShell\7'))){
            $candidate=Join-Path $folder $p;if(Test-Path -LiteralPath $candidate -PathType Leaf){return $candidate}
        }
    }
    return ''
}
function Get-CommandPaths {
    param([string]$Command,[string]$WorkingDirectory='')
    $expanded=[Environment]::ExpandEnvironmentVariables($Command.Trim());$exe='';$paths=New-Object 'System.Collections.Generic.List[string]'
    if($expanded -match '^"([^"]+)"'){$exe=$matches[1]}
    elseif($expanded -match '(?i)^(.+?\.(?:exe|com|sys|dll))(?=\s|$)'){$exe=$matches[1]}
    elseif($expanded -match '^(\S+)'){$exe=$matches[1]}
    $resolved=Resolve-ObservedPath $exe $WorkingDirectory;if($resolved){$paths.Add($resolved)}
    foreach($pattern in @('(?i)"([A-Z]:\\[^"]+\.(?:ps1|cmd|bat|vbs|js|dll))"','(?i)([A-Z]:\\[^\s"'']+\.(?:ps1|cmd|bat|vbs|js|dll))(?=\s|$|["''])')){
        foreach($match in [regex]::Matches($expanded,$pattern)){$p=Resolve-ObservedPath $match.Groups[1].Value;if($p){$paths.Add($p)}}
    }
    [pscustomobject]@{Executable=$resolved;Paths=@($paths | Select-Object -Unique);UnquotedSpaces=($exe -match '\s' -and -not $expanded.StartsWith('"'));RemoteReference=($expanded -match '(?i)(?:^|[\s"''])\\\\[^\\\s]+\\')}
}
# Identify broad-principal allow grants and retain deny ambiguity. This is not a full AccessCheck.
function Get-BroadAclSignals {
    param([object[]]$Aces,[ValidateSet('File','Directory','Service')][string]$Kind,[bool]$NullDacl=$false)
    if($NullDacl){return ,([pscustomobject]@{Code='NullDacl';Weight=40;Text=$Kind+' has a null DACL; access is not restricted by a discretionary ACL.'})}
    $danger=if($Kind -eq 'Service'){[long]0x500D0002}elseif($Kind -eq 'Directory'){[long]0x500D0046}else{[long]0x500D0006}
    $broad=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546')
    foreach($ace in $Aces){
        if($ace.InheritOnly -or $ace.Type -ne 'Allow'){continue}
        if($ace.Sid -notin $broad -and $ace.Sid -notmatch '^S-1-5-21-(?:\d+-){2}\d+-513$'){continue}
        $mask=[long]$ace.Mask;if($mask -lt 0){$mask+=4294967296}
        if(($mask -band $danger) -eq 0){continue}
        $denies=@($Aces | Where-Object {$_.Type -eq 'Deny' -and -not $_.InheritOnly -and (([long]$_.Mask -band $danger) -ne 0)})
        $ambiguous=$ace.Conditional -or $denies.Count -gt 0
        $weight=if($ambiguous){10}elseif($Kind -eq 'Directory'){20}else{35}
        $text=$Kind+' grants potentially dangerous rights to '+$ace.Sid+'; mask='+$mask+'; inherited='+$ace.Inherited+'. '
        $text+=if($ambiguous){'Deny/conditional entries also exist; effective access requires validation.'}else{'Broad allow ACE observed. Full effective-token/group access is not established.'}
        [pscustomobject]@{Code=('Broad'+$Kind+'Rights');Weight=$weight;Text=$text}
    }
}
function Read-FileAces {
    param([string]$Path)
    $acl=Get-Acl -LiteralPath $Path
    $aces=@()
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        $aces+=[pscustomobject]@{Sid=$rule.IdentityReference.Value;Type=[string]$rule.AccessControlType;Mask=[long]$rule.FileSystemRights;Inherited=$rule.IsInherited;InheritOnly=(([int]$rule.PropagationFlags -band 2) -ne 0);Conditional=$false}
    }
    $raw=New-Object Security.AccessControl.RawSecurityDescriptor($acl.Sddl)
    [pscustomobject]@{Sddl=$acl.Sddl;Aces=$aces;NullDacl=($null -eq $raw.DiscretionaryAcl)}
}
# Skip remote/mapped drives and reparse paths before inspecting referenced file content.
function Assert-LocalReadPath {
    param([string]$Path)
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')){throw 'Only ordinary local drive paths are inspected.'}
    $root=[IO.Path]::GetPathRoot($Path)
    $drive=New-Object IO.DriveInfo($root)
    if($drive.DriveType -ne [IO.DriveType]::Fixed){throw 'Only fixed local drives are inspected; mapped/network/removable drives are skipped.'}
    $part=$root
    foreach($segment in @($Path.Substring($root.Length) -split '\\' | Where-Object {$_})){
        $part=[IO.Path]::Combine($part,$segment)
        $item=Get-Item -LiteralPath $part -Force -ErrorAction Stop
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse-point paths are not followed.'}
    }
}
function Get-FileEvidence {
    param([string]$Path)
    if($script:Files.ContainsKey($Path)){return $script:Files[$Path]}
    $fact=[pscustomobject]@{Path=$Path;Status='Unavailable';Length=$null;Sha256='';SignatureStatus='Unknown';Signer='';LastWriteUtc='';Acl=$null;ParentAcl=$null;Errors=@();ContentSignals=@()}
    $script:Files[$Path]=$fact
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.StartsWith('\\')){$fact.Errors+= 'Only local drive paths are inspected.';return $fact}
    try {
        Assert-LocalReadPath $Path
        $file=Get-Item -LiteralPath $Path -Force
        if($file.PSIsContainer){throw 'Path is a directory.'}
        if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse-point files are not followed.'}
        $fact.Length=$file.Length;$fact.LastWriteUtc=$file.LastWriteTimeUtc.ToString('o');$fact.Status='Observed'
        if($file.Length -le ($MaxFileSizeMB*1MB)){$fact.Sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}else{$fact.Errors+='Hash skipped: size limit.'}
        try {$signature=Get-AuthenticodeSignature -LiteralPath $Path;$fact.SignatureStatus=[string]$signature.Status;if($signature.SignerCertificate){$fact.Signer=$signature.SignerCertificate.Subject}}catch{$fact.Errors+='Signature: '+$_.Exception.Message}
        try {$fact.Acl=Read-FileAces $Path}catch{$fact.Errors+='File ACL: '+$_.Exception.Message}
        try {$fact.ParentAcl=Read-FileAces $file.DirectoryName}catch{$fact.Errors+='Parent ACL: '+$_.Exception.Message}
        if($file.Extension -in @('.ps1','.cmd','.bat','.vbs','.js','.wsf') -and $file.Length -le 262144){
            try {$text=Get-Content -LiteralPath $Path -Raw;$fact.ContentSignals=@(Get-TextSignals $text)}catch{$fact.Errors+='Script read: '+$_.Exception.Message}
        }
    } catch {$fact.Errors+= $_.Exception.Message}
    return $fact
}
function Get-TextSignals {
    param([string]$Text)
    if($Text -match '(?is)\b(?:powershell|pwsh)(?:\.exe)?["'']?\s+(?:.*?\s)?-(?:enc(?:odedcommand)?|e)\s'){
        [pscustomobject]@{Code='EncodedPowerShell';Weight=30;Text='Encoded PowerShell arguments; command was not decoded or executed.'}
    }
    if($Text -match '(?is)(?:\b(?:iex|Invoke-Expression)\b.{0,200}(?:DownloadString|https?://)|(?:DownloadString|Invoke-WebRequest).{0,400}\|\s*(?:iex|Invoke-Expression))'){
        [pscustomobject]@{Code='DownloadAndExecute';Weight=35;Text='Text resembles download-and-execute behavior; manual review required.'}
    }
    if($Text -match '(?i)\b(?:xp_cmdshell|sp_OACreate)\b'){
        [pscustomobject]@{Code='SqlOsExecution';Weight=25;Text='SQL OS-execution functionality referenced; verify approved job/procedure purpose.'}
    }
}
# Associate observed PIDs/paths. Association is supporting evidence, not launch attribution.
function Get-LinkedProcesses {
    param([object]$Artifact,[object[]]$Processes,[object]$CommandPaths)
    $interpreters=@('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','rundll32.exe','regsvr32.exe','svchost.exe','dllhost.exe','mshta.exe')
    foreach($p in $Processes){
        if($Artifact.Type -eq 'Process'){
            if(@($Artifact.ProcessIds) -contains [int]$p.ProcessId){$p};continue
        }
        if($Artifact.Type -eq 'Service' -and @($Artifact.ProcessIds) -contains [int]$p.ProcessId){
            if($p.ExecutablePath -and $CommandPaths.Executable -and $p.ExecutablePath -ieq $CommandPaths.Executable){$p}
            continue
        }
        if($Artifact.Type -eq 'Service'){continue}
        if($CommandPaths.Executable -and $p.ExecutablePath -ieq $CommandPaths.Executable -and [IO.Path]::GetFileName($p.ExecutablePath) -notin $interpreters){$p;continue}
        $scriptPaths=@($CommandPaths.Paths | Where-Object {$_ -ine $CommandPaths.Executable})
        foreach($path in $scriptPaths){if($p.CommandLine -and $p.CommandLine -match ('(?i)(?:^|[\s"''])'+[regex]::Escape($path)+'(?=$|[\s"''])')){$p;break}}
    }
}
# Combine explicit signals, keeping operator tool names and exceptions as annotations only.
function Get-ArtifactAssessment {
    param([object]$Artifact,[object]$Intent,[object[]]$Processes,[object[]]$Connections)
    $signals=New-Object 'System.Collections.Generic.List[object]'
    foreach($signal in @(Get-TextSignals $Artifact.Command)){$signals.Add($signal)}
    $working='';if($Artifact.Details -and $Artifact.Details.PSObject.Properties['WorkingDirectory']){$working=[string]$Artifact.Details.WorkingDirectory}
    $paths=Get-CommandPaths $Artifact.Command $working
    if($Artifact.Type -eq 'Task'){
        $allPaths=@();foreach($action in @($Artifact.Details.Actions)){if($action.Execute){$actionPaths=Get-CommandPaths ('"'+$action.Execute+'" '+$action.Arguments) ([string]$action.WorkingDirectory);$allPaths+=@($actionPaths.Paths);if($actionPaths.RemoteReference){$paths.RemoteReference=$true}}}
        $paths.Paths=@($allPaths | Select-Object -Unique)
    }
    if($Artifact.Type -eq 'Process' -and $Artifact.Details.Image){$image=Resolve-ObservedPath $Artifact.Details.Image;if($image){$paths.Executable=$image;$paths.Paths=@(@($paths.Paths)+@($image) | Select-Object -Unique)}}
    if($paths.RemoteReference){$signals.Add([pscustomobject]@{Code='RemoteExecutionReference';Weight=30;Text='Execution entry references a UNC path. Remote files were not accessed.'})}
    if($Artifact.Type -eq 'Service' -and $paths.UnquotedSpaces){$signals.Add([pscustomobject]@{Code='UnquotedServicePath';Weight=10;Text='Unquoted service executable path contains spaces; exploitability depends on intermediate paths and permissions.'})}
    foreach($path in $paths.Paths){
        $fact=Get-FileEvidence $path
        if($path -match '(?i)\\(?:Users\\[^\\]+\\(?:AppData|Downloads|Desktop|Public)|Users\\Public|Windows\\Temp|Temp)\\'){$signals.Add([pscustomobject]@{Code='UnusualExecutionPath';Weight=25;Text='Execution references '+$path+'; verify purpose and permissions.'})}
        if([IO.Path]::GetFileName($path) -in @('svchost.exe','lsass.exe','services.exe','winlogon.exe','spoolsv.exe') -and (Split-Path -Parent $path) -inotmatch ('^'+[regex]::Escape($env:windir)+'\\(?:System32|SysWOW64)$')){$signals.Add([pscustomobject]@{Code='SystemNameUnexpectedPath';Weight=30;Text='Windows-like executable name outside its usual system directories: '+$path})}
        if($fact.Status -ne 'Observed'){continue}
        if($fact.SignatureStatus -eq 'HashMismatch'){$signals.Add([pscustomobject]@{Code='SignatureHashMismatch';Weight=35;Text='Authenticode reports a hash mismatch: '+$path})}
        if($fact.SignatureStatus -eq 'NotSigned' -and @($signals | Where-Object {$_.Weight -ge 25}).Count){$signals.Add([pscustomobject]@{Code='UnsignedCorroboration';Weight=10;Text='Referenced file is unsigned: '+$path+'; unsigned alone is not a malware verdict.'})}
        if($fact.Acl){foreach($signal in @(Get-BroadAclSignals $fact.Acl.Aces 'File' -NullDacl:$fact.Acl.NullDacl)){$signals.Add($signal)}}
        if($fact.ParentAcl){foreach($signal in @(Get-BroadAclSignals $fact.ParentAcl.Aces 'Directory' -NullDacl:$fact.ParentAcl.NullDacl)){$signals.Add($signal)}}
        foreach($signal in $fact.ContentSignals){$signals.Add($signal)}
    }
    if($Artifact.Type -eq 'Service' -and $Artifact.Details.PSObject.Properties['Aces']){
        foreach($signal in @(Get-BroadAclSignals $Artifact.Details.Aces 'Service' -NullDacl:$Artifact.Details.NullDacl)){$signals.Add($signal)}
    }
    if($Artifact.Type -eq 'WmiConsumer'){$signals.Add([pscustomobject]@{Code='WmiConsumer';Weight=15;Text='Permanent WMI consumer observed; verify its trigger/bindings and purpose.'})}
    if($Artifact.Type -eq 'SqlStartupProcedure'){$signals.Add([pscustomobject]@{Code='SqlStartupProcedure';Weight=20;Text='Procedure configured for startup execution; verify its owner and definition.'})}
    $linked=@(Get-LinkedProcesses $Artifact $Processes $paths | Sort-Object ProcessId -Unique)
    $network=@()
    foreach($p in $linked){$network+=@($Connections | Where-Object {[int]$_.OwningProcess -eq [int]$p.ProcessId -and $_.State -eq 'Established' -and $_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::')})}
    if($signals.Count -and (Canonical-Account $Artifact.Account $Intent.Computer) -eq 's-1-5-18'){$signals.Add([pscustomobject]@{Code='SystemContext';Weight=10;Text='Entry runs as SYSTEM; privilege alone was not used to generate this lead.'})}
    if($signals.Count -and $network.Count){$signals.Add([pscustomobject]@{Code='NetworkCorroboration';Weight=10;Text='Associated process has non-loopback established TCP connections; destination intent is not established.'})}
    $unique=@($signals | Group-Object Code | ForEach-Object {$_.Group | Sort-Object Weight -Descending | Select-Object -First 1})
    $score=0;foreach($signal in $unique){$score+=[int]$signal.Weight};$score=[Math]::Min(100,$score)
    $tools=@($Intent.ManagementTools.Values | Where-Object {([string]$Artifact.Command).IndexOf($_,[StringComparison]::OrdinalIgnoreCase) -ge 0})
    $exceptions=@($Intent.Exceptions | Where-Object Identity -eq $Artifact.Identity)
    [pscustomobject]@{Identity=$Artifact.Identity;Type=$Artifact.Type;Name=$Artifact.Name;Score=$score;Priority=$(if($score -ge 55){'High'}elseif($score -ge 25){'Medium'}else{'Low'});Signals=$unique;Paths=$paths.Paths;LinkedProcesses=$linked;Connections=$network;ManagementContext=$tools;Exceptions=$exceptions;Source=$Artifact.Evidence;Command=$Artifact.Command;Account=$Artifact.Account}
}

function Get-Discovery {
    $os=Get-CimInstance Win32_OperatingSystem;$computer=Get-CimInstance Win32_ComputerSystem
    if([int]$os.ProductType -eq 1){throw 'Run on Windows Server.'}
    $year=@{'14393'='2016';'17763'='2019';'20348'='2022';'26100'='2025'}[[string]$os.BuildNumber]
    if(-not $year){throw ('Unsupported Server base build '+$os.BuildNumber)}
    $services=@(Collect-Read 'Services' {Get-CimInstance Win32_Service})
    $role=if([int]$computer.DomainRole -in @(4,5)){'Domain Controller'}elseif($computer.PartOfDomain){'Member Server'}else{'Standalone'}
    $roles=@();if($role -eq 'Domain Controller'){$roles+='DomainController'}
    if(@($services | Where-Object {$_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*'}).Count){$roles+='SQL'}
    if(@($services | Where-Object Name -eq 'W3SVC').Count){$roles+='IIS'}
    if(@($services | Where-Object Name -eq 'DNS').Count){$roles+='DNS'}
    if(@($services | Where-Object Name -eq 'LanmanServer').Count){$roles+='FileServer (service present; role needs confirmation)'}
    $ubr=Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR
    [pscustomobject]@{Computer=$env:COMPUTERNAME;Caption=$os.Caption;Year=$year;Build=([string]$os.BuildNumber+'.'+$ubr);Role=$role;EditionSku=[int]$os.OperatingSystemSKU;Architecture=$os.OSArchitecture;Services=$services;DetectedRoles=$roles;AdminMembers=@()}
}
function Get-LiveEvidence {
    param([string]$Stage)
    $processes=@(Collect-Read ('Processes/'+$Stage) {Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate})
    $tcp=@(Collect-Read ('TCP/'+$Stage) {Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime})
    $udp=@(Collect-Read ('UDP/'+$Stage) {Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess})
    [pscustomobject]@{CapturedUtc=(Get-Date).ToUniversalTime().ToString('o');Processes=$processes;Tcp=$tcp;Udp=$udp}
}
# GetSecurityDescriptor is the read-only CIM method; no service control method is called.
function Get-ServiceObservations {
    param([object[]]$Services)
    foreach($service in $Services){
        $aces=@();$nullDacl=$false;$sdStatus='Unknown';$dll=''
        try {
            $sd=Invoke-CimMethod -InputObject $service -MethodName GetSecurityDescriptor
            if($sd.ReturnValue -ne 0 -or -not $sd.Descriptor){throw ('GetSecurityDescriptor returned '+$sd.ReturnValue)}
            $nullDacl=($null -eq $sd.Descriptor.DACL -or (([int]$sd.Descriptor.ControlFlags -band 4) -eq 0))
            foreach($ace in @($sd.Descriptor.DACL)){
                $aces+=[pscustomobject]@{Sid=$ace.Trustee.SIDString;Type=$(if($ace.AceType -eq 0){'Allow'}elseif($ace.AceType -eq 1){'Deny'}else{'Other'});Mask=[long]$ace.AccessMask;Inherited=(([int]$ace.AceFlags -band 16) -ne 0);InheritOnly=(([int]$ace.AceFlags -band 8) -ne 0);Conditional=($ace.AceType -notin @(0,1))}
            }
            $sdStatus='Read'
        } catch {Add-Coverage ('ServiceACL/'+$service.Name) 'Unavailable' $_.Exception.Message}
        try {$dll=[string](Get-ItemPropertyValue -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$service.Name+'\Parameters') -Name ServiceDll -ErrorAction Stop)}catch{}
        $command=[string]$service.PathName;if($dll){$command+=' "'+[Environment]::ExpandEnvironmentVariables($dll)+'"'}
        $details=[pscustomobject]@{State=$service.State;Startup=$service.StartMode;ImagePath=$service.PathName;ServiceDll=$dll;Aces=$aces;NullDacl=$nullDacl;AclStatus=$sdStatus}
        New-Observation ('Service:'+$service.Name) 'Service' $service.Name $command $service.StartName 'Services' $details @([int]$service.ProcessId)
    }
}
function Get-TaskObservations {
    $tasks=@(Collect-Read 'Tasks' {Get-ScheduledTask})
    foreach($task in $tasks){
        $id=$task.TaskPath+$task.TaskName;$commands=@();$work=''
        foreach($action in @($task.Actions)){
            if($action.PSObject.Properties['Execute']){$commands+=('"'+$action.Execute+'" '+$action.Arguments);$work=[string]$action.WorkingDirectory}
            elseif($action.PSObject.Properties['ClassId']){$commands+=('COM handler '+$action.ClassId);Add-Coverage ('TaskCOM/'+$id) 'Partial' 'COM handler identity collected; CLSID registration and handler binary not resolved.'}
        }
        $details=[pscustomobject]@{WorkingDirectory=$work;Actions=@($task.Actions | Select-Object Execute,Arguments,WorkingDirectory,ClassId,Data);Enabled=$task.Settings.Enabled;Triggers=@($task.Triggers | Select-Object Enabled,StartBoundary,EndBoundary,Delay,DaysInterval,DaysOfWeek,WeeksInterval);LogonType=[string]$task.Principal.LogonType;RunLevel=[string]$task.Principal.RunLevel}
        $account=if($task.Principal.UserId){[string]$task.Principal.UserId}else{[string]$task.Principal.GroupId}
        New-Observation ('Task:'+$id) 'Task' $id ($commands -join ' ; ') $account 'Tasks' $details
    }
}
function Get-StartupObservations {
    # Machine keys and already-loaded user hives only. No hives are loaded.
    foreach($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)){
        foreach($hiveName in @('LocalMachine','Users')){
            $base=$null
            try {
                $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$hiveName,$view)
                $prefixes=if($hiveName -eq 'Users'){@($base.GetSubKeyNames() | Where-Object {$_ -match '^S-1-5-21-[\d-]+$'})}else{@('')}
                foreach($prefix in $prefixes){
                    foreach($tail in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce')){
                        $subkey=if($prefix){$prefix+'\'+$tail}else{$tail};$key=$null
                        try {
                            $key=$base.OpenSubKey($subkey);if(-not $key){continue}
                            foreach($name in $key.GetValueNames()){
                                $command=[string]$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                                $id=$hiveName+'|'+$view+'|'+$subkey+'|'+$name
                                New-Observation ('Startup:'+$id) 'Startup' $id $command $prefix 'StartupRegistry' ([pscustomobject]@{Location=$subkey;ValueName=$name;Value=$command})
                            }
                        }catch{Add-Coverage ('StartupRegistry/'+$subkey) 'Unavailable' $_.Exception.Message}finally{if($key){$key.Close()}}
                    }
                }
            }catch{Add-Coverage 'StartupRegistry' 'Partial' $_.Exception.Message}finally{if($base){$base.Close()}}
        }
    }
    Add-Coverage 'StartupRegistry' 'Partial' 'Machine Run/RunOnce and loaded user hives only; other users are not assumed empty.'
    $folders=@([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonStartup),[Environment]::GetFolderPath([Environment+SpecialFolder]::Startup)) | Select-Object -Unique
    foreach($folder in $folders){
        if(-not $folder){continue}
        try {
            if(-not (Test-Path -LiteralPath $folder)){continue}
            Assert-LocalReadPath $folder
            foreach($file in @(Get-ChildItem -LiteralPath $folder -Force -File)){
                Assert-LocalReadPath $file.FullName
                $command='"'+$file.FullName+'"'
                if($file.Extension -ieq '.lnk'){
                    try {$shell=$null;$link=$null;$shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut($file.FullName);$command='"'+$link.TargetPath+'" '+$link.Arguments}finally{if($link){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($link)};if($shell){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)}}
                }
                New-Observation ('StartupFile:'+$file.FullName) 'Startup' $file.Name $command '' 'StartupFolders' ([pscustomobject]@{Shortcut=$file.FullName;Length=$file.Length})
            }
        }catch{Add-Coverage 'StartupFolders' 'Partial' $_.Exception.Message}
    }
    foreach($path in @((Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\profile.ps1'),(Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1'),(Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\profile.ps1'),(Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'))){
        if($path -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $path -PathType Leaf)){New-Observation ('PowerShellProfile:'+$path) 'PowerShellProfile' $path ('powershell.exe -File "'+$path+'"') '' 'PowerShellProfiles' ([pscustomobject]@{Path=$path})}
    }
    Add-Coverage 'StartupFolders/Profiles' 'Partial' 'Common/current-user Startup folders and Windows PowerShell profiles; nested folders and other unloaded profiles are not enumerated.'
}
function Get-WmiObservations {
    $filters=@(Collect-Read 'WMI/Filters' {Get-CimInstance -Namespace root/subscription -ClassName __EventFilter})
    $bindings=@(Collect-Read 'WMI/Bindings' {Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding})
    foreach($class in @('CommandLineEventConsumer','ActiveScriptEventConsumer')){
        foreach($consumer in @(Collect-Read ('WMI/'+$class) {Get-CimInstance -Namespace root/subscription -ClassName $class})){
            $command=if($class -eq 'CommandLineEventConsumer'){$consumer.ExecutablePath+' '+$consumer.CommandLineTemplate}else{[string]$consumer.ScriptText}
            $related=@($bindings | Where-Object {([string]$_.Consumer).IndexOf([string]$consumer.Name,[StringComparison]::OrdinalIgnoreCase) -ge 0} | Select-Object Consumer,Filter)
            New-Observation ('WMI:'+$class+'/'+$consumer.Name) 'WmiConsumer' $consumer.Name $command '' ('WMI/'+$class) ([pscustomobject]@{Class=$class;Consumer=$consumer.Name;PossibleBindings=$related;BindingNote='Name-based candidate association; inspect exact WMI references to confirm.';Filters=@($filters | Select-Object Name,Query,EventNamespace)})
        }
    }
}
function Get-AdminMembers {
    param([string]$Role)
    if($Role -eq 'Domain Controller'){
        $root=$null;$group=$null;$searchRoot=$null;$searcher=$null
        try {
            $root=[ADSI]'LDAP://RootDSE';$dn=[string]$root.defaultNamingContext
            $searchRoot=[ADSI]('LDAP://'+$dn);$searcher=New-Object DirectoryServices.DirectorySearcher($searchRoot);$searcher.Filter='(objectSid=S-1-5-32-544)';$found=$searcher.FindOne();if(-not $found){throw 'AD Builtin Administrators group SID could not be located.'};$group=$found.GetDirectoryEntry();$null=$group.NativeObject
            if(@($group.Properties.PropertyNames | Where-Object {$_ -like 'member;range=*'}).Count){throw 'Ranged AD group membership is not supported; direct membership is incomplete.'}
            foreach($memberDn in @($group.Properties['member'])){
                $entry=$null
                try {$entry=[ADSI]('LDAP://'+$memberDn);$sid=New-Object Security.Principal.SecurityIdentifier([byte[]]$entry.objectSid.Value,0);[pscustomobject]@{Name=[string]$memberDn;Sid=$sid.Value;Source='AD Builtin Administrators; direct only'}}finally{if($entry){$entry.Dispose()}}
            }
        }finally{if($group){$group.Dispose()};if($searcher){$searcher.Dispose()};if($searchRoot){$searchRoot.Dispose()};if($root){$root.Dispose()}}
    } else {
        Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]'S-1-5-32-544') | ForEach-Object {[pscustomobject]@{Name=$_.Name;Sid=[string]$_.SID;Source='Local Administrators; direct only'}}
    }
}
function Get-FirewallEvidence {
    $profiles=@(Collect-Read 'FirewallProfiles' {Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,AllowLocalFirewallRules,AllowInboundRules,DefaultInboundAction,DefaultOutboundAction,DisabledInterfaceAliases})
    $networks=@(Collect-Read 'NetworkProfiles' {Get-NetConnectionProfile | Select-Object InterfaceAlias,NetworkCategory})
    $rules=@();$native=@(Collect-Read 'FirewallRuleInventory' {Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore})
    foreach($rule in @($native | Where-Object {[string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq 'Inbound'})){
        try {
            $port=$rule | Get-NetFirewallPortFilter;$address=$rule | Get-NetFirewallAddressFilter;$app=$rule | Get-NetFirewallApplicationFilter;$service=$rule | Get-NetFirewallServiceFilter
            $rules+=[pscustomobject]@{Name=$rule.Name;DisplayName=$rule.DisplayName;Action=[string]$rule.Action;Profile=[string]$rule.Profile;Protocol=[string]$port.Protocol;LocalPort=@($port.LocalPort);RemotePort=@($port.RemotePort);RemoteAddress=@($address.RemoteAddress);LocalAddress=@($address.LocalAddress);Program=$app.Program;Service=$service.Service;Source=$rule.PolicyStoreSource;SourceType=[string]$rule.PolicyStoreSourceType}
        }catch{Add-Coverage ('FirewallFilters/'+$rule.Name) 'Unavailable' $_.Exception.Message}
    }
    [pscustomobject]@{Profiles=$profiles;Networks=$networks;Rules=$rules}
}

# Open a local shared-memory connection using the current Windows identity for fixed SELECT queries.
function Invoke-SqlMetadata {
    param([string]$Instance,[string]$Database,[string]$Query)
    $builder=New-Object System.Data.SqlClient.SqlConnectionStringBuilder
    $builder.DataSource=if($Instance -eq 'MSSQLSERVER'){'lpc:.'}else{'lpc:.\'+$Instance}
    $builder.InitialCatalog=$Database;$builder.IntegratedSecurity=$true;$builder.ConnectTimeout=5;$builder.Pooling=$false;$builder.ApplicationName='WindowsServerAudit Triage ReadOnly'
    $connection=New-Object System.Data.SqlClient.SqlConnection($builder.ConnectionString);$command=$null;$reader=$null
    try {
        $connection.Open();$command=$connection.CreateCommand();$command.CommandTimeout=15;$command.CommandText=$Query;$reader=$command.ExecuteReader()
        while($reader.Read()){$row=[ordered]@{};for($i=0;$i -lt $reader.FieldCount;$i++){$row[$reader.GetName($i)]=if($reader.IsDBNull($i)){$null}else{$reader.GetValue($i)}};[pscustomobject]$row}
    }finally{if($reader){$reader.Dispose()};if($command){$command.Dispose()};$connection.Dispose()}
}
function Get-SqlObservations {
    param([object[]]$Services)
    $records=@();$artifacts=@()
    foreach($service in @($Services | Where-Object {$_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*'})){
        $instance=if($service.Name -eq 'MSSQLSERVER'){'MSSQLSERVER'}else{$service.Name.Substring(6)}
        if($SkipSql){Add-Coverage ('SQL/'+$instance) 'NotAssessed' '-SkipSql selected.';continue}
        if($service.State -ne 'Running'){Add-Coverage ('SQL/'+$instance) 'Unavailable' 'Engine not running. No service was started.';continue}
        try {
            $version=@(Invoke-SqlMetadata $instance 'master' "SELECT CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')) AS Version,CONVERT(nvarchar(128),SERVERPROPERTY('Edition')) AS Edition,IS_SRVROLEMEMBER('sysadmin') AS IsSysadmin;")
            if($version.Count -ne 1){throw 'Unexpected version response.'}
            $records+=[pscustomobject]@{Instance=$instance;Kind='Version';Data=$version}
        }catch{Add-Coverage ('SQL/'+$instance) 'Unavailable' $_.Exception.Message;continue}
        $sysadmin=$version[0].IsSysadmin -eq 1
        if(-not $sysadmin){Add-Coverage ('SQL/'+$instance+'/Visibility') 'Partial' 'Login lacks sysadmin. Metadata visibility may be limited; absent entries are not inferred.'}
        # Independent fixed SELECT queries: denied msdb access must not hide a
        # readable master startup procedure. No observed command is executed.
        $queries=@(
            [pscustomobject]@{Kind='Sysadmins';Database='master';Query="SELECT p.name AS LoginName,p.type_desc AS LoginType,p.is_disabled AS IsDisabled FROM sys.server_role_members m JOIN sys.server_principals r ON m.role_principal_id=r.principal_id JOIN sys.server_principals p ON m.member_principal_id=p.principal_id WHERE r.name='sysadmin';"},
            [pscustomobject]@{Kind='Configuration';Database='master';Query="SELECT name,CONVERT(int,value_in_use) AS ValueInUse FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','Ad Hoc Distributed Queries');"},
            [pscustomobject]@{Kind='Jobs';Database='msdb';Query='SELECT CONVERT(nvarchar(36),j.job_id) AS JobId,j.name AS JobName,j.enabled AS Enabled,SUSER_SNAME(j.owner_sid) AS OwnerName,s.step_id AS StepId,s.subsystem AS Subsystem,s.command AS Command FROM dbo.sysjobs j JOIN dbo.sysjobsteps s ON j.job_id=s.job_id;'},
            [pscustomobject]@{Kind='StartupProcedures';Database='master';Query='SELECT name,OBJECT_DEFINITION(object_id) AS Definition FROM sys.procedures WHERE is_auto_executed=1;'}
        )
        foreach($query in $queries){
            $collection='SQL/'+$instance+'/'+$query.Kind
            try {
                $rows=@(Invoke-SqlMetadata $instance $query.Database $query.Query)
                $visibility=if($sysadmin){'sysadmin metadata access'}else{'May be incomplete under this login'}
                $records+=[pscustomobject]@{Instance=$instance;Kind=$query.Kind;Data=$rows;Visibility=$visibility}
                Add-Coverage $collection $(if($sysadmin){'Collected'}else{'Partial'}) $visibility $sysadmin
                if($query.Kind -eq 'Jobs'){
                    foreach($job in $rows){$artifacts+=New-Observation ('SqlJob:'+$instance+'/'+$job.JobId+'/'+$job.StepId) 'SqlJob' ($instance+'/'+$job.JobName+'/'+$job.StepId) $job.Command $job.OwnerName $collection $job}
                }
                if($query.Kind -eq 'StartupProcedures'){
                    foreach($procedure in $rows){
                        $artifacts+=New-Observation ('SqlStartup:'+$instance+'/'+$procedure.name) 'SqlStartupProcedure' ($instance+'/'+$procedure.name) ([string]$procedure.Definition) '' $collection $procedure
                        if($null -eq $procedure.Definition){Add-Coverage ($collection+'/'+$procedure.name) 'Partial' 'Procedure definition is unavailable or encrypted.'}
                    }
                }
            }catch{Add-Coverage $collection 'Unavailable' $_.Exception.Message}
        }
    }
    if(-not @($Services | Where-Object {$_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*'}).Count){Add-Coverage 'SQL/Discovery' 'NotAssessed' 'No local Database Engine service was discovered. Cluster, container, LocalDB and remote instances are outside this discovery scope.'}
    [pscustomobject]@{Records=$records;Artifacts=$artifacts}
}

function New-TriageFinding {
    param([string]$Kind,[string]$Priority,[string]$Identity,[string]$Title,[string]$Expected,[string]$Observed,[string]$Evidence,[string]$NextStep)
    [pscustomobject]@{Kind=$Kind;Priority=$Priority;Identity=$Identity;Title=$Title;Expected=$Expected;Observed=$Observed;Evidence=$Evidence;NextStep=$NextStep}
}
# Compare observed evidence to operator intent, preserving uncertainty and partial lists.
function Get-RequirementFindings {
    param([object]$Intent,[object]$Data)
    foreach($required in @($Intent.Services)){
        $actual=@($Data.Services | Where-Object Name -eq $required.Name)
        if(-not $actual.Count){
            $kind=if(Is-Collected 'Services'){'RequirementViolation'}else{'NotAssessed'}
            New-TriageFinding $kind 'High' ('Service:'+$required.Name) 'Required service was not found' 'Required service present.' 'Not discovered.' 'Win32_Service inventory; unavailable or inaccessible services may be omitted.' 'Confirm the exact service name and collection permissions.';continue
        }
        $s=$actual[0]
        foreach($pair in @(@('State',$required.State,$s.State),@('Startup',$required.Startup,$s.StartMode))){
            if($pair[1] -ne 'Unknown' -and $pair[1] -ne $pair[2]){New-TriageFinding 'RequirementViolation' 'High' ('Service:'+$s.Name) ('Unexpected service '+$pair[0]) $pair[1] $pair[2] 'Operator requirement versus Win32_Service.' 'Review dependencies, role requirements and service change history.'}
        }
        if($required.Account -and (Canonical-Account $required.Account $Intent.Computer) -ne (Canonical-Account $s.StartName $Intent.Computer)){New-TriageFinding 'Review' 'Medium' ('Service:'+$s.Name) 'Service account name differs from the intended account' $required.Account $s.StartName 'Name comparison; equivalent aliases/group context may require validation.' 'Resolve both identities to SIDs and verify the approved account.'}
    }
    if($Intent.Roles.Known -and $Intent.Roles.Values -icontains 'DomainController' -and $Data.Discovery.Role -ne 'Domain Controller'){New-TriageFinding 'RequirementViolation' 'High' 'Role:DomainController' 'Intended domain-controller role does not match detection' 'Domain Controller' $Data.Discovery.Role 'Win32_ComputerSystem.DomainRole' 'Confirm the intended machine and role.'}
    $unresolved=@($Intent.AdminIdentities | Where-Object {-not $_.Resolved})
    if(-not $Intent.Administrators.Known){New-TriageFinding 'NotAssessed' 'Low' 'Administrators' 'Approved administrator membership is unknown' 'Operator-approved identities.' 'No requirement supplied.' 'Direct membership is still saved as evidence.' 'Provide a reviewed complete list when available.'}
    elseif(Is-Collected 'Administrators'){
        foreach($member in $Data.Admins){
            $matches=@($Intent.AdminIdentities | Where-Object {($_.Resolved -and $_.Sid -and $_.Sid -eq $member.Sid) -or $_.Name -ieq $member.Name})
            if(-not $matches.Count){
                $kind=if($Intent.Administrators.Complete -and -not $unresolved.Count){'RequirementViolation'}else{'Review'}
                New-TriageFinding $kind 'High' ('Administrator:'+$member.Sid) 'Administrator member not matched to your approved list' ($Intent.Administrators.Values -join ', ') ($member.Name+'; '+$member.Sid) 'Direct membership only. Nested group membership is not expanded.' 'Verify the identity, approval, and membership-change history.'
            }
        }
    }
    if($unresolved.Count){New-TriageFinding 'NotAssessed' 'Low' 'Intent:AdminResolution' 'Some approved administrator names could not be resolved' 'Resolvable identities or explicit SIDs.' ($unresolved.Name -join ', ') 'Unmatched members are not declared unapproved when approved identities are unresolved.' 'Correct names or supply verified SIDs.'}
    $active=@($Data.Firewall.Networks | ForEach-Object {if([string]$_.NetworkCategory -eq 'DomainAuthenticated'){'Domain'}else{[string]$_.NetworkCategory}} | Select-Object -Unique)
    foreach($p in $Data.Firewall.Profiles){
        $isActive=$active -contains [string]$p.Name;$priority=if($isActive){'High'}else{'Medium'}
        $context='Profile='+$p.Name+'; reported on current interfaces='+$isActive+'. Interface exclusions: '+($p.DisabledInterfaceAliases -join ', ')
        if([string]$p.Enabled -eq 'False'){New-TriageFinding 'Review' $priority ('Firewall:'+$p.Name) 'Firewall profile is disabled' 'Review protection requirements.' 'Enabled=False' $context 'Verify whether an approved exception or alternate protection explains this.'}
        if([string]$p.DefaultInboundAction -eq 'Allow'){New-TriageFinding 'Review' $priority ('Firewall:'+$p.Name) 'Default policy allows unmatched inbound traffic' 'Review the intended inbound default.' 'DefaultInboundAction=Allow' $context 'Review effective rules and external network controls.'}
        $expected=$Intent.LocalRuleMerging.PSObject.Properties[[string]$p.Name].Value
        if($null -ne $expected){
            $actual=[string]$p.AllowLocalFirewallRules
            if($actual -notin @('True','False')){New-TriageFinding 'NotAssessed' 'Medium' ('FirewallMerge:'+$p.Name) 'Effective local rule merging is unresolved' ([string]$expected) $actual $context 'Check effective GPO/MDM profile settings.'}
            elseif(([bool]::Parse($actual)) -ne $expected){New-TriageFinding 'RequirementViolation' $priority ('FirewallMerge:'+$p.Name) 'Local rule merging conflicts with your requirement' ([string]$expected) $actual $context 'Inspect effective profile policy. PersistentStore rules and local Group Policy rules are distinct.'}
        }
        if([string]$p.AllowInboundRules -eq 'False' -and [string]$p.DefaultInboundAction -eq 'Block'){New-TriageFinding 'Review' $priority ('FirewallInboundRules:'+$p.Name) 'Inbound allow rules are ignored in shields-up mode' 'Verify this operating mode is intended.' 'AllowInboundRules=False; default inbound Block' $context 'Inspect the effective profile setting before troubleshooting individual allow rules.'}
    }
    if(-not $Intent.NetworkKnown){New-TriageFinding 'NotAssessed' 'Low' 'NetworkRequirements' 'Expected inbound access is unknown' 'Approved protocol/port/source scope.' 'No requirement supplied.' 'Listening endpoints and firewall evidence were still collected.' 'Provide known requirements without declaring an incomplete list complete.'}
    foreach($requirement in @($Intent.Network)){
        $listeners=if($requirement.Protocol -eq 'TCP'){@($Data.Live.Tcp | Where-Object {$_.State -eq 'Listen' -and [int]$_.LocalPort -eq $requirement.Port})}else{@($Data.Live.Udp | Where-Object {[int]$_.LocalPort -eq $requirement.Port})}
        $networkCollection=if($requirement.Protocol -eq 'TCP'){'TCP/Final'}else{'UDP/Final'}
        if($requirement.Required -and -not $listeners.Count -and (Is-Collected $networkCollection)){New-TriageFinding 'RequirementViolation' 'Medium' ('Listener:'+$requirement.Protocol+':'+$requirement.Port) 'Expected listening endpoint was not observed' 'Listener required now.' 'No matching local listener in this capture.' 'This is an availability observation, not a firewall reachability test.' 'Verify the service state, listening address, actual port, and timing.'}
        foreach($rule in $Data.Firewall.Rules){
            $protocol=if($rule.Protocol -eq '6'){'TCP'}elseif($rule.Protocol -eq '17'){'UDP'}else{$rule.Protocol}
            if($protocol -notin @($requirement.Protocol,'Any','256')){continue}
            if((Test-PortSpec $rule.LocalPort $requirement.Port) -ne $true){continue}
            $ruleProfiles=$rule.Profile -split '\s*,\s*'
            if($active.Count -and $ruleProfiles -notcontains 'Any' -and -not @($ruleProfiles | Where-Object {$active -contains $_}).Count){continue}
            if($rule.Action -eq 'Allow' -and $requirement.SourcesKnown){
                $broader=@();$unknown=@()
                foreach($source in $rule.RemoteAddress){$contained=Test-AddressSubset $source $requirement.Sources;if($null -eq $contained){$unknown+=$source}elseif(-not $contained){$broader+=$source}}
                if($broader.Count){
                    $unrestricted=([string]$rule.Program -eq 'Any' -and [string]$rule.Service -eq 'Any')
                    New-TriageFinding 'Review' $(if($unrestricted){'High'}else{'Medium'}) ('FirewallRule:'+$rule.Name) 'Allow rule has source scope broader than an intended port requirement' ($requirement.Protocol+':'+$requirement.Port+' from '+($requirement.Sources -join ', ')) ($broader -join ', ') ('Candidate rule='+$rule.DisplayName+'; program='+$rule.Program+'; service='+$rule.Service+'; source='+$rule.Source) 'Validate application/service, local address, profile and other conditions. This is not proof of network reachability.'
                }
                if($unknown.Count){New-TriageFinding 'NotAssessed' 'Low' ('FirewallScope:'+$rule.Name) 'Firewall address keywords could not be compared' ($requirement.Sources -join ', ') ($unknown -join ', ') 'Dynamic firewall scopes require runtime/environment context.' 'Resolve the keyword scope before deciding whether access is too broad.'}
            }
        }
    }
    if($Intent.NetworkKnown -and $Intent.NetworkComplete){
        $listeners=@($Data.Live.Tcp | Where-Object State -eq 'Listen' | ForEach-Object {[pscustomobject]@{Protocol='TCP';Port=[int]$_.LocalPort;Address=$_.LocalAddress;ProcessId=$_.OwningProcess}})
        $listeners+=@($Data.Live.Udp | ForEach-Object {[pscustomobject]@{Protocol='UDP';Port=[int]$_.LocalPort;Address=$_.LocalAddress;ProcessId=$_.OwningProcess}})
        foreach($listener in @($listeners | Sort-Object Protocol,Port,Address,ProcessId -Unique)){
            if($listener.Address -in @('127.0.0.1','::1')){continue}
            if(-not @($Intent.Network | Where-Object {$_.Protocol -eq $listener.Protocol -and $_.Port -eq $listener.Port}).Count){New-TriageFinding 'Review' 'Medium' ('Listener:'+$listener.Protocol+':'+$listener.Port+'/'+$listener.ProcessId) 'Listening port is outside your complete intended list' 'Declared complete inbound port list.' ($listener.Protocol+':'+$listener.Port+' on '+$listener.Address+'; PID='+$listener.ProcessId) 'Listening does not prove firewall permission or external reachability. Dynamic RPC ports may be legitimate.' 'Identify the owning process and confirm workload requirements.'}
        }
    }
    foreach($task in @($Data.Artifacts | Where-Object Type -eq 'Task')){
        if($Intent.ExpectedTasks.Known -and $Intent.ExpectedTasks.Complete -and $task.Name -notlike '\Microsoft\Windows\*' -and $Intent.ExpectedTasks.Values -inotcontains $task.Name){New-TriageFinding 'Review' 'Medium' $task.Identity 'Custom task is outside your complete approved task list' ($Intent.ExpectedTasks.Values -join ', ') $task.Name $task.Command 'Verify whether application installation, maintenance or an unauthorized change created it.'}
    }
    foreach($entry in $Data.Defender){
        $id=$entry.Type+'|'+$entry.Value
        if($Intent.DefenderExclusions.Known -and $Intent.DefenderExclusions.Values -icontains $id){continue}
        $kind=if($Intent.DefenderExclusions.Known -and $Intent.DefenderExclusions.Complete){'RequirementViolation'}else{'Review'}
        New-TriageFinding $kind 'Medium' ('Defender:'+ $id) 'Visible Defender exclusion lacks an approved match' $(if($Intent.DefenderExclusions.Known){$Intent.DefenderExclusions.Values -join ', '}else{'Unknown approved exclusions.'}) $id 'Only visible Get-MpPreference exclusions; automatic/hidden exclusions can exist.' 'Verify the scope and approved purpose. A process exclusion concerns files opened by that process.'
    }
    foreach($record in @($Data.Sql.Records | Where-Object Kind -eq 'Configuration')){
        foreach($setting in @($record.Data | Where-Object ValueInUse -eq 1)){New-TriageFinding 'Review' 'Medium' ('SqlConfig:'+$record.Instance+'/'+$setting.name) 'Security-sensitive SQL feature is enabled' 'Verify approved workload requirement.' ($setting.name+'=1') 'Supplemental metadata observation; enabled alone does not establish compromise.' 'Review who can invoke the feature and related jobs/procedures.'}
    }
    if($Intent.SqlAdministrators.Known -and $Intent.SqlAdministrators.Complete){
        foreach($record in @($Data.Sql.Records | Where-Object Kind -eq 'Sysadmins')){foreach($login in $record.Data){if($Intent.SqlAdministrators.Values -inotcontains $login.LoginName){New-TriageFinding 'RequirementViolation' 'High' ('SqlAdmin:'+$record.Instance+'/'+$login.LoginName) 'SQL sysadmin login is outside your approved list' ($Intent.SqlAdministrators.Values -join ', ') ($login.LoginName+'; disabled='+$login.IsDisabled) $record.Visibility 'Validate login ownership, role membership and approval.'}}}
    }
}

function Get-TriageSnapshot {
    param([object]$Discovery,[object[]]$Artifacts)
    $items=@()
    foreach($a in $Artifacts){
        if($a.Type -eq 'Process'){continue}
        $items+=[pscustomobject]@{Identity=$a.Identity;Type=$a.Type;Collection=$a.Collection;Fields=[ordered]@{Command=$a.Command;Account=$a.Account}}
    }
    [pscustomobject]@{Schema='WindowsServerAudit.TriageSnapshot';Version=1;CapturedUtc=(Get-Date).ToUniversalTime().ToString('o');Trust='User must establish reference cleanliness.';Machine=[pscustomobject]@{Computer=$Discovery.Computer;Year=$Discovery.Year;Role=$Discovery.Role;Build=$Discovery.Build;EditionSku=$Discovery.EditionSku};Artifacts=$items;Files=@($script:Files.Values | Select-Object Path,Status,Sha256);Collections=$script:Coverage.ToArray()}
}
# Infer absence only when the relevant last enumeration completed successfully.
function Compare-TriageSnapshot {
    param([object]$Current,[object]$Reference,[switch]$AllowBuildMismatch)
    if($Reference.Schema -ne 'WindowsServerAudit.TriageSnapshot' -or $Reference.Version -ne 1){throw 'Baseline must be a focused v0.4 triage snapshot; v0.3 configuration snapshots use a different schema.'}
    foreach($field in @('Year','Role','EditionSku')){if($Reference.Machine.$field -ne $Current.Machine.$field){throw ('Baseline '+$field+' does not match.')}}
    if($Reference.Machine.Build -ne $Current.Machine.Build){
        if(-not $AllowBuildMismatch){throw 'Baseline build differs; update the reference or explicitly use -AllowBaselineBuildMismatch.'}
        New-TriageFinding 'Review' 'Low' 'Baseline:Build' 'Baseline build mismatch explicitly allowed' $Reference.Machine.Build $Current.Machine.Build 'Updates can explain configuration and file differences.' 'Review changes against approved updates.'
    }
    $old=@{};$now=@{}
    foreach($a in @($Reference.Artifacts)){if($old.ContainsKey([string]$a.Identity)){throw 'Duplicate baseline artifact identity.'};$old[[string]$a.Identity]=$a}
    foreach($a in @($Current.Artifacts)){$now[[string]$a.Identity]=$a}
    foreach($id in $now.Keys){
        if($old.ContainsKey($id)){
            $a=$now[$id];$b=$old[$id]
            if($a.Fields.Command -cne $b.Fields.Command -or $a.Fields.Account -ine $b.Fields.Account){New-TriageFinding 'Review' 'High' $id 'Execution entry differs from the selected baseline' ($b.Fields | ConvertTo-Json -Compress) ($a.Fields | ConvertTo-Json -Compress) 'Compared command/account fields. Different host-specific identities or approved updates may explain changes.' 'Inspect the exact change and reference provenance.'}
        } elseif((($Reference.Collections | Where-Object Name -eq $now[$id].Collection | Select-Object -Last 1).Complete -eq $true)){New-TriageFinding 'Review' 'High' $id 'Execution entry not present in the selected baseline' 'Absent in fully enumerated reference collection.' $now[$id].Fields.Command $now[$id].Collection 'Validate reference scope and approved installations.'}
    }
    foreach($id in $old.Keys){if(-not $now.ContainsKey($id) -and (($Current.Collections | Where-Object Name -eq $old[$id].Collection | Select-Object -Last 1).Complete -eq $true)){New-TriageFinding 'Review' 'Medium' $id 'Baseline execution entry was not observed' $old[$id].Fields.Command 'Absent in current enumerated collection.' $old[$id].Collection 'Verify removal, visibility and approved changes.'}}
    $oldFiles=@{};foreach($file in @($Reference.Files)){$oldFiles[[string]$file.Path]=$file}
    foreach($file in @($Current.Files | Where-Object {$_.Status -eq 'Observed' -and $_.Sha256})){
        if($oldFiles.ContainsKey([string]$file.Path) -and $oldFiles[$file.Path].Sha256 -and $oldFiles[$file.Path].Sha256 -ine $file.Sha256){New-TriageFinding 'Review' 'High' ('File:'+$file.Path) 'Referenced file content differs from the selected baseline' $oldFiles[$file.Path].Sha256 $file.Sha256 $file.Path 'Validate approved updates, signature and contents. A hash difference is not a malware verdict.'}
    }
}

function Encode-Html {param([AllowNull()][object]$Text) [Net.WebUtility]::HtmlEncode([string]$Text)}
# Encode every evidence value before HTML insertion. The report needs no external assets.
function Write-TriageReport {
    param([string]$Path,[object]$Discovery,[object]$Intent,[object[]]$Findings,[object[]]$Assessments,[object[]]$Coverage,[object[]]$Artifacts)
    $rows=New-Object Text.StringBuilder;$rank=@{High=0;Medium=1;Low=2}
    foreach($f in @($Findings | Sort-Object @{Expression={$rank[$_.Priority]}},Kind,Identity)){
        $null=$rows.Append(('<tr data-kind="{0}" data-priority="{1}"><td><b>{1}</b><br>{0}</td><td><b>{2}</b><br>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td></tr>' -f (Encode-Html $f.Kind),(Encode-Html $f.Priority),(Encode-Html $f.Identity),(Encode-Html $f.Title),(Encode-Html $f.Expected),(Encode-Html $f.Observed),(Encode-Html $f.Evidence),(Encode-Html $f.NextStep)))
    }
    $cards=New-Object Text.StringBuilder
    foreach($a in @($Assessments | Where-Object Score -gt 0 | Sort-Object Score -Descending)){
        $reasons=@($a.Signals | ForEach-Object {'<li>'+(Encode-Html $_.Text)+'</li>'}) -join ''
        $connections=@($a.Connections | ForEach-Object {$_.RemoteAddress+':'+$_.RemotePort+' (PID '+$_.OwningProcess+')'}) -join '; '
        $processes=@($a.LinkedProcesses | ForEach-Object {'PID '+$_.ProcessId+'; parent '+$_.ParentProcessId+'; '+$_.ExecutablePath+'; started '+$_.CreationDate}) -join '; '
        $notes=(@($a.Exceptions | ForEach-Object {$_.Reason}) -join '; ')
        $null=$cards.Append(('<details><summary>{0} | {1} | triage score {2}</summary><p><b>Command:</b> {3}<br><b>Account:</b> {4}</p><ul>{5}</ul><p><b>Associated processes:</b> {6}<br><b>Connections:</b> {7}<br><b>Declared management context:</b> {8}<br><b>Operator exception annotation:</b> {9}</p><p>Associations describe matching PIDs/paths, not proof of which persistence mechanism launched a process. PID reuse and collection timing can affect linkage. Scores are transparent sorting weights, not probabilities or malware verdicts.</p></details>' -f (Encode-Html $a.Priority),(Encode-Html $a.Identity),$a.Score,(Encode-Html $a.Command),(Encode-Html $a.Account),$reasons,(Encode-Html $processes),(Encode-Html $connections),(Encode-Html ($a.ManagementContext -join ', ')),(Encode-Html $notes)))
    }
    $coverageRows=@($Coverage | ForEach-Object {'<tr><td>'+(Encode-Html $_.Name)+'</td><td>'+(Encode-Html $_.Status)+'</td><td>'+(Encode-Html $_.Detail)+'</td></tr>'}) -join ''
    $fileJson=Encode-Html (ConvertTo-Json -InputObject @($script:Files.Values) -Depth 12)
    $intentJson=Encode-Html (ConvertTo-Json -InputObject $Intent -Depth 16)
    $inventoryRows=@($Artifacts | ForEach-Object {'<tr><td>'+(Encode-Html $_.Identity)+'</td><td>'+(Encode-Html $_.Account)+'</td><td>'+(Encode-Html $_.Command)+'</td></tr>'}) -join ''
    $title=Encode-Html ($Discovery.Computer+' - Windows Server triage')
    $html=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'"><title>$title</title><style>
body{font:15px/1.5 Segoe UI,Arial,sans-serif;margin:0;background:#edf2f5;color:#183348}header{background:#153448;color:white;padding:26px 4%}h1{margin:0;font-size:28px}main{padding:20px 4%}.notice,details{background:white;padding:16px;border:1px solid #ccd8e0;border-radius:8px;margin:12px 0}.notice{border-left:5px solid #d49a27}summary{font-weight:600;cursor:pointer}table{border-collapse:collapse;width:100%;background:white;font-size:13px}td,th{padding:10px;vertical-align:top;border-bottom:1px solid #dce4ea;text-align:left;overflow-wrap:anywhere}th{background:#dbe6ed}tr[data-priority=High]{border-left:5px solid #b53c3c}input,select{padding:9px;margin:8px;border:1px solid #a8bac8;border-radius:5px}pre{white-space:pre-wrap;overflow-wrap:anywhere}.scroll{overflow-x:auto}small{color:#536c7d}nav a{color:#c0e5ff;margin-right:15px}h2{margin-top:28px;font-size:21px}@media print{input,select{display:none}header{background:white;color:black}details{break-inside:avoid}}
</style></head><body><header><h1>$title</h1><p>Focused read-only triage 0.4.0 | $(Encode-Html $Discovery.Caption) | $(Encode-Html $Discovery.Role) | build $(Encode-Html $Discovery.Build)</p><nav><a href="#findings">Findings</a><a href="#candidates">Artifact evidence</a><a href="#coverage">Coverage</a><a href="#intent">Your requirements</a><a href="#inventory">Inventory</a></nav></header><main>
<div class="notice">Investigation leads and requirement checks. No finding establishes a red-team implant. Zero findings does not establish a clean machine. This scan does not perform comprehensive memory, kernel, file-integrity or network-reachability analysis. Event-log timeline analysis is not included. No commands found in evidence are executed and no remediation is applied.</div>
<h2 id="findings">Prioritized findings</h2><input id="query" type="search" placeholder="Search findings" aria-label="Search findings"><select id="kind" aria-label="Finding category"><option value="">All categories</option><option>SuspiciousArtifact</option><option>RequirementViolation</option><option>Review</option><option>NotAssessed</option></select><select id="priority" aria-label="Priority"><option value="">All priorities</option><option>High</option><option>Medium</option><option>Low</option></select>
<div class="scroll"><table id="results"><thead><tr><th>Priority / type</th><th>Object / finding</th><th>Intended</th><th>Observed</th><th>Evidence / uncertainty</th><th>Next verification</th></tr></thead><tbody>$rows</tbody></table></div>
<h2 id="candidates">Artifact evidence</h2>$cards
<details><summary>Referenced file hashes, signatures and permissions</summary><pre>$fileJson</pre></details>
<h2 id="coverage">Collection coverage</h2><table><thead><tr><th>Collector</th><th>Status</th><th>Detail</th></tr></thead><tbody>$coverageRows</tbody></table>
<details id="intent"><summary>Your intended configuration</summary><pre>$intentJson</pre></details>
<details id="inventory"><summary>Collected execution entries ($($Artifacts.Count))</summary><table><thead><tr><th>Identity</th><th>Account</th><th>Command / target</th></tr></thead><tbody>$inventoryRows</tbody></table></details>
<p><small>Complete JSON evidence and selected snapshot are in the Evidence directory. File and service ACL leads inspect broad-principal allow entries, inherited flags and deny ambiguity; full effective access for arbitrary users/groups is not computed. Current-user shortcuts and observed local files may be read; UNC targets are not fetched. Signature verification may use normal Windows trust/revocation behavior. Treat reports and intent files as sensitive configuration.</small></p>
</main><script>const q=document.getElementById('query'),k=document.getElementById('kind'),p=document.getElementById('priority');function filter(){for(const r of document.querySelectorAll('#results tbody tr'))r.hidden=!(r.textContent.toLowerCase().includes(q.value.toLowerCase())&&(!k.value||r.dataset.kind===k.value)&&(!p.value||r.dataset.priority===p.value))}q.addEventListener('input',filter);k.addEventListener('change',filter);p.addEventListener('change',filter);</script></body></html>
"@
    $html | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Save-Evidence {
    param([object]$Value,[string]$Name)
    ConvertTo-Json -InputObject $Value -Depth 24 | Set-Content -LiteralPath (Join-Path $script:EvidenceDirectory $Name) -Encoding UTF8
}

# Entry point: Windows-specific operations occur only below this marker.
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){throw 'Run locally in 64-bit Windows PowerShell on Windows Server.'}
if(-not [Environment]::Is64BitProcess){throw 'Use 64-bit PowerShell.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Open PowerShell as administrator.'}
if($NonInteractive -and -not $ConfigPath){throw '-NonInteractive requires -ConfigPath.'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'Choose a new OutputDirectory so an existing report is not overwritten.'}
$null=New-Item -ItemType Directory -Path $OutputDirectory
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$script:EvidenceDirectory=Join-Path $OutputDirectory 'Evidence';$null=New-Item -ItemType Directory -Path $script:EvidenceDirectory
$script:Coverage=New-Object 'System.Collections.Generic.List[object]';$script:Files=@{}
Write-Host 'Capturing initial processes and connections before setup...'
$initial=Get-LiveEvidence 'Initial';Save-Evidence $initial 'LiveInitial.json'
$discovery=Get-Discovery
$discovery.AdminMembers=@(Collect-Read 'Administrators' {Get-AdminMembers $discovery.Role})
if($ConfigPath){
    $file=Get-Item -LiteralPath $ConfigPath;if($file.Length -gt 2MB){throw 'Intent profile exceeds 2 MiB.'}
    $intent=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json;$null=Test-IntentProfile $intent
    if(-not $NonInteractive){Show-IntentSummary $intent;$accept=Ask-TriState 'Use this saved profile (n starts new setup)';if($accept -ne $true){$intent=$null}}
}else{$intent=$null}
if(-not $intent){
    do {$intent=New-IntentWizard $discovery;Show-IntentSummary $intent;$accept=Ask-TriState 'Confirm these requirements and start the read-only scan';if($accept -ne $true){Write-Host 'Starting setup again. Press Ctrl+C to cancel.'}}while($accept -ne $true)
}
# Bind machine-local comparisons to the assessed host while retaining the saved
# profile source name as metadata. Reusing a profile still requires operator review.
$sourceComputer=$intent.Computer;$intent.Computer=$discovery.Computer
if($sourceComputer -ne $discovery.Computer){Add-Coverage 'Intent/Host' 'Review' ('Profile was created for '+$sourceComputer+'. Local account names and paths may require edits.')}
ConvertTo-Json -InputObject $intent -Depth 16 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'ServerIntent.json') -Encoding UTF8
Write-Host 'Capturing current processes, connections, persistence and policy...'
$live=Get-LiveEvidence 'Final'
# Refresh services after the wizard; do not correlate to stale initial PIDs.
$services=@(Collect-Read 'Services' {Get-CimInstance Win32_Service})
$artifacts=@(Get-ServiceObservations $services)
$artifacts+=@(Get-TaskObservations)
$artifacts+=@(Get-StartupObservations)
$artifacts+=@(Get-WmiObservations)
foreach($p in $live.Processes){$artifacts+=New-Observation ('Process:'+$p.ProcessId+'/'+$p.CreationDate) 'Process' $p.Name ([string]$p.CommandLine) '' 'Processes/Final' ([pscustomobject]@{Image=$p.ExecutablePath;ParentProcessId=$p.ParentProcessId;CreationDate=$p.CreationDate}) @([int]$p.ProcessId)}
$firewall=Get-FirewallEvidence
$admins=@(Collect-Read 'Administrators' {Get-AdminMembers $discovery.Role})
$defender=@(Collect-Read 'DefenderVisibleExclusions' {$preferences=Get-MpPreference;foreach($property in @('ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress')){foreach($value in @($preferences.$property)){if($value){[pscustomobject]@{Type=$property;Value=[string]$value}}}}})
Add-Coverage 'DefenderVisibility' 'Partial' 'Automatic and hidden exclusions can be absent from Get-MpPreference; no exclusion removals are inferred.'
Add-Type -AssemblyName System.Data
$sql=Get-SqlObservations $services;$artifacts+=@($sql.Artifacts)
$data=[pscustomobject]@{Discovery=$discovery;Services=$services;Artifacts=$artifacts;Live=$live;Firewall=$firewall;Admins=$admins;Defender=$defender;Sql=$sql}
Save-Evidence $live 'LiveFinal.json';Save-Evidence $services 'Services.json';Save-Evidence $artifacts 'Artifacts.json';Save-Evidence $firewall 'Firewall.json';Save-Evidence $admins 'Administrators.json';Save-Evidence $defender 'DefenderVisibleExclusions.json';Save-Evidence $sql.Records 'SqlMetadata.json'
$findings=New-Object 'System.Collections.Generic.List[object]'
foreach($f in @(Get-RequirementFindings $intent $data)){$findings.Add($f)}
$assessments=New-Object 'System.Collections.Generic.List[object]'
Write-Host 'Inspecting referenced local files and correlating candidate artifacts...'
foreach($artifact in $artifacts){
    $assessment=Get-ArtifactAssessment $artifact $intent $live.Processes $live.Tcp;$assessments.Add($assessment)
    if($assessment.Score -gt 0){$findings.Add((New-TriageFinding 'SuspiciousArtifact' $assessment.Priority $artifact.Identity 'Artifact has indicators worth investigating' 'Review approved purpose and supporting evidence.' $artifact.Command (($assessment.Signals.Text) -join ' | ') 'Expand Artifact evidence, inspect referenced files and correlate with available EDR/event history.'))}
}
$fileGaps=@($script:Files.Values | Where-Object {$_.Status -ne 'Observed' -or @($_.Errors).Count})
if($fileGaps.Count){Add-Coverage 'ReferencedFiles' 'Partial' ($fileGaps.Count.ToString()+' files had skipped/unavailable hash, signature, content or ACL evidence. See file details and ReferencedFiles.json.')}
$snapshot=Get-TriageSnapshot $discovery $artifacts
if($intent.BaselinePath){
    try {$file=Get-Item -LiteralPath $intent.BaselinePath;if($file.Length -gt 50MB){throw 'Baseline exceeds 50 MiB.'};$reference=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json;foreach($f in @(Compare-TriageSnapshot $snapshot $reference -AllowBuildMismatch:$AllowBaselineBuildMismatch)){$findings.Add($f)}}
    catch {$findings.Add((New-TriageFinding 'NotAssessed' 'Medium' 'Baseline' 'Baseline comparison unavailable' 'Compatible focused triage snapshot.' $_.Exception.Message $intent.BaselinePath 'Select a reviewed reference created by this focused version.'))}
}
$gaps=@($script:Coverage | Where-Object {$_.Status -in @('Unavailable','Partial','NotAssessed')})
if($gaps.Count){$findings.Add((New-TriageFinding 'NotAssessed' 'Low' 'Coverage' 'Some evidence could not be fully assessed' 'Review the Coverage section.' ($gaps.Count.ToString()+' partial, unavailable or skipped collection records.') 'Per-collector reasons are retained in Coverage and Coverage.json.' 'Resolve relevant collection gaps; absence of evidence is not a clean result.'))}

Save-Evidence @($script:Files.Values) 'ReferencedFiles.json';Save-Evidence $assessments.ToArray() 'ArtifactAssessments.json';Save-Evidence $snapshot 'TriageSnapshot.json';Save-Evidence $findings.ToArray() 'Findings.json';Save-Evidence $script:Coverage.ToArray() 'Coverage.json'
if($CaptureBaseline){ConvertTo-Json -InputObject $snapshot -Depth 24 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'Baseline.json') -Encoding UTF8}
Write-TriageReport -Path (Join-Path $OutputDirectory 'index.html') -Discovery $discovery -Intent $intent -Findings $findings.ToArray() -Assessments $assessments.ToArray() -Coverage $script:Coverage.ToArray() -Artifacts $artifacts
Write-Host ('Report: '+(Join-Path $OutputDirectory 'index.html')) -ForegroundColor Green
Write-Host ('Reusable intended configuration: '+(Join-Path $OutputDirectory 'ServerIntent.json'))
[pscustomobject]@{Report=(Join-Path $OutputDirectory 'index.html');Intent=(Join-Path $OutputDirectory 'ServerIntent.json');Findings=$findings.Count;CandidateArtifacts=@($assessments | Where-Object Score -gt 0).Count}
