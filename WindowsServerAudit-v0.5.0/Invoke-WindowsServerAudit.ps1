#Requires -Version 5.1
<#
.SYNOPSIS
Interactive Windows Server intent setup and read-only implant triage.
.DESCRIPTION
Version 0.5.0. Collects evidence, asks what should be present, and writes a
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
        $answer=(Ask-Text ($Prompt+' [yes/no/unknown; Enter=unknown]')).ToLowerInvariant()
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
    if($Profile.Schema -ne 'WindowsServerAudit.Intent' -or $Profile.Version -ne 2){throw 'Use a version 2 intended-configuration profile from this release.'}
    if($null -ne $Profile.DomainController -and $Profile.DomainController -isnot [bool]){throw 'Domain-controller answer must be true, false or null.'}
    if($Profile.Roles.Known -isnot [bool] -or $Profile.Roles.Complete -isnot [bool]){throw 'Invalid role metadata.'}
    foreach($role in @($Profile.Roles.Values)){if($role -notin @('DomainController','Web','Database','File','DNS','RemoteDesktop')){throw 'Unknown server role in configuration.'}}
    foreach($direction in @('Inbound','Outbound')){
        $network=$Profile.$direction
        if($network.Mode -notin @('Defaults','Custom','None','Unknown')){throw 'Invalid network mode.'}
        foreach($port in @($network.Ports)){
            if($port.Protocol -notin @('TCP','UDP') -or $port.Specification -isnot [string] -or -not (Test-ValidPortRange $port.Specification)){throw 'Invalid network port or range.'}
        }
        if($network.Mode -ne 'Custom' -and @($network.Ports).Count){throw 'Ports require Custom mode.'}
        if($network.Mode -eq 'Custom' -and -not @($network.Ports).Count){throw 'Custom mode requires ports.'}
    }
    return $true
}
function Test-ValidPortRange {
    param([string]$Value)
    if($Value -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$'){return $false}
    $first=[int]$matches[1];$last=if($matches[2]){[int]$matches[2]}else{$first}
    return ($first -ge 1 -and $last -le 65535 -and $first -le $last)
}
function Read-SimplePorts {
    param([string]$Prompt)
    while($true){
        $text=Ask-Text ($Prompt+' [Enter=role/Windows defaults; none; unknown]')
        if(-not $text){return [pscustomobject]@{Mode='Defaults';Ports=@()}}
        if($text -ieq 'none'){return [pscustomobject]@{Mode='None';Ports=@()}}
        if($text -in @('u','unknown')){return [pscustomobject]@{Mode='Unknown';Ports=@()}}
        $ports=@();$valid=$true
        foreach($part in @($text -split ',' | ForEach-Object {$_.Trim().ToUpperInvariant()} | Select-Object -Unique)){
            if($part -notmatch '^(TCP|UDP):(\d{1,5}(?:-\d{1,5})?)$'){$valid=$false;break}
            $protocol=$matches[1];$specification=$matches[2]
            if(-not (Test-ValidPortRange $specification)){$valid=$false;break}
            $ports+=[pscustomobject]@{Protocol=$protocol;Specification=$specification}
        }
        if($valid){return [pscustomobject]@{Mode='Custom';Ports=$ports}}
        Write-Host 'Use TCP (Transmission Control Protocol) or UDP (User Datagram Protocol), for example TCP:443,UDP:53,TCP:5000-5010.'
    }
}
function Get-RoleLabel {
    param([string]$Name)
    $labels=@{DomainController='Domain controller';Web='Websites using Internet Information Services (IIS)';Database='Microsoft Structured Query Language (SQL) Server databases';File='File sharing';DNS='Domain Name System (DNS)';RemoteDesktop='Remote Desktop Services'}
    if($labels.ContainsKey($Name)){return $labels[$Name]};return $Name
}

function Show-IntentSummary {
    param([object]$Profile)
    Write-Host "`nSCAN SETUP" -ForegroundColor Cyan
    $dc=if($null -eq $Profile.DomainController){'Unknown'}elseif($Profile.DomainController){'Yes'}else{'No'}
    Write-Host ('Intended domain controller: '+$dc)
    Write-Host ('Other intended roles: '+(@($Profile.Roles.Values | Where-Object {$_ -ne 'DomainController'} | ForEach-Object {Get-RoleLabel $_}) -join '; '))
    foreach($direction in @('Inbound','Outbound')){
        $network=$Profile.$direction
        $ports=if($network.Mode -eq 'Custom'){@($network.Ports | ForEach-Object {Expand-AuditText ($_.Protocol+':'+$_.Specification)}) -join '; '}else{$network.Mode}
        Write-Host ($direction+': '+$ports)
    }
    Write-Host 'Services are assessed using built-in role expectations. Windows firewall defaults are the reference; policy differences alone are informational.'
}

function New-IntentWizard {
    param([object]$Discovery)
    Write-Host "`nWINDOWS SERVER TRIAGE - QUICK SETUP" -ForegroundColor Cyan
    Write-Host ($Discovery.Computer+' | '+$Discovery.Caption+' | '+$Discovery.Role)
    $detectedDc=$Discovery.Role -eq 'Domain Controller';$default=if($detectedDc){'yes'}else{'no'}
    while($true){
        $answer=Ask-Text ('Is this server intended to be a domain controller? [yes/no/unknown; Enter='+$default+']')
        if(-not $answer){$dc=$detectedDc;break}
        if($answer -in @('y','yes')){$dc=$true;break};if($answer -in @('n','no')){$dc=$false;break};if($answer -in @('u','unknown')){$dc=$null;break}
    }
    $detected=@()
    if(@($Discovery.Services | Where-Object Name -eq 'W3SVC').Count){$detected+='Web'}
    if(@($Discovery.Services | Where-Object {$_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*'}).Count){$detected+='Database'}
    if(@($Discovery.Services | Where-Object Name -eq 'DNS').Count){$detected+='DNS'}
    Write-Host ('Detected role candidates: '+(@($detected | ForEach-Object {Get-RoleLabel $_}) -join '; '))
    Write-Host 'Other intended roles: 1=websites using Internet Information Services (IIS); 2=Microsoft Structured Query Language (SQL) Server databases; 3=file sharing; 4=Domain Name System (DNS); 5=Remote Desktop Services.'
    while($true){
        $answer=Ask-Text 'Select intended role numbers, comma-separated [Enter=use detected candidates; none; unknown]'
        $known=$true;$complete=$true
        if(-not $answer){$values=@($detected);$complete=$false;break}
        if($answer -ieq 'none'){$values=@();break}
        if($answer -in @('u','unknown')){$values=@();$known=$false;$complete=$false;break}
        $tokens=@($answer -split ',' | ForEach-Object {$_.Trim()} | Select-Object -Unique)
        if(@($tokens | Where-Object {$_ -notin @('1','2','3','4','5')}).Count){Write-Host 'Enter role numbers, none, or unknown.';continue}
        $mapping=@{'1'='Web';'2'='Database';'3'='File';'4'='DNS';'5'='RemoteDesktop'}
        $values=@($tokens | ForEach-Object {$mapping[$_]});break
    }
    if($dc -eq $true){$values+=@('DomainController')}
    Write-Host 'TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) ports use forms such as TCP:443,UDP:53. Ranges such as TCP:5000-5010 are supported.'
    Write-Host 'Inbound: enter the complete application listening-port list. Essential Windows and selected-role ports are included automatically. Enter keeps those defaults.'
    $inbound=Read-SimplePorts 'Which inbound ports should listen?'
    Write-Host 'Outbound: enter allowed REMOTE DESTINATION ports for connections made by this server, not its temporary local source ports. Enter allows all, matching Windows defaults. No outbound listener concept is used.'
    $outbound=Read-SimplePorts 'Which outbound destination ports are allowed?'
    $profile=[pscustomobject]@{Schema='WindowsServerAudit.Intent';Version=2;CreatedUtc=(Get-Date).ToUniversalTime().ToString('o');Computer=$Discovery.Computer;DomainController=$dc;Roles=[pscustomobject]@{Known=$known;Complete=$complete;Values=@($values | Select-Object -Unique)};Inbound=$inbound;Outbound=$outbound;BaselinePath=''}
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
    $tools=@(@() | Where-Object {([string]$Artifact.Command).IndexOf($_,[StringComparison]::OrdinalIgnoreCase) -ge 0})
    $exceptions=@(@())
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
    $policy=$null
    try {
        $policy=New-Object -ComObject HNetCfg.FwPolicy2
        $profileTypes=@{Domain=1;Private=2;Public=4}
        foreach($profile in $profiles){
            foreach($name in @('Enabled','DefaultInboundAction','DefaultOutboundAction','AllowInboundRules')){
                if([string]$profile.$name -notin @('','NotConfigured')){continue}
                $original=[string]$profile.$name;$type=$profileTypes[[string]$profile.Name]
                $value=switch($name){
                    'Enabled'{[string]$policy.FirewallEnabled($type)}
                    'AllowInboundRules'{[string](-not $policy.BlockAllInboundTraffic($type))}
                    'DefaultInboundAction'{$action=[int]$policy.DefaultInboundAction($type);if($action -eq 0){'Block'}elseif($action -eq 1){'Allow'}else{'Unknown'}}
                    'DefaultOutboundAction'{$action=[int]$policy.DefaultOutboundAction($type);if($action -eq 0){'Block'}elseif($action -eq 1){'Allow'}else{'Unknown'}}
                }
                $profile.$name=$value
                Add-Coverage ('FirewallResolution/'+$profile.Name+'/'+$name) 'Collected' ('Network security provider returned '+$original+'; native effective-policy interface returned '+$value) $true
            }
        }
    }catch{Add-Coverage 'FirewallResolution' 'Partial' ('Native effective-policy fallback unavailable: '+$_.Exception.Message)}finally{if($policy){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy)}}
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

function Get-ServiceReference {
    param([object]$Intent,[object[]]$Services)
    $reference=@(
        @('EventLog','Windows Event Log','Running','Auto','NT AUTHORITY\LocalService','Windows core'),
        @('MpsSvc','Windows Defender Firewall','Running','Auto','NT AUTHORITY\LocalService','Windows core'),
        @('BFE','Base Filtering Engine','Running','Auto','NT AUTHORITY\LocalService','Windows core'),
        @('RpcSs','Remote Procedure Call','Running','Auto','NT AUTHORITY\NetworkService','Windows core'),
        @('Schedule','Task Scheduler','Running','Auto','LocalSystem','Windows core'),
        @('Winmgmt','Windows Management Instrumentation','Running','Auto','LocalSystem','Windows core')
    )
    $roles=@($Intent.Roles.Values)
    if($Intent.DomainController -eq $true){$reference+=@(@('NTDS','Active Directory Domain Services','Running','Auto','LocalSystem','Domain controller'),@('Kdc','Kerberos Key Distribution Center','Running','Auto','LocalSystem','Domain controller'),@('Netlogon','Net Logon','Running','Auto','LocalSystem','Domain controller'),@('ADWS','Active Directory Web Services','Running','Auto','LocalSystem','Domain controller'))}
    if($roles -contains 'Web'){$reference+=@(@('W3SVC','World Wide Web Publishing Service','Running','Auto','LocalSystem','Websites'),@('WAS','Windows Process Activation Service','Running','Auto|Manual','LocalSystem','Websites'))}
    if($roles -contains 'DNS'){$reference+=,@('DNS','Domain Name System Server','Running','Auto','LocalSystem','Name resolution')}
    if($roles -contains 'File' -or $Intent.DomainController -eq $true){$reference+=,@('LanmanServer','Server - file sharing','Running','Auto','','File sharing or domain controller')}
    if($roles -contains 'RemoteDesktop'){$reference+=,@('TermService','Remote Desktop Services','Running','Auto|Manual','NT AUTHORITY\NetworkService','Remote desktops')}
    foreach($entry in $reference){[pscustomobject]@{Name=$entry[0];DisplayName=$entry[1];States=@($entry[2] -split '\|');StartModes=@($entry[3] -split '\|');Account=$entry[4];Basis=$entry[5]}}
    if($roles -contains 'Database'){
        foreach($service in @($Services | Where-Object {$_.Name -eq 'MSSQLSERVER' -or $_.Name -like 'MSSQL$*'})){
            [pscustomobject]@{Name=$service.Name;DisplayName='Microsoft Structured Query Language (SQL) Server Database Engine - '+$service.Name;States=@('Running');StartModes=@('Auto','Manual');Account='';Basis='Selected database role; account and startup policy can be deployment-specific'}
        }
    }
}
function Get-RolePorts {
    param([object]$Intent)
    # Allowed-if-present reference ports, never assertions that every port must listen.
    $specs=@('TCP:135','TCP:139','TCP:445','TCP:5985','UDP:68','UDP:123','UDP:137','UDP:138','UDP:546','UDP:5353','UDP:5355')
    if($Intent.DomainController -eq $true){$specs+=@('TCP:53','UDP:53','TCP:88','UDP:88','UDP:123','TCP:389','UDP:389','TCP:464','UDP:464','TCP:636','TCP:3268','TCP:3269','UDP:137','UDP:138','TCP:139','TCP:9389')}
    if($Intent.Roles.Values -contains 'Web'){$specs+=@('TCP:80','TCP:443')}
    if($Intent.Roles.Values -contains 'Database'){$specs+=@('TCP:1433','UDP:1434')}
    if($Intent.Roles.Values -contains 'DNS'){$specs+=@('TCP:53','UDP:53')}
    if($Intent.Roles.Values -contains 'File'){$specs+=@('UDP:137','UDP:138','TCP:139')}
    if($Intent.Roles.Values -contains 'RemoteDesktop'){$specs+=@('TCP:3389','UDP:3389')}
    foreach($spec in @($specs | Select-Object -Unique)){$parts=$spec -split ':';[pscustomobject]@{Protocol=$parts[0];Specification=$parts[1]}}
}
function Test-LoopbackAddress {
    param([string]$Address)
    $ip=$null
    if([Net.IPAddress]::TryParse($Address,[ref]$ip)){return [Net.IPAddress]::IsLoopback($ip)}
    return $false
}
function Test-ExpectedEndpoint {
    param([string]$Protocol,[int]$Port,[object[]]$Ports)
    foreach($entry in $Ports){if($entry.Protocol -eq $Protocol -and (Test-PortSpec @($entry.Specification) $Port) -eq $true){return $true}}
    return $false
}
function Get-FirewallReference {
    foreach($profile in @('Domain','Private','Public')){
        [pscustomobject]@{Profile=$profile;Enabled='True';DefaultInboundAction='Block';DefaultOutboundAction='Allow';AllowInboundRules='True';AllowLocalFirewallRules='True';Note='Windows starting defaults, not a certification or a substitute for managed policy. Unresolved values stay unknown.'}
    }
}
function Get-FirewallComparison {
    param([object]$Firewall)
    $defaults=@(Get-FirewallReference)
    foreach($profile in $Firewall.Profiles){
        foreach($property in @('Enabled','DefaultInboundAction','DefaultOutboundAction','AllowInboundRules','AllowLocalFirewallRules')){
            $expected=[string]$defaults[0].$property;$observed=[string]$profile.$property
            $result=if($observed -in @('True','False','Allow','Block')){if($observed -eq $expected){'Matches Windows starting default'}else{'Policy difference - review context'}}else{'Unknown - no unsafe value inferred'}
            [pscustomobject]@{Profile=$profile.Name;Setting=$property;WindowsDefault=$expected;Observed=$observed;Comparison=$result}
        }
    }
}
function Get-RequirementFindings {
    param([object]$Intent,[object]$Data)
    if($null -ne $Intent.DomainController -and $Intent.DomainController -ne ($Data.Discovery.Role -eq 'Domain Controller')){New-TriageFinding 'RequirementViolation' 'High' 'Role:DomainController' 'Detected domain-controller role differs from your answer' ([string]$Intent.DomainController) $Data.Discovery.Role 'Operating-system role detection versus operator answer.' 'Confirm the intended machine and domain-controller role.'}
    foreach($expected in @(Get-ServiceReference $Intent $Data.Services)){
        $service=@($Data.Services | Where-Object Name -eq $expected.Name)
        $identity='Service:'+$expected.Name
        if(-not $service.Count){
            if(Is-Collected 'Services'){New-TriageFinding 'Review' 'High' $identity ($expected.DisplayName+' was not found') 'Expected for '+$expected.Basis 'Not observed.' 'Built-in role reference; required Windows components are deployment assumptions.' 'Confirm the selected role, service installation and approved exceptions.'}
            continue
        }
        $actual=$service[0]
        if($expected.States -notcontains $actual.State){New-TriageFinding 'Review' 'High' $identity ($expected.DisplayName+' is not in its expected running state') ($expected.States -join ' or ') $actual.State $expected.Basis 'Check role availability, approved maintenance and service dependencies.'}
        if($expected.StartModes -notcontains $actual.StartMode){New-TriageFinding 'Review' 'Medium' $identity ($expected.DisplayName+' startup differs from the role reference') ($expected.StartModes -join ' or ') $actual.StartMode $expected.Basis 'Verify whether approved policy explains the change.'}
        if($expected.Account -and (Canonical-Account $actual.StartName $Intent.Computer) -ne (Canonical-Account $expected.Account $Intent.Computer)){New-TriageFinding 'Review' 'High' $identity ($expected.DisplayName+' uses an unexpected account') $expected.Account $actual.StartName $expected.Basis 'Verify the configured identity and approved service configuration.'}
    }
    # Do not assume every unrecognized service is unsafe or should be disabled.
    if($Intent.Roles.Known -and $Intent.Roles.Complete){
        foreach($service in $Data.Services){
            $role=if($service.Name -in @('W3SVC','WAS')){'Web'}elseif($service.Name -eq 'MSSQLSERVER' -or $service.Name -like 'MSSQL$*'){'Database'}else{''}
            if($role -and $service.State -eq 'Running' -and $Intent.Roles.Values -notcontains $role){New-TriageFinding 'Review' 'Medium' ('Service:'+$service.Name) 'A running service supports a role you did not select' (Get-RoleLabel $role) $service.DisplayName 'Complete intended role answer versus observed running service.' 'Confirm application requirements before treating this as unnecessary.'}
        }
    }
    $active=@($Data.Firewall.Networks | ForEach-Object {if([string]$_.NetworkCategory -eq 'DomainAuthenticated'){'Domain'}else{[string]$_.NetworkCategory}} | Select-Object -Unique)
    foreach($profile in $Data.Firewall.Profiles){
        $priority=if($active -contains [string]$profile.Name){'High'}else{'Medium'}
        $evidence='Profile='+$profile.Name+'; current-interface category match='+($active -contains [string]$profile.Name)
        if([string]$profile.Enabled -eq 'False'){New-TriageFinding 'Review' $priority ('Firewall:'+$profile.Name) 'Firewall profile is disabled' 'Enabled in Windows starting defaults.' 'Disabled' $evidence 'Confirm effective protection and any approved exception.'}
        if([string]$profile.DefaultInboundAction -eq 'Allow'){New-TriageFinding 'Review' $priority ('FirewallInbound:'+$profile.Name) 'Unmatched inbound traffic is allowed' 'Block in Windows starting defaults.' 'Allow' $evidence 'Review effective rules and approved network design.'}
        # Allow outbound and normal inbound allow rules are standard Windows behavior.
        # A false local-rule merge setting can be deliberate centralized management.
        if([string]$profile.AllowInboundRules -eq 'False' -and [string]$profile.DefaultInboundAction -eq 'Block'){New-TriageFinding 'Information' 'Low' ('FirewallInboundRules:'+$profile.Name) 'Policy ignores inbound allow rules on this profile' 'Normal starting default permits allow rules.' 'Inbound allow rules disabled.' $evidence 'If a required application is unreachable, verify whether this policy is intentional.'}
        if([string]$profile.AllowLocalFirewallRules -eq 'False'){New-TriageFinding 'Information' 'Low' ('FirewallMerge:'+$profile.Name) 'Policy does not merge local firewall rules' 'Windows starting default allows merging.' 'Local rules ignored.' $evidence 'May be intentional central management. Local application rules need an applicable centrally managed equivalent.'}
        if($Intent.Outbound.Mode -in @('Custom','None') -and [string]$profile.DefaultOutboundAction -eq 'Allow' -and ($active -contains [string]$profile.Name)){New-TriageFinding 'Review' 'Medium' ('OutboundPolicy:'+$profile.Name) 'Outbound default is broader than your declared destination-port policy' 'Only declared outbound destinations allowed.' 'Windows normal default allows unmatched outbound traffic.' $evidence 'Inspect block rules and upstream controls; default action alone does not prove effective reachability.'}
    }
    foreach($rule in $Data.Firewall.Rules){
        if($rule.Action -eq 'Allow' -and $rule.Protocol -in @('Any','256') -and @($rule.LocalPort).Count -eq 1 -and $rule.LocalPort[0] -eq 'Any' -and $rule.Program -eq 'Any' -and $rule.Service -eq 'Any' -and @($rule.RemoteAddress).Count -eq 1 -and $rule.RemoteAddress[0] -eq 'Any'){
            New-TriageFinding 'Review' 'High' ('FirewallRule:'+$rule.Name) 'Inbound allow rule appears unusually broad' 'Typical application rules limit program, service, protocol, port or source.' $rule.DisplayName ('Rule source='+$rule.Source+'; profiles='+$rule.Profile) 'Inspect all rule conditions and block rules before judging effective exposure.'
        }
    }
    $allowed=@(Get-RolePorts $Intent)+@($Intent.Inbound.Ports)
    $listeners=@($Data.Live.Tcp | Where-Object State -eq 'Listen' | ForEach-Object {[pscustomobject]@{Protocol='TCP';Port=[int]$_.LocalPort;Address=$_.LocalAddress;ProcessId=$_.OwningProcess}})
    $listeners+=@($Data.Live.Udp | ForEach-Object {[pscustomobject]@{Protocol='UDP';Port=[int]$_.LocalPort;Address=$_.LocalAddress;ProcessId=$_.OwningProcess}})
    if($Intent.Inbound.Mode -ne 'Unknown'){
        foreach($listener in @($listeners | Sort-Object Protocol,Port,Address,ProcessId -Unique)){
            if(Test-LoopbackAddress $listener.Address){continue}
            $matched=if($Intent.Inbound.Mode -eq 'None'){$false}else{Test-ExpectedEndpoint $listener.Protocol $listener.Port $allowed}
            if($matched){continue}
            # Dynamic remote procedure call ports require application context, not a
            # blanket exemption for every program using a high-numbered port.
            $process=@($Data.Live.Processes | Where-Object ProcessId -eq $listener.ProcessId | Select-Object -First 1)
            $dynamic=($listener.Protocol -in @('TCP','UDP') -and $listener.Port -ge 49152 -and $listener.Port -le 65535 -and $process.Count -and [string]$process[0].ExecutablePath -imatch ('^'+[regex]::Escape($env:windir)+'\\System32\\(?:svchost|lsass|services|spoolsv|wininit|dns|dfsr)\.exe$'))
            if($dynamic -and $Intent.Inbound.Mode -ne 'None'){continue}
            if($listener.Protocol -eq 'UDP' -and $listener.Port -ge 49152 -and $Intent.Inbound.Mode -ne 'None'){
                New-TriageFinding 'Information' 'Low' ('DatagramEndpoint:'+$listener.Port+'/'+$listener.ProcessId) 'Datagram endpoint uses a dynamic local port' 'A bound socket does not establish an inbound server role.' ($listener.Address+':'+$listener.Port+'; process identifier='+$listener.ProcessId) 'Remote destination and connection direction are unavailable for this datagram endpoint.' 'May be a temporary outbound socket. Review owning application if relevant.'
                continue
            }
            New-TriageFinding 'Review' 'Medium' ('Listener:'+$listener.Protocol+':'+$listener.Port+'/'+$listener.ProcessId) 'Listening port is outside the role reference and your declared ports' $(if($Intent.Inbound.Mode -eq 'None'){'No non-loopback listeners.'}else{'Selected role defaults plus declared workload ports.'}) ($listener.Protocol+':'+$listener.Port+' on '+$listener.Address+'; process identifier='+$listener.ProcessId) 'Local listening observation only; does not establish network reachability.' 'Identify the owning program and confirm whether this workload or custom port is intended.'
        }
        foreach($requirement in @($Intent.Inbound.Ports)){
            $found=@($listeners | Where-Object {$_.Protocol -eq $requirement.Protocol -and (Test-PortSpec @($requirement.Specification) $_.Port) -eq $true})
            $collection=if($requirement.Protocol -eq 'TCP'){'TCP/Final'}else{'UDP/Final'}
            if(-not $found.Count -and (Is-Collected $collection)){New-TriageFinding 'Review' 'Medium' ('ExpectedListener:'+$requirement.Protocol+':'+$requirement.Specification) 'Declared inbound listening port was not observed' ($requirement.Protocol+':'+$requirement.Specification) 'No matching listener in current capture.' 'Custom ports are expected now; a range requires at least one listener, not every number.' 'Check application state, port bindings and timing.'}
        }
    }
    if($Intent.Outbound.Mode -in @('Custom','None')){
        foreach($connection in @($Data.Live.Tcp | Where-Object State -eq 'Established')){
            if(Test-LoopbackAddress $connection.RemoteAddress){continue}
            $destinationPort=[int]$connection.RemotePort
            # The endpoint table does not state initiator direction. A matching
            # local listener is evidence of a possible accepted inbound connection.
            $localListener=@($Data.Live.Tcp | Where-Object {$_.State -eq 'Listen' -and $_.OwningProcess -eq $connection.OwningProcess -and $_.LocalPort -eq $connection.LocalPort -and ($_.LocalAddress -in @('0.0.0.0','::') -or $_.LocalAddress -eq $connection.LocalAddress)})
            if($localListener.Count){continue}
            if($Intent.Outbound.Mode -eq 'Custom' -and (Test-ExpectedEndpoint 'TCP' $destinationPort $Intent.Outbound.Ports)){continue}
            New-TriageFinding 'Review' 'Medium' ('Connection:'+$connection.OwningProcess+'/'+$connection.LocalPort+'/'+$connection.RemoteAddress+':'+$destinationPort) 'Possible outbound connection uses an undeclared destination port' 'Declared remote destination ports.' ('TCP remote '+$connection.RemoteAddress+':'+$destinationPort+'; local source port='+$connection.LocalPort+'; process identifier='+$connection.OwningProcess) 'Direction is inferred from absence of a matching same-process local listener, not proven. Initial capture is also retained.' 'Verify connection direction and owning application. Temporary local source ports are not compared to your destination-port list.'
        }
    }
    foreach($entry in $Data.Defender){
        # Narrow global exclusions deserve attention without asking the operator
        # to enumerate every ordinary application exclusion.
        if(($entry.Type -eq 'ExclusionPath' -and $entry.Value -match '^(?:[A-Za-z]:\\?|\*|[A-Za-z]:\\\*)$') -or ($entry.Type -eq 'ExclusionExtension' -and $entry.Value -in @('*','exe','dll','ps1'))){New-TriageFinding 'Review' 'High' ('Defender:'+$entry.Type+'|'+$entry.Value) 'Microsoft Defender Antivirus has a broad exclusion' 'Review exceptions that cover entire drives or executable/script types.' $entry.Value 'Visible exclusions only; legitimate exceptions can exist.' 'Verify approved purpose and scope.'}
    }
    foreach($record in @($Data.Sql.Records | Where-Object Kind -eq 'Configuration')){foreach($setting in @($record.Data | Where-Object ValueInUse -eq 1)){New-TriageFinding 'Review' 'Medium' ('SqlConfig:'+$record.Instance+'/'+$setting.name) 'Security-sensitive database feature is enabled' 'Review application requirements.' ($setting.name+'=1') 'Enabled alone does not establish compromise.' 'Review permission to invoke the feature and related jobs/procedures.'}}
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


function Expand-AuditText {
    param([AllowNull()][object]$Text)
    $value=[string]$Text
    $names=[ordered]@{ADWS='Active Directory Web Services';KDC='Kerberos Key Distribution Center';MpsSvc='Windows Defender Firewall';W3SVC='World Wide Web Publishing Service';WAS='Windows Process Activation Service';NTDS='Active Directory Domain Services';BFE='Base Filtering Engine';RpcSs='Remote Procedure Call';Winmgmt='Windows Management Instrumentation';IIS='Internet Information Services';MSSQL='Microsoft Structured Query Language Server';SQL='Structured Query Language';DNS='Domain Name System';TCP='Transmission Control Protocol';UDP='User Datagram Protocol';WMI='Windows Management Instrumentation';CIM='Common Information Model';DACL='Discretionary Access Control List';ACL='Access Control List';ACE='Access Control Entry';SID='Security Identifier';PID='Process Identifier';GPO='Group Policy Object';MDM='Mobile Device Management';EDR='Endpoint Detection and Response';UNC='Universal Naming Convention';JSON='JavaScript Object Notation';HTML='Hypertext Markup Language';IP='Internet Protocol';RPC='Remote Procedure Call';SMB='Server Message Block';LDAP='Lightweight Directory Access Protocol';RDP='Remote Desktop Protocol';SHA256='Secure Hash Algorithm 256-bit'}
    $pattern='(?i)\b('+((@($names.Keys) | ForEach-Object {[regex]::Escape($_)}) -join '|')+')\b(?!\s*\()'
    return [regex]::Replace($value,$pattern,[Text.RegularExpressions.MatchEvaluator]{param($m) $m.Value+' ('+$names[$m.Value]+')'})
}
function Get-FriendlyKind {
    param([string]$Kind)
    switch($Kind){'SuspiciousArtifact'{'Suspicious artifact'}'RequirementViolation'{'Requirement mismatch'}'NotAssessed'{'Not assessed'}'Information'{'Information'}default{'Review'}}
}
function Encode-Display {param([AllowNull()][object]$Text) Encode-Html (Expand-AuditText $Text)}

function Encode-Html {param([AllowNull()][object]$Text) [Net.WebUtility]::HtmlEncode([string]$Text)}
# Encode every evidence value before HTML insertion. The report needs no external assets.
function Get-ReportFilterScript {
    # Deliberately use older JavaScript syntax for server browsers. No dependencies.
    return @'
(function () {
    'use strict';
    var query = document.getElementById('query');
    var kind = document.getElementById('kind');
    var priority = document.getElementById('priority');
    var reset = document.getElementById('resetFilters');
    var rows = document.querySelectorAll('#results tbody tr[data-kind]');
    var cards = document.querySelectorAll('#candidatesList details[data-kind]');
    function text(element) { return element.textContent || element.innerText || ''; }
    function matches(element) {
        var category = element.getAttribute('data-kind');
        var categoryMatches = kind.value === '' || category === kind.value ||
            (kind.value === 'Actionable' && category !== 'Information' && category !== 'NotAssessed');
        return categoryMatches && (!priority.value || element.getAttribute('data-priority') === priority.value) &&
            text(element).toLowerCase().indexOf(query.value.toLowerCase().replace(/^\s+|\s+$/g, '')) !== -1;
    }
    function filter() {
        var count = 0, i, visible;
        for (i = 0; i < rows.length; i += 1) {
            visible = matches(rows[i]); rows[i].style.display = visible ? 'table-row' : 'none';
            if (visible) { count += 1; }
        }
        for (i = 0; i < cards.length; i += 1) { cards[i].style.display = matches(cards[i]) ? 'block' : 'none'; }
        document.getElementById('resultCount').innerHTML = 'Showing ' + count + ' of ' + rows.length + ' findings';
        document.getElementById('noResults').style.display = count === 0 ? 'block' : 'none';
    }
    query.disabled = false; kind.disabled = false; priority.disabled = false; reset.disabled = false;
    query.addEventListener('input', filter); query.addEventListener('keyup', filter);
    query.addEventListener('change', filter); kind.addEventListener('change', filter); priority.addEventListener('change', filter);
    reset.addEventListener('click', function () { query.value = ''; kind.value = 'Actionable'; priority.value = ''; filter(); });
    document.getElementById('filterWarning').style.display = 'none';
    filter();
}());
'@
}
function Write-TriageReport {
    param([string]$Path,[object]$Discovery,[object]$Intent,[object[]]$Findings,[object[]]$Assessments,[object[]]$Coverage,[object[]]$Artifacts,[object]$Firewall,[object[]]$Services)
    $rows=New-Object Text.StringBuilder;$rank=@{High=0;Medium=1;Low=2}
    foreach($f in @($Findings | Sort-Object @{Expression={$rank[$_.Priority]}},Kind,Identity)){
        $null=$rows.Append(('<tr data-kind="{0}" data-priority="{1}"><td><b>{1}</b><br>{2}</td><td><b>{3}</b><br>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td>{8}</td></tr>' -f (Encode-Html $f.Kind),(Encode-Html $f.Priority),(Encode-Display (Get-FriendlyKind $f.Kind)),(Encode-Display $f.Identity),(Encode-Display $f.Title),(Encode-Display $f.Expected),(Encode-Display $f.Observed),(Encode-Display $f.Evidence),(Encode-Display $f.NextStep)))
    }
    $cards=New-Object Text.StringBuilder
    foreach($a in @($Assessments | Where-Object Score -gt 0 | Sort-Object Score -Descending)){
        $reasons=@($a.Signals | ForEach-Object {'<li>'+(Encode-Display $_.Text)+'</li>'}) -join ''
        $connections=@($a.Connections | ForEach-Object {$_.RemoteAddress+':'+$_.RemotePort+' (process identifier '+$_.OwningProcess+')'}) -join '; '
        $processes=@($a.LinkedProcesses | ForEach-Object {'Process identifier '+$_.ProcessId+'; parent identifier '+$_.ParentProcessId+'; '+$_.ExecutablePath+'; started '+$_.CreationDate}) -join '; '
        $null=$cards.Append(('<details data-kind="SuspiciousArtifact" data-priority="{0}"><summary>{0} | {1} | triage score {2}</summary><p><b>Collected command (verbatim):</b> <code>{3}</code><br><b>Account:</b> {4}</p><ul>{5}</ul><p><b>Associated processes:</b> {6}<br><b>Connections:</b> {7}</p><p>Process and path associations support review; they do not prove how a program started. Collection timing and process identifier reuse can affect association.</p></details>' -f (Encode-Html $a.Priority),(Encode-Display $a.Identity),$a.Score,(Encode-Html $a.Command),(Encode-Html $a.Account),$reasons,(Encode-Html $processes),(Encode-Html $connections)))
    }
    $coverageRows=@($Coverage | ForEach-Object {'<tr><td>'+(Encode-Display $_.Name)+'</td><td>'+(Encode-Display $_.Status)+'</td><td>'+(Encode-Display $_.Detail)+'</td></tr>'}) -join ''
    $firewallRows=@(Get-FirewallComparison $Firewall | ForEach-Object {'<tr><td>'+(Encode-Html $_.Profile)+'</td><td>'+(Encode-Html (Get-FirewallSettingLabel $_.Setting))+'</td><td>'+(Encode-Html $_.WindowsDefault)+'</td><td>'+(Encode-Html $_.Observed)+'</td><td>'+(Encode-Html $_.Comparison)+'</td></tr>'}) -join ''
    $serviceRows=@(Get-ServiceReference $Intent $Services | ForEach-Object {'<tr><td>'+(Encode-Display ($_.DisplayName+' ['+$_.Name+']'))+'</td><td>'+(Encode-Html ($_.States -join ' or '))+'</td><td>'+(Encode-Html (($_.StartModes -join ' or ') -replace '\bAuto\b','Automatic'))+'</td><td>'+(Encode-Html $(if($_.Account){$_.Account}else{'Deployment-specific'}))+'</td><td>'+(Encode-Display $_.Basis)+'</td></tr>'}) -join ''
    $rolePorts=@(Get-RolePorts $Intent | ForEach-Object {Encode-Display ($_.Protocol+':'+$_.Specification)}) -join '; '
    $fileJson=Encode-Html (ConvertTo-Json -InputObject @($script:Files.Values) -Depth 12)
    $intentJson=Encode-Html (ConvertTo-Json -InputObject $Intent -Depth 16)
    $inventoryRows=@($Artifacts | ForEach-Object {'<tr><td>'+(Encode-Display $_.Identity)+'</td><td>'+(Encode-Html $_.Account)+'</td><td><code>'+(Encode-Html $_.Command)+'</code></td></tr>'}) -join ''
    $title=Encode-Html ($Discovery.Computer+' - Windows Server triage')
    $filterScript=Get-ReportFilterScript
    $html=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'"><title>$title</title><style>
body{font:15px/1.5 Segoe UI,Arial,sans-serif;margin:0;background:#edf2f5;color:#183348}header{background:#153448;color:white;padding:26px 4%}h1{margin:0;font-size:28px}main{padding:20px 4%}.notice,details{background:white;padding:16px;border:1px solid #ccd8e0;border-radius:8px;margin:12px 0}.notice{border-left:5px solid #d49a27}summary{font-weight:600;cursor:pointer}table{border-collapse:collapse;width:100%;background:white;font-size:13px}td,th{padding:10px;vertical-align:top;border-bottom:1px solid #dce4ea;text-align:left;word-break:break-word}th{background:#dbe6ed}tr[data-priority=High]{border-left:5px solid #b53c3c}input,select,button{padding:9px;margin:5px;border:1px solid #a8bac8;border-radius:5px}pre{white-space:pre-wrap;word-break:break-word}.scroll{overflow-x:auto}small{color:#536c7d}nav a{color:#c0e5ff;margin-right:15px}h2{margin-top:28px;font-size:21px}#noResults{display:none}code{white-space:pre-wrap}@media print{.controls{display:none}header{background:white;color:black}details{break-inside:avoid}}
</style></head><body><header><h1>$title</h1><p>Read-only triage 0.5.0 | $(Encode-Html $Discovery.Caption) | $(Encode-Html $Discovery.Role) | build $(Encode-Html $Discovery.Build)</p><nav><a href="#findings">Findings</a><a href="#candidates">Artifact evidence</a><a href="#reference">Default reference</a><a href="#coverage">Coverage</a><a href="#inventory">Inventory</a></nav></header><main>
<div class="notice">Investigation leads, not malware verdicts. No remediation is applied. Role expectations are starting assumptions; a difference can be legitimate. Zero findings does not establish a clean machine. Commands found in evidence are never executed. Event-log timeline analysis is not included.</div>
<h2 id="findings">Prioritized findings</h2>
<p id="filterWarning" class="notice">Interactive filtering has not started. If this message stays visible, open the saved report in Microsoft Edge or another browser that permits local scripts. All findings remain readable below.</p><noscript><p>JavaScript is disabled. All findings are displayed; interactive filtering requires JavaScript.</p></noscript>
<div class="controls"><label>Search <input id="query" type="search" disabled aria-label="Search findings"></label><label>Category <select id="kind" disabled aria-label="Finding category"><option value="Actionable">Actionable findings</option><option value="">All categories</option><option value="SuspiciousArtifact">Suspicious artifacts</option><option value="RequirementViolation">Requirement mismatches</option><option value="Review">Review</option><option value="Information">Information</option><option value="NotAssessed">Not assessed</option></select></label><label>Priority <select id="priority" disabled aria-label="Priority"><option value="">All priorities</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select></label><button id="resetFilters" type="button" disabled>Reset filters</button></div>
<p id="resultCount" aria-live="polite">All findings below</p><p id="noResults" role="status">No findings match these filters. Reset filters or select All categories.</p>
<div class="scroll"><table id="results"><thead><tr><th>Priority / category</th><th>Object / finding</th><th>Expected</th><th>Observed</th><th>Evidence / uncertainty</th><th>Next verification</th></tr></thead><tbody>$rows</tbody></table></div>
<h2 id="candidates">Artifact evidence</h2><p>The same search, category and priority filters apply here.</p><div id="candidatesList">$cards</div>
<h2 id="reference">Windows firewall starting defaults and role expectations</h2><p>Normal defaults are enabled firewall profiles, blocking unmatched inbound traffic, allowing unmatched outbound traffic, accepting inbound allow rules and merging local rules. Managed policy can intentionally differ. Unresolved values are shown as unknown, not unsafe. This is a settings reference, not a fixed list of every firewall rule.</p>
<div class="scroll"><table><thead><tr><th>Profile</th><th>Setting</th><th>Windows starting default</th><th>Observed</th><th>Interpretation</th></tr></thead><tbody>$firewallRows</tbody></table></div>
<details><summary>Automatic service expectations</summary><p>Only core and selected-role services have state expectations. Other services still receive artifact checks. An unfamiliar service is not assumed to be unsafe. Manual startup is accepted for Windows Process Activation Service when it supports the website role. Microsoft Structured Query Language (SQL) Server Agent and third-party security products have deployment-specific requirements.</p><table><thead><tr><th>Service</th><th>Expected state</th><th>Accepted startup</th><th>Expected account</th><th>Basis</th></tr></thead><tbody>$serviceRows</tbody></table></details>
<details><summary>Allowed-if-present role listening ports</summary><p>$rolePorts</p><p>These ports are allowed assumptions, not requirements that every port listen. Custom named database instance ports must be supplied. Dynamic Remote Procedure Call (RPC) ports are recognized only for selected Windows system process paths, and those artifacts still receive behavioral checks.</p></details>
<details><summary>Referenced file evidence (verbatim technical values)</summary><p>Secure Hash Algorithm 256-bit (SHA256) hashes; Access Control Lists (ACL); Access Control Entries (ACE); Security Identifiers (SID); Universal Naming Convention (UNC) paths. Technical evidence preserves the exact collected values.</p><pre>$fileJson</pre></details>
<h2 id="coverage">Collection coverage</h2><table><thead><tr><th>Collector</th><th>Status</th><th>Detail</th></tr></thead><tbody>$coverageRows</tbody></table>
<details id="intent"><summary>Saved answers as JavaScript Object Notation (JSON)</summary><pre>$intentJson</pre></details>
<details id="inventory"><summary>Collected execution entries ($($Artifacts.Count))</summary><p>Commands and paths are verbatim. Service labels expand common abbreviations.</p><table><thead><tr><th>Identity</th><th>Account</th><th>Command / target</th></tr></thead><tbody>$inventoryRows</tbody></table></details>
<p><small>Evidence files retain exact values. Broad permission checks do not calculate full effective access for every user. Remote files are not fetched. Windows signature verification may use normal trust/revocation behavior. Restrict access to reports, which can contain sensitive configuration and command text.</small></p>
</main><script>$filterScript</script></body></html>
"@
    $html | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Get-FirewallSettingLabel {
    param([string]$Setting)
    switch($Setting){'Enabled'{'Firewall enabled'}'DefaultInboundAction'{'Default action for unmatched inbound traffic'}'DefaultOutboundAction'{'Default action for unmatched outbound traffic'}'AllowInboundRules'{'Inbound allow rules accepted'}'AllowLocalFirewallRules'{'Local firewall rules merged'}default{$Setting}}
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
    $intent=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json;if($intent.Version -ne 2){throw 'This release uses simplified version 2 profiles. Run without -ConfigPath to create one; old profiles are not silently reused.'};$null=Test-IntentProfile $intent
    if(-not $NonInteractive){Show-IntentSummary $intent;$accept=Ask-TriState 'Use this saved profile (n starts new setup)';if($accept -ne $true){$intent=$null}}
}else{$intent=$null}
if(-not $intent){
    do {$intent=New-IntentWizard $discovery;Show-IntentSummary $intent;$accept=Ask-TriState 'Use these answers and start the read-only scan';if($accept -ne $true){Write-Host 'Starting setup again. Press Ctrl+C to cancel.'}}while($accept -ne $true)
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
Add-Coverage 'OutboundDatagrams' 'Partial' 'User Datagram Protocol endpoint inventory has no remote destination addresses or ports. Outbound datagram destination policy is not assessed.'
$data=[pscustomobject]@{Discovery=$discovery;Services=$services;Artifacts=$artifacts;Live=$live;Firewall=$firewall;Admins=$admins;Defender=$defender;Sql=$sql}
Save-Evidence ([pscustomobject]@{Firewall=@(Get-FirewallReference);Services=@(Get-ServiceReference $intent $services);AllowedRolePorts=@(Get-RolePorts $intent);FirewallComparison=@(Get-FirewallComparison $firewall)}) 'ReferenceDefaults.json'
Save-Evidence $live 'LiveFinal.json';Save-Evidence $services 'Services.json';Save-Evidence $artifacts 'Artifacts.json';Save-Evidence $firewall 'Firewall.json';Save-Evidence $admins 'Administrators.json';Save-Evidence $defender 'DefenderVisibleExclusions.json';Save-Evidence $sql.Records 'SqlMetadata.json'
$findings=New-Object 'System.Collections.Generic.List[object]'
foreach($f in @(Get-RequirementFindings $intent $data)){$findings.Add($f)}
$assessments=New-Object 'System.Collections.Generic.List[object]'
Write-Host 'Inspecting referenced local files and correlating candidate artifacts...'
foreach($artifact in $artifacts){
    $assessment=Get-ArtifactAssessment $artifact $intent $live.Processes $live.Tcp;$assessments.Add($assessment)
    if($assessment.Score -gt 0){$findings.Add((New-TriageFinding 'SuspiciousArtifact' $assessment.Priority $artifact.Identity 'Artifact has indicators worth investigating' 'Review approved purpose and supporting evidence.' $artifact.Command (($assessment.Signals.Text) -join ' | ') 'Expand Artifact evidence, inspect referenced files and correlate with available endpoint detection and response or event history.'))}
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
Write-TriageReport -Path (Join-Path $OutputDirectory 'index.html') -Discovery $discovery -Intent $intent -Findings $findings.ToArray() -Assessments $assessments.ToArray() -Coverage $script:Coverage.ToArray() -Artifacts $artifacts -Firewall $firewall -Services $services
Write-Host ('Report: '+(Join-Path $OutputDirectory 'index.html')) -ForegroundColor Green
Write-Host ('Reusable intended configuration: '+(Join-Path $OutputDirectory 'ServerIntent.json'))
[pscustomobject]@{Report=(Join-Path $OutputDirectory 'index.html');Intent=(Join-Path $OutputDirectory 'ServerIntent.json');Findings=$findings.Count;CandidateArtifacts=@($assessments | Where-Object Score -gt 0).Count}
