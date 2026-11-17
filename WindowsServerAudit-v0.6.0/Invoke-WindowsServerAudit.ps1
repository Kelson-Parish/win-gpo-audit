#Requires -Version 5.1
<#
.SYNOPSIS
Interactive Windows Server intent setup and read-only implant triage.
.DESCRIPTION
Version 0.6.0. Collects evidence, asks what should be present, and writes a
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
    foreach($pattern in @('(?i)"([A-Z]:\\[^"]+\.(?:ps1|psm1|py|pyw|cmd|bat|vbs|js|mjs|cjs|sh|pl|rb|dll))"','(?i)([A-Z]:\\[^\s"'']+\.(?:ps1|psm1|py|pyw|cmd|bat|vbs|js|mjs|cjs|sh|pl|rb|dll))(?=\s|$|["''])')){
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
        if($file.Extension -in @('.ps1','.psm1','.py','.pyw','.cmd','.bat','.vbs','.js','.mjs','.cjs','.sh','.pl','.rb','.wsf') -and $file.Length -le 262144){
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
    if(($Text -match '(?is)from\s+pynput(?:\.keyboard)?\s+import|import\s+pynput|keyboard\s*\.\s*Listener\s*\(|GetAsyncKeyState\s*\(|SetWindowsHookEx\w*\s*\(|keyboard\s*\.\s*(?:on_press|record)\s*\(') -and ($Text -match '(?is)on_press\s*=|WH_KEYBOARD(?:_LL)?|(?:WriteAllText|AppendAllText)\s*\(|open\(.{0,150}["''][aw]["'']|keyboard\s*\.\s*record\s*\(')){
        [pscustomobject]@{Code='KeyboardCapturePatterns';Weight=60;Text='Referenced text combines keyboard-capture APIs or callbacks with capture/logging patterns. Static text can include examples/comments; inspect the actual code before calling it a keylogger.'}
    }
    if($Text -match '(?i)\b(?:while|for)\b' -and $Text -match '(?i)Start-Sleep\s+(?:-\w+\s+)?\d|time\s*\.\s*sleep\s*\(|setInterval\s*\(' -and $Text -match '(?i)(?:Invoke-WebRequest|Invoke-RestMethod)\s+(?:-\w+\s+)?(?:https?://|["'']https?://|\$\w+)|requests\s*\.\s*(?:get|post)\s*\(|socket\s*\.\s*connect\s*\(|\bfetch\s*\('){
        [pscustomobject]@{Code='PeriodicNetworkCode';Weight=30;Text='Referenced text combines a loop, delay and network call. Legitimate polling also does this; periodic beaconing is not established.'}
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
        if($CommandPaths.Executable -and $p.ExecutablePath -ieq $CommandPaths.Executable -and [IO.Path]::GetFileName($p.ExecutablePath) -notin $interpreters -and -not (Get-ScriptRuntime $p.ExecutablePath $p.Name $p.CommandLine)){$p;continue}
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
    foreach($p in $linked){$network+=@($Connections | Where-Object {[int]$_.OwningProcess -eq [int]$p.ProcessId -and $_.State -eq 'Established' -and $_.RemoteAddress -notin @('0.0.0.0','::') -and -not (Test-LoopbackAddress $_.RemoteAddress)})}
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
    [pscustomobject]@{Computer=$env:COMPUTERNAME;Caption=$os.Caption;Year=$year;Build=([string]$os.BuildNumber+'.'+$ubr);Role=$role;Domain=[string]$computer.Domain;EditionSku=[int]$os.OperatingSystemSKU;Architecture=$os.OSArchitecture;Services=$services;DetectedRoles=$roles;AdminMembers=@()}
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
    $rules=@($native | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile,PolicyStoreSource,PolicyStoreSourceType)
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
function Get-DomainSecurityEvidence {
    param([object]$Discovery)
    $result=[pscustomobject]@{Domain='';Status='NotAssessed';PwdProperties=$null;ReversibleEncryption=$null;FineGrainedPolicies=@();UserOverrides=@()}
    if($Discovery.Role -eq 'Standalone'){$result.Status='NotApplicable';Add-Coverage 'DomainPasswordPolicy' 'NotApplicable' 'Standalone server; no domain password policy queried.';return $result}
    $root=$null;$domain=$null
    try {
        $server=[string]$Discovery.Domain
        if($server -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'Computer domain name is unavailable or invalid.'}
        $root=[ADSI]('LDAP://'+$server+'/RootDSE');$dn=[string]$root.defaultNamingContext
        if(-not $dn){throw 'No default domain naming context was returned.'}
        $domain=[ADSI]('LDAP://'+$server+'/'+$dn);$result.Domain=$dn
        try {
            $domain.RefreshCache(@('pwdProperties'))
            if($domain.Properties['pwdProperties'].Count -ne 1){throw 'Domain password-properties attribute is unavailable.'}
            $result.PwdProperties=[int]$domain.Properties['pwdProperties'][0]
            $result.ReversibleEncryption=(($result.PwdProperties -band 16) -ne 0);$result.Status='Collected'
            Add-Coverage 'DomainPasswordPolicy' 'Collected' 'Read current domain password-properties flags. No password material or policy settings were changed.' $true
        }catch{Add-Coverage 'DomainPasswordPolicy' 'Unavailable' $_.Exception.Message}
        foreach($query in @(
            [pscustomobject]@{Name='FineGrainedPolicies';Filter='(&(objectClass=msDS-PasswordSettings)(msDS-PasswordReversibleEncryptionEnabled=TRUE))';Properties=@('name','distinguishedName','msDS-PSOAppliesTo')},
            [pscustomobject]@{Name='UserOverrides';Filter='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))';Properties=@('samAccountName','distinguishedName','userAccountControl')}
        )){
            $search=$null;$found=$null
            try {
                $search=New-Object DirectoryServices.DirectorySearcher($domain)
                $search.Filter=$query.Filter;$search.ClientTimeout=[TimeSpan]::FromSeconds(25);$search.PageSize=200;$search.SizeLimit=1001;$search.ServerTimeLimit=[TimeSpan]::FromSeconds(20)
                foreach($property in $query.Properties){$null=$search.PropertiesToLoad.Add($property)}
                $found=$search.FindAll();$rows=@()
                foreach($entry in @($found | Select-Object -First 1000)){
                    if($query.Name -eq 'FineGrainedPolicies'){$rows+=[pscustomobject]@{Name=[string]$entry.Properties['name'][0];DistinguishedName=[string]$entry.Properties['distinguishedname'][0];AppliesTo=@($entry.Properties['msds-psoappliesto']);ReversibleEncryption=$true}}
                    else {$flags=[int]$entry.Properties['useraccountcontrol'][0];$rows+=[pscustomobject]@{Name=[string]$entry.Properties['samaccountname'][0];DistinguishedName=[string]$entry.Properties['distinguishedname'][0];Disabled=(($flags -band 2) -ne 0)}}
                }
                $result.($query.Name)=$rows
                if($found.Count -gt 1000){Add-Coverage ('Domain/'+$query.Name) 'Partial' 'Results truncated at 1000 entries.'}
                else {Add-Coverage ('Domain/'+$query.Name) 'Collected' 'Visible matching entries only; object permissions may limit visibility.' $true}
            }catch{Add-Coverage ('Domain/'+$query.Name) 'Unavailable' $_.Exception.Message}finally{if($found){$found.Dispose()};if($search){$search.Dispose()}}
        }
    }catch{Add-Coverage 'DomainPasswordPolicy' 'Unavailable' $_.Exception.Message}finally{if($domain){$domain.Dispose()};if($root){$root.Dispose()}}
    return $result
}
function Get-DefenderSecurityEvidence {
    $status=@(Collect-Read 'DefenderStatus' {Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected})
    $threats=@(Collect-Read 'DefenderThreats' {Get-MpThreat | Select-Object ThreatID,ThreatName,IsActive,DidThreatExecute,Resources})
    # Read existing antivirus records only. This does not start a scan or read event logs.
    [pscustomobject]@{Status=$status;Threats=$threats}
}
function Get-ScriptRuntime {
    param([string]$Image,[string]$Name,[string]$Command)
    $exe=if($Image){[IO.Path]::GetFileName([Environment]::ExpandEnvironmentVariables($Image.Trim('"')))}else{$Name}
    if($exe -and -not [IO.Path]::GetExtension($exe)){$exe+='.exe'}
    if($exe -match '^(?:cron|crond|atd)\.exe$'){return 'Nonstandard Windows scheduler'}
    if($exe -match '^(?:python(?:w|\d+(?:\.\d+)*)?|pypy\d*|py)\.exe$'){return 'Python'}
    if($exe -match '^(?:node|nodejs|deno|bun)\.exe$'){return 'JavaScript runtime'}
    if($exe -match '^(?:bash|sh|perl|ruby|php|lua)\.exe$'){return 'General-purpose script runtime'}
    if($exe -match '^(?:wscript|cscript)\.exe$'){return 'Windows Script Host'}
    if($exe -match '^(?:pwsh|powershell)\.exe$' -and $Command -match '(?i)(?:\.(?:ps1|psm1)\b|\s-(?:f(?:ile)?|c(?:ommand)?|enc(?:odedcommand)?|e)\s)'){return 'PowerShell script or command'}
    if($exe -ieq 'cmd.exe' -and $Command -match '(?i)\.(?:cmd|bat)(?:\s|$|["''])'){return 'Windows command script'}
    return ''
}
function Test-ProminentArtifact {
    param([object]$Assessment)
    $codes=@($Assessment.Signals | ForEach-Object Code)
    # One weak attribute (unsigned, network connection, unusual directory, or
    # broad inherited permissions) never earns a prominent artifact finding.
    if(@($codes | Where-Object {$_ -in @('KeyboardCapturePatterns','DownloadAndExecute','SystemNameUnexpectedPath','SignatureHashMismatch')}).Count){return $true}
    if(@($Assessment.Signals | Where-Object {$_.Code -eq 'BroadServiceRights' -and $_.Weight -ge 35}).Count){return $true}
    if($codes -contains 'EncodedPowerShell' -and $Assessment.Type -in @('Task','Service','Startup','WmiConsumer','Process')){return $true}
    if($codes -contains 'PeriodicNetworkCode' -and $codes -contains 'NetworkCorroboration' -and $codes -contains 'UnusualExecutionPath'){return $true}
    if($codes -contains 'UnusualExecutionPath' -and @($codes | Where-Object {$_ -in @('BroadFileRights','BroadServiceRights','NullDacl')}).Count){return $true}
    return $false
}
function Get-FocusedArtifactFindings {
    param([object[]]$Assessments,[object[]]$Artifacts,[object[]]$Processes,[object[]]$Connections,[int]$AuditProcessId=$PID,[object]$Intent=$null)
    $coveredProcesses=@{};$scriptGroups=@{}
    foreach($assessment in $Assessments){
        $artifact=@($Artifacts | Where-Object Identity -eq $assessment.Identity | Select-Object -First 1)
        if($assessment.Type -eq 'Process' -and @($assessment.LinkedProcesses | Where-Object ProcessId -eq $AuditProcessId).Count){continue}
        if($assessment.Type -eq 'Task' -and $artifact.Count -and $artifact[0].Details.Enabled -eq $false){continue}
        $currentCodes=@($assessment.Signals | ForEach-Object Code)
        if($assessment.Type -eq 'Process'){
            $covered=@($assessment.LinkedProcesses | Where-Object {$coveredProcesses.ContainsKey([string]$_.ProcessId)})
            if($covered.Count -and -not @($currentCodes | Where-Object {$coveredProcesses[[string]$covered[0].ProcessId] -notcontains $_}).Count){continue}
        }
        $prominent=Test-ProminentArtifact $assessment
        if(-not $prominent -and $assessment.Type -eq 'Task' -and $artifact.Count){
            foreach($action in @($artifact[0].Details.Actions)){
                $runtime=Get-ScriptRuntime $action.Execute '' ($action.Execute+' '+$action.Arguments)
                if($runtime -in @('Python','JavaScript runtime','General-purpose script runtime','Nonstandard Windows scheduler')){$prominent=$true;break}
                if($runtime -in @('PowerShell script or command','Windows Script Host','Windows command script')){
                    $paths=Get-CommandPaths ('"'+$action.Execute+'" '+$action.Arguments) ([string]$action.WorkingDirectory)
                    $scriptPaths=@($paths.Paths | Where-Object {$_ -match '(?i)\.(?:ps1|psm1|vbs|js|cmd|bat)$'})
                    if(@($scriptPaths | Where-Object {$_ -inotmatch ('^'+[regex]::Escape($env:windir)+'\\(?:System32|SysWOW64|WinSxS)\\')}).Count){$prominent=$true;break}
                    if(-not $scriptPaths.Count -and $artifact[0].Name -notlike '\Microsoft\Windows\*'){$prominent=$true;break}
                }
                if([IO.Path]::GetFileName([string]$action.Execute) -in @('cron.exe','crond.exe')){$prominent=$true;break}
            }
        }
        if(-not $prominent){continue}
        $kind=if($assessment.Type -eq 'Process'){'ThreatEvidence'}else{'Persistence'}
        $codes=@($assessment.Signals | ForEach-Object Code)
        $title=if($codes -contains 'KeyboardCapturePatterns'){'Referenced code contains keyboard-capture patterns'}elseif($assessment.Type -eq 'Task'){'Scheduled task launches a script runtime or has suspicious command evidence'}elseif($assessment.Type -eq 'Process'){'Running process has specific suspicious execution evidence'}else{'Persistence entry has specific suspicious execution evidence'}
        $priority=if($codes -contains 'KeyboardCapturePatterns' -or $assessment.Score -ge 55){'High'}else{'Medium'}
        $reason=@($assessment.Signals | Where-Object {$_.Code -notin @('WmiConsumer','SqlStartupProcedure','UnsignedCorroboration')} | ForEach-Object Text) -join ' '
        if(-not $reason){$reason='Enabled scheduled task invokes a general-purpose script runtime or nonstandard scheduler. This is a review lead, not proof of unauthorized activity.'}
        $network=@($assessment.Connections | ForEach-Object {$_.RemoteAddress+':'+$_.RemotePort}) -join ', '
        if($network){$reason+=' Associated established connections: '+$network+'. This does not prove beaconing.'}
        New-TriageFinding $kind $priority $assessment.Identity $title 'Confirm an approved purpose.' $assessment.Command $reason 'Inspect the exact script or executable and task action. Do not execute suspicious files. Validate with endpoint detection and response tooling when available.'
        foreach($process in $assessment.LinkedProcesses){$coveredProcesses[[string]$process.ProcessId]=$codes}
    }
    # Running interpreters are explicitly requested review leads. Group identical
    # command lines so worker processes do not generate duplicate rows.
    foreach($process in $Processes){
        if([int]$process.ProcessId -eq $AuditProcessId -or $coveredProcesses.ContainsKey([string]$process.ProcessId)){continue}
        $runtime=Get-ScriptRuntime $process.ExecutablePath $process.Name $process.CommandLine
        if(-not $runtime){continue}
        $key=$runtime+'|'+$process.CommandLine+'|'+$process.ExecutablePath
        if(-not $scriptGroups.ContainsKey($key)){$scriptGroups[$key]=[pscustomobject]@{Runtime=$runtime;Command=$process.CommandLine;Image=$process.ExecutablePath;ProcessIds=@()}}
        $scriptGroups[$key].ProcessIds+=@([int]$process.ProcessId)
    }
    foreach($group in $scriptGroups.Values){
        $network=@($Connections | Where-Object {$_.OwningProcess -in $group.ProcessIds -and $_.State -eq 'Established' -and -not (Test-LoopbackAddress $_.RemoteAddress)} | ForEach-Object {$_.RemoteAddress+':'+$_.RemotePort} | Select-Object -Unique)
        $evidence='Running '+$group.Runtime+'; process identifiers='+($group.ProcessIds -join ', ')+'. Executable='+$group.Image+'. '
        if($network.Count){$evidence+='Established remote connections: '+($network -join ', ')+'. '}
        if($Intent -and $Intent.Outbound.Mode -in @('Custom','None')){
            $outside=@($Connections | Where-Object {$_.OwningProcess -in $group.ProcessIds -and $_.State -eq 'Established' -and -not (Test-LoopbackAddress $_.RemoteAddress) -and ($Intent.Outbound.Mode -eq 'None' -or -not (Test-ExpectedEndpoint 'TCP' ([int]$_.RemotePort) $Intent.Outbound.Ports))} | ForEach-Object {$_.RemoteAddress+':'+$_.RemotePort} | Select-Object -Unique)
            if($outside.Count){$evidence+='Remote ports outside your declared outbound list (connection direction needs validation): '+($outside -join ', ')+'. '}
        }
        if($Intent -and $Intent.Inbound.Mode -in @('Custom','None')){
            $allowed=@(Get-RolePorts $Intent)+@($Intent.Inbound.Ports)
            $outside=@($Connections | Where-Object {$_.OwningProcess -in $group.ProcessIds -and $_.State -eq 'Listen' -and -not (Test-LoopbackAddress $_.LocalAddress) -and ($Intent.Inbound.Mode -eq 'None' -or -not (Test-ExpectedEndpoint 'TCP' ([int]$_.LocalPort) $allowed))} | ForEach-Object LocalPort | Select-Object -Unique)
            if($outside.Count){$evidence+='Script process listening outside your declared inbound ports: '+($outside -join ', ')+'. '}
        }
        $evidence+='Script execution is observed; unauthorized intent is unknown.'
        New-TriageFinding 'RunningScript' 'Medium' ('RunningScript:'+($group.ProcessIds -join ',')) ($group.Runtime+' is running - confirm its purpose') 'Identify the application or operator that needs this script.' ([string]$group.Command) $evidence 'Review the script path, command, parent process and owner. A running interpreter or connection alone is not a beacon or keylogger verdict.'
    }
}
function Get-RequirementFindings {
    param([object]$Intent,[object]$Data)
    if($null -ne $Intent.DomainController -and $Intent.DomainController -ne ($Data.Discovery.Role -eq 'Domain Controller')){
        New-TriageFinding 'SecurityWeakness' 'High' 'Role:DomainController' 'Domain-controller role differs from your intended role' ([string]$Intent.DomainController) $Data.Discovery.Role 'The detected machine role conflicts with the operator answer.' 'Confirm the machine and intended role before interpreting domain findings.'
    }
    $active=@($Data.Firewall.Networks | ForEach-Object {if([string]$_.NetworkCategory -eq 'DomainAuthenticated'){'Domain'}else{[string]$_.NetworkCategory}} | Select-Object -Unique)
    $disabled=@($Data.Firewall.Profiles | Where-Object {[string]$_.Enabled -eq 'False'})
    $stoppedService=@($Data.Services | Where-Object {$_.Name -eq 'MpsSvc' -and $_.State -in @('Stopped','Paused')})
    if($disabled.Count -or $stoppedService.Count){
        $names=@($disabled | ForEach-Object Name);$onCurrent=@($names | Where-Object {$active -contains [string]$_})
        $priority=if($stoppedService.Count -or $onCurrent.Count -or -not $active.Count){'High'}else{'Medium'}
        $title=if($disabled.Count){'Windows Defender Firewall is off'}else{'Windows Defender Firewall service is not running'}
        $observed='Disabled profiles: '+($names -join ', ')
        if($stoppedService.Count){$observed+='; firewall service state='+$stoppedService[0].State}
        New-TriageFinding 'SecurityWeakness' $priority 'Firewall:Disabled' $title 'Enabled on profiles that protect this server.' $observed ('Current network profiles: '+($active -join ', ')+'. Explicit disabled values were observed; unresolved values were not guessed.') 'Verify the effective profile state and whether this is an approved exception. Disabled protection is the primary issue; ordinary rule breadth is not flagged.'
    }
    $domain=$Data.DomainSecurity
    if($domain.Status -eq 'Collected' -and $domain.ReversibleEncryption -eq $true){New-TriageFinding 'SecurityWeakness' 'High' 'Domain:ReversibleEncryption' 'Domain password policy allows reversible encryption' 'Reversible password encryption disabled unless explicitly required.' ($domain.Domain+'; pwdProperties='+$domain.PwdProperties) 'The domain password-properties flag includes value 16. This weakens password protection; it does not prove which existing passwords use this storage format.' 'Review the effective domain password policy and any legacy authentication requirement. No password contents were read.'}
    if($domain -and @($domain.FineGrainedPolicies).Count){New-TriageFinding 'SecurityWeakness' 'High' 'Domain:FineGrainedReversibleEncryption' 'Fine-grained domain password policies allow reversible encryption' 'Reversible encryption disabled unless explicitly required.' (@($domain.FineGrainedPolicies | ForEach-Object Name) -join '; ') 'Matching password-settings objects were read; group expansion and resultant policy per account were not computed.' 'Inspect affected policy assignments and approved authentication requirements.'}
    if($domain -and @($domain.UserOverrides).Count){
        $enabled=@($domain.UserOverrides | Where-Object {-not $_.Disabled});$priority=if($enabled.Count){'High'}else{'Medium'}
        New-TriageFinding 'SecurityWeakness' $priority 'Domain:UserReversibleEncryption' 'User accounts allow reversible password encryption' 'Per-account reversible encryption disabled unless explicitly required.' ($domain.UserOverrides.Count.ToString()+' matching accounts; '+$enabled.Count+' enabled. Examples: '+(@($domain.UserOverrides | Select-Object -First 8 | ForEach-Object Name) -join ', ')) 'The account-control flag value 128 is set. Full visible results are in the separate domain evidence file.' 'Review each account setting and business requirement. Disabled accounts are included as context.'
    }
    $exclusions=@($Data.Defender | Sort-Object Type,Value -Unique)
    if($exclusions.Count){
        $broad=@($exclusions | Where-Object {($_.Type -eq 'ExclusionPath' -and $_.Value -match '^(?:[A-Za-z]:\\?|\*|[A-Za-z]:\\\*)$') -or ($_.Type -eq 'ExclusionExtension' -and $_.Value -in @('*','exe','dll','ps1','py'))})
        $priority=if($broad.Count){'High'}else{'Medium'}
        New-TriageFinding 'SecurityWeakness' $priority 'Defender:Exclusions' 'Microsoft Defender Antivirus has configured exclusions' 'Every configured exclusion should have an approved purpose.' (@($exclusions | Select-Object -First 12 | ForEach-Object {$_.Type+': '+$_.Value}) -join '; ') ($exclusions.Count.ToString()+' visible exclusions; '+$broad.Count+' cover entire drives or common executable/script types. Exclusions can be legitimate application requirements. Automatic/hidden exclusions may not be visible.') 'Review the exact paths, processes and extensions. Complete results are in DefenderVisibleExclusions.json; no exclusion was removed.'
    }
    foreach($status in $Data.DefenderSecurity.Status){
        $normal=[string]$status.AMRunningMode -eq 'Normal'
        if($normal -and ($status.RealTimeProtectionEnabled -eq $false -or $status.AntivirusEnabled -eq $false)){New-TriageFinding 'SecurityWeakness' 'High' 'Defender:Protection' 'Microsoft Defender Antivirus protection is disabled in active mode' 'Enabled protection when Defender is the active antivirus.' ('Mode='+$status.AMRunningMode+'; real-time protection='+$status.RealTimeProtectionEnabled+'; antivirus='+$status.AntivirusEnabled) 'Passive mode is not treated as this finding because another antivirus may be responsible.' 'Verify approved security software and the effective protection policy.'}
    }
    foreach($threat in @($Data.DefenderSecurity.Threats | Where-Object {$_.IsActive -eq $true})){
        New-TriageFinding 'ThreatEvidence' 'High' ('DefenderThreat:'+$threat.ThreatID) ('Antivirus reports an active threat: '+$threat.ThreatName) 'No active antivirus threat reports.' (@($threat.Resources) -join '; ') ('Microsoft Defender Antivirus reports IsActive=True; execution reported='+$threat.DidThreatExecute+'. Historical inactive detections are not presented as active compromise.') 'Validate the detection, resource and current status using the security tooling. The audit did not start an antivirus scan or remediate.'
    }
    foreach($record in @($Data.Sql.Records | Where-Object Kind -eq 'Configuration')){foreach($setting in @($record.Data | Where-Object {$_.ValueInUse -eq 1 -and $_.name -in @('xp_cmdshell','Ole Automation Procedures')})){New-TriageFinding 'SecurityWeakness' 'Medium' ('SqlConfig:'+$record.Instance+'/'+$setting.name) 'Database instance enables operating-system execution functionality' 'Approved application requirement and restricted invocation permissions.' ($record.Instance+': '+$setting.name+'=1') 'Feature enabled; this does not establish that it was abused.' 'Review feature permissions, related job steps and startup procedures.'}}
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
            if($a.Fields.Command -cne $b.Fields.Command -or $a.Fields.Account -ine $b.Fields.Account){New-TriageFinding 'Review' 'High' $id 'Execution entry differs from the selected baseline' ('Command: '+$b.Fields.Command+'; account: '+$b.Fields.Account) ('Command: '+$a.Fields.Command+'; account: '+$a.Fields.Account) 'Compared command/account fields. Different host-specific identities or approved updates may explain changes.' 'Inspect the exact change and reference provenance.'}
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
    switch($Kind){'SecurityWeakness'{'Security weakness'}'Persistence'{'Persistence to investigate'}'RunningScript'{'Running script to review'}'ThreatEvidence'{'Threat evidence to validate'}'NotAssessed'{'Not assessed'}default{'Review'}}
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
        $observed=[string]$f.Observed
        if($observed.Length -gt 2400){$observed=$observed.Substring(0,2400)+' ... [display truncated; full value is saved separately]'}
        $null=$rows.Append(('<tr data-kind="{0}" data-priority="{1}"><td><b>{1}</b><br>{2}</td><td><b>{3}</b><br><small>{4}</small></td><td><code>{5}</code><details><summary>Why this matters and what to check</summary><p>{6}</p><p><b>Verify:</b> {7}</p></details></td></tr>' -f (Encode-Html $f.Kind),(Encode-Html $f.Priority),(Encode-Display (Get-FriendlyKind $f.Kind)),(Encode-Display $f.Title),(Encode-Display $f.Identity),(Encode-Html $observed),(Encode-Display $f.Evidence),(Encode-Display $f.NextStep)))
    }
    $missing=@($Coverage | Where-Object Status -in @('Unavailable','Partial','NotAssessed'))
    $gapRows=@($missing | Select-Object -First 12 | ForEach-Object {'<li>'+(Encode-Display ($_.Name+': '+$_.Detail))+'</li>'}) -join ''
    $title=Encode-Html ($Discovery.Computer+' - focused security findings')
    $filterScript=Get-ReportFilterScript
    $high=@($Findings | Where-Object {$_.Priority -eq 'High'}).Count
    $review=@($Findings | Where-Object {$_.Priority -eq 'Medium'}).Count
    $html=@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'"><title>$title</title><style>
body{font:15px/1.5 Segoe UI,Arial,sans-serif;margin:0;background:#f1f4f6;color:#173042}header{background:#17364b;color:white;padding:24px 5%}h1{font-size:27px;margin:0}main{padding:20px 5%}.notice{background:#fff7e6;border-left:4px solid #d79b25;padding:12px}table{border-collapse:collapse;width:100%;background:white}td,th{padding:14px;border-bottom:1px solid #d6e0e7;text-align:left;vertical-align:top;word-break:break-word}th{background:#dfe8ee}td:first-child{min-width:120px}tr[data-priority=High]{border-left:4px solid #b53138}input,select,button{padding:9px;margin:5px;border:1px solid #a9bcc9;border-radius:4px}details{margin-top:12px}summary{cursor:pointer;color:#255d80}code{white-space:pre-wrap;word-break:break-word;font:13px Consolas,monospace}small{color:#526b7a}.scroll{overflow-x:auto}#noResults{display:none;background:white;padding:16px}.limits{margin-top:24px;padding:14px;background:white;border:1px solid #d6e0e7}@media print{.controls,#filterWarning{display:none}header{color:black;background:white}}
</style></head><body><header><h1>$title</h1><p>Read-only audit 0.6.0 | $(Encode-Html $Discovery.Caption) | $(Encode-Html $Discovery.Role)</p><p>$high high-priority findings | $review review leads | $($missing.Count) incomplete collection records</p></header><main>
<p class="notice">Settings and behaviors to investigate on a potentially compromised server. Findings distinguish observed weaknesses from leads needing validation. A running script is not automatically malicious, and an open connection does not establish beaconing.</p>
<p id="filterWarning">Filters have not started. If this stays visible, open the saved report in Microsoft Edge with local JavaScript allowed. All findings remain readable.</p><noscript><p>JavaScript is disabled. Every finding is displayed below.</p></noscript>
<div class="controls"><label>Search <input id="query" type="search" disabled aria-label="Search findings"></label><label>Category <select id="kind" disabled aria-label="Finding category"><option value="Actionable">Findings and review leads</option><option value="SecurityWeakness">Security weaknesses</option><option value="Persistence">Persistence to investigate</option><option value="RunningScript">Running scripts to review</option><option value="ThreatEvidence">Threat evidence to validate</option><option value="NotAssessed">Checks not assessed</option><option value="">All categories</option></select></label><label>Priority <select id="priority" disabled aria-label="Priority"><option value="">All priorities</option><option value="High">High</option><option value="Medium">Medium</option><option value="Low">Low</option></select></label><button id="resetFilters" type="button" disabled>Reset filters</button></div>
<p id="resultCount" aria-live="polite">All findings below</p><p id="noResults" role="status">No findings match this view. Try resetting filters. No selected findings does not establish that the machine is clean.</p>
<div class="scroll"><table id="results"><thead><tr><th>Priority / category</th><th>Finding</th><th>Exact observation and verification</th></tr></thead><tbody>$rows</tbody></table></div>
<details class="limits"><summary>Scan limits and missing evidence ($($missing.Count) collection records)</summary><p>This audit cannot rule out memory-only implants, prove a connection is a beacon, or identify every compiled keylogger. Keyboard-capture patterns are static leads; active threat names come from existing Microsoft Defender Antivirus records. Domain results reflect visible directory data. No passwords were collected and no remediation was applied.</p><ul>$gapRows</ul><p>Full collection details are saved separately in Evidence/Coverage.txt. Exact command lines, file hashes, task definitions and machine-readable evidence remain in the Evidence folder; they are not embedded in this report.</p></details>
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
$domainSecurity=Get-DomainSecurityEvidence $discovery
$defenderSecurity=Get-DefenderSecurityEvidence
$admins=@(Collect-Read 'Administrators' {Get-AdminMembers $discovery.Role})
$defender=@(Collect-Read 'DefenderVisibleExclusions' {$preferences=Get-MpPreference;foreach($property in @('ExclusionPath','ExclusionProcess','ExclusionExtension','ExclusionIpAddress')){foreach($value in @($preferences.$property)){if($value){[pscustomobject]@{Type=$property;Value=[string]$value}}}}})
Add-Coverage 'DefenderVisibility' 'Partial' 'Automatic and hidden exclusions can be absent from Get-MpPreference; no exclusion removals are inferred.'
Add-Type -AssemblyName System.Data
$sql=Get-SqlObservations $services;$artifacts+=@($sql.Artifacts)
Add-Coverage 'OutboundDatagrams' 'Partial' 'User Datagram Protocol endpoint inventory has no remote destination addresses or ports. Outbound datagram destination policy is not assessed.'
$data=[pscustomobject]@{Discovery=$discovery;Services=$services;Artifacts=$artifacts;Live=$live;Firewall=$firewall;Admins=$admins;Defender=$defender;Sql=$sql;DomainSecurity=$domainSecurity;DefenderSecurity=$defenderSecurity}
Save-Evidence ([pscustomobject]@{Firewall=@(Get-FirewallReference);Services=@(Get-ServiceReference $intent $services);AllowedRolePorts=@(Get-RolePorts $intent);FirewallComparison=@(Get-FirewallComparison $firewall)}) 'ReferenceDefaults.json'
Save-Evidence $domainSecurity 'DomainSecurity.json';Save-Evidence $defenderSecurity 'DefenderSecurity.json'
Save-Evidence $live 'LiveFinal.json';Save-Evidence $services 'Services.json';Save-Evidence $artifacts 'Artifacts.json';Save-Evidence $firewall 'Firewall.json';Save-Evidence $admins 'Administrators.json';Save-Evidence $defender 'DefenderVisibleExclusions.json';Save-Evidence $sql.Records 'SqlMetadata.json'
$findings=New-Object 'System.Collections.Generic.List[object]'
foreach($f in @(Get-RequirementFindings $intent $data)){$findings.Add($f)}
$assessments=New-Object 'System.Collections.Generic.List[object]'
Write-Host 'Inspecting referenced local files and correlating candidate artifacts...'
foreach($artifact in $artifacts){
    $assessment=Get-ArtifactAssessment $artifact $intent $live.Processes $live.Tcp;$assessments.Add($assessment)

}
foreach($f in @(Get-FocusedArtifactFindings -Assessments $assessments.ToArray() -Artifacts $artifacts -Processes $live.Processes -Connections $live.Tcp -Intent $intent)){$findings.Add($f)}
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
@($script:Coverage | ForEach-Object {(Expand-AuditText ($_.Name+' | '+$_.Status+' | '+$_.Detail))}) | Set-Content -LiteralPath (Join-Path $script:EvidenceDirectory 'Coverage.txt') -Encoding UTF8
Write-TriageReport -Path (Join-Path $OutputDirectory 'index.html') -Discovery $discovery -Intent $intent -Findings $findings.ToArray() -Assessments $assessments.ToArray() -Coverage $script:Coverage.ToArray() -Artifacts $artifacts -Firewall $firewall -Services $services
Write-Host ('Report: '+(Join-Path $OutputDirectory 'index.html')) -ForegroundColor Green
Write-Host ('Reusable intended configuration: '+(Join-Path $OutputDirectory 'ServerIntent.json'))
[pscustomobject]@{Report=(Join-Path $OutputDirectory 'index.html');Intent=(Join-Path $OutputDirectory 'ServerIntent.json');Findings=$findings.Count}
