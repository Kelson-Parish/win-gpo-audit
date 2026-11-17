/* Build synthetic report from the real PowerShell report and filter templates.
 * This does not execute PowerShell string interpolation or any Windows collector. */
const fs=require('fs'),path=require('path'),assert=require('assert');
const root=path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(root,'Invoke-WindowsServerAudit.ps1'),'utf8').replace(/\r\n/g,'\n');
const javascript=source.match(/function Get-ReportFilterScript \{[\s\S]*?return @'\n([\s\S]*?)\n'@/)[1];
assert(!/\b(?:const|let)\b|=>|\.includes\(|for\s*\([^)]*\bof\b/.test(javascript));
const template=source.match(/\$html=@"\n([\s\S]*?)\n"@/)[1];
const escape=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const findings=[
 {kind:'SecurityWeakness',priority:'High',title:'Windows Defender Firewall is off',observed:'Domain profile is disabled'},
 {kind:'SecurityWeakness',priority:'Medium',title:'Microsoft Defender Antivirus has configured exclusions',observed:'C:\\Example'},
 {kind:'Persistence',priority:'High',title:'Suspicious scheduled task',observed:'Synthetic encoded command'},
 {kind:'RunningScript',priority:'Medium',title:'Python is running - confirm its purpose',observed:'python.exe C:\\Example\\app.py'},
 {kind:'ThreatEvidence',priority:'High',title:'Antivirus reports an active threat',observed:'Synthetic threat record'},
 {kind:'NotAssessed',priority:'Low',title:'Some checks unavailable',observed:'<script>window.injected=1</script>'}
];
const rows=findings.map(f=>`<tr data-kind="${f.kind}" data-priority="${f.priority}"><td>${f.priority}</td><td>${escape(f.title)}</td><td><code>${escape(f.observed)}</code><details><summary>Why this matters and what to check</summary><p>Synthetic evidence only. No machine was scanned.</p></details></td></tr>`).join('');
const values={
 '$(Encode-Html $Discovery.Caption)':'SYNTHETIC EXAMPLE - NOT A SERVER SCAN',
 '$(Encode-Html $Discovery.Role)':'Member Server','$($missing.Count)':'1','$high':'3','$review':'2',
 '$title':'Synthetic focused findings - filter demonstration','$rows':rows,'$gapRows':'<li>Example unavailable collector.</li>','$filterScript':javascript
};
let html=template;for(const key of Object.keys(values).sort((a,b)=>b.length-a.length))html=html.split(key).join(values[key]);
assert(!/\$\(|\$(?:rows|title|filterScript)/.test(html));assert(!html.includes('<pre>'));
const example=path.join(root,'ExampleReport.html');fs.writeFileSync(example,html);
module.exports={source,javascript,html,findings,example};
