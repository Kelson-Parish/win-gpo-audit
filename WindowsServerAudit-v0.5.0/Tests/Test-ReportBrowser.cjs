/* Developer regression: node Tests/Test-ReportBrowser.cjs
 * Requires Playwright and Chromium. Reads the actual PowerShell HTML/JavaScript
 * templates, injects synthetic rows, then exercises their browser behavior.
 * It does not execute PowerShell or claim to validate PowerShell HTML rendering.
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { pathToFileURL } = require('url');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'Invoke-WindowsServerAudit.ps1'), 'utf8').replace(/\r\n/g, '\n');
const javascript = source.match(/function Get-ReportFilterScript \{[\s\S]*?return @'\n([\s\S]*?)\n'@/)[1];
assert(!/\b(?:const|let)\b|=>|\.includes\(|for\s*\([^)]*\bof\b/.test(javascript), 'Report JavaScript must retain older-browser syntax');
const template = source.match(/\$html=@"\n([\s\S]*?)\n"@/)[1];
const escape = value => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const evidence = [
  { kind:'SuspiciousArtifact', priority:'High', name:'Threat service', text:'Example public-directory execution' },
  { kind:'SuspiciousArtifact', priority:'Medium', name:'Example task', text:'Encoded command text' },
  { kind:'RequirementViolation', priority:'High', name:'Domain-controller role', text:'Expected role differs' },
  { kind:'Review', priority:'Medium', name:'Example listener', text:'Transmission Control Protocol port 4444' },
  { kind:'Information', priority:'Low', name:'Managed firewall policy', text:'Local rules are not merged' },
  { kind:'NotAssessed', priority:'Low', name:'Coverage', text:'Example missing evidence <script>window.injected=1</script>' }
];
const rows = evidence.map(f=>`<tr data-kind="${f.kind}" data-priority="${f.priority}"><td>${f.priority}<br>${f.kind}</td><td>${escape(f.name)}</td><td>Fixture</td><td>${escape(f.text)}</td><td>Synthetic evidence</td><td>Review</td></tr>`).join('');
const cards = evidence.filter(f=>f.kind==='SuspiciousArtifact').map(f=>`<details data-kind="${f.kind}" data-priority="${f.priority}"><summary>${escape(f.name)}</summary><p>${escape(f.text)}</p></details>`).join('');
const replacements = {
  '$(Encode-Html $Discovery.Caption)':'SYNTHETIC EXAMPLE - NOT A SERVER SCAN',
  '$(Encode-Html $Discovery.Role)':'Member Server',
  '$(Encode-Html $Discovery.Build)':'fixture',
  '$($Artifacts.Count)':'2', '$title':'Synthetic Windows Server report - filter example',
  '$rows':rows, '$cards':cards,
  '$coverageRows':'<tr><td>Example collector</td><td>Not assessed</td><td>Synthetic report only.</td></tr>',
  '$firewallRows':'<tr><td>Domain</td><td>Default action for unmatched outbound traffic</td><td>Allow</td><td>Allow</td><td>Matches Windows starting default</td></tr>',
  '$serviceRows':'<tr><td>Windows Process Activation Service [WAS]</td><td>Running</td><td>Automatic or Manual</td><td>LocalSystem</td><td>Website role</td></tr>',
  '$rolePorts':'TCP (Transmission Control Protocol):135; TCP (Transmission Control Protocol):445',
  '$fileJson':'[]', '$intentJson':'{"ExampleOnly": true}', '$inventoryRows':'', '$filterScript':javascript
};
let html = template;
for (const key of Object.keys(replacements).sort((a,b)=>b.length-a.length)) html = html.split(key).join(replacements[key]);
assert(!/\$\(|\$(?:rows|cards|title|filterScript)/.test(html));
const example = path.join(root, 'ExampleReport.html');
fs.writeFileSync(example, html);
if (!process.env.GENERATE_ONLY) (async()=>{
  const { chromium } = require('playwright');
  const browser = await chromium.launch({ executablePath:process.env.CHROMIUM_PATH || (process.platform === 'linux' ? '/usr/bin/chromium' : undefined), headless:true, args:['--no-sandbox'] });
  let groups = 0;
  try {
    const page = await browser.newPage(); const errors=[]; const requests=[];
    page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>requests.push(r.url()));
    await page.goto(pathToFileURL(example).href);
    const visibleRows=()=>page.locator('#results tbody tr:visible').count();
    const visibleCards=()=>page.locator('#candidatesList details:visible').count();
    assert.equal(await visibleRows(),4);assert.equal(await visibleCards(),2);assert.equal(await page.locator('#filterWarning').isVisible(),false);groups++;
    await page.selectOption('#priority','High');assert.equal(await visibleRows(),2);assert.equal(await visibleCards(),1);groups++;
    await page.selectOption('#kind','Review');assert.equal(await visibleRows(),0);assert.equal(await page.locator('#noResults').isVisible(),true);groups++;
    await page.click('#resetFilters');assert.equal(await visibleRows(),4);assert.equal(await visibleCards(),2);groups++;
    await page.fill('#query','  ThReAt  ');assert.equal(await visibleRows(),1);assert.equal(await visibleCards(),1);groups++;
    await page.click('#resetFilters');await page.selectOption('#kind','Information');assert.equal(await visibleRows(),1);assert.equal(await visibleCards(),0);groups++;
    await page.selectOption('#kind','');await page.selectOption('#priority','Low');assert.equal(await visibleRows(),2);groups++;
    await page.fill('#query','<script>');assert.equal(await visibleRows(),1);assert.equal(await page.evaluate(()=>window.injected),undefined);groups++;
    assert.equal(errors.length,0,errors.join('\n'));assert.equal(requests.filter(url=>/^https?:/.test(url)).length,0);groups++;
    const noScript = await browser.newContext({javaScriptEnabled:false});
    const p=await noScript.newPage();await p.goto(pathToFileURL(example).href);
    assert.equal(await p.locator('#results tbody tr:visible').count(),6);assert.equal(await p.locator('#query').isDisabled(),true);assert.equal(await p.locator('#filterWarning').isVisible(),true);await noScript.close();groups++;
    const legacy=await browser.newPage();
    await legacy.addInitScript(()=>{String.prototype.includes=undefined;Array.from=undefined;});
    await legacy.goto(pathToFileURL(example).href);await legacy.fill('#query','threat');assert.equal(await legacy.locator('#results tbody tr:visible').count(),1);groups++;
    console.log(JSON.stringify({passedGroups:groups, browser:'Chromium', checked:'Search, category, priority, combined filters, reset, count/empty state, artifact cards, escaped evidence, no external requests, disabled scripts, and absent modern helpers', limitation:'Actual PowerShell generation and Windows collectors were not executed.'},null,2));
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
