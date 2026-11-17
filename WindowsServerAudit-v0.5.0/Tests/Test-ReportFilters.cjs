/* Dependency-free JavaScript regression tests.
 * node Tests/Test-ReportFilters.cjs
 * Executes the report's actual JavaScript in a document fixture. This validates
 * logic/event handling, not a browser's rendering or Windows PowerShell output.
 */
const fs=require('fs'), path=require('path'), vm=require('vm'), assert=require('assert'), cp=require('child_process');
const root=path.resolve(__dirname,'..');
cp.execFileSync(process.execPath,[path.join(__dirname,'Test-ReportBrowser.cjs')],{env:Object.assign({},process.env,{GENERATE_ONLY:'1'})});
const html=fs.readFileSync(path.join(root,'ExampleReport.html'),'utf8');
const source=fs.readFileSync(path.join(root,'Invoke-WindowsServerAudit.ps1'),'utf8').replace(/\r\n/g,'\n');
const code=source.match(/function Get-ReportFilterScript \{[\s\S]*?return @'\n([\s\S]*?)\n'@/)[1];
const decode=s=>s.replace(/<[^>]+>/g,' ').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&amp;/g,'&');
function element(attributes,text){return {style:{},value:'',disabled:true,textContent:decode(text||''),innerHTML:'',events:{},getAttribute(name){return attributes[name];},addEventListener(name,handler){this.events[name]=handler;}};}
const rowMarkup=html.match(/<table id="results">[\s\S]*?<tbody>([\s\S]*?)<\/tbody>/)[1];
const cardMarkup=html.match(/<div id="candidatesList">([\s\S]*?)<\/div>/)[1];
function parse(markup,tag){return [...markup.matchAll(new RegExp('<'+tag+' data-kind="([^"]+)" data-priority="([^"]+)"[^>]*>([\\s\\S]*?)<\\/'+tag+'>','g'))].map(m=>element({'data-kind':m[1],'data-priority':m[2]},m[3]));}
const rows=parse(rowMarkup,'tr'),cards=parse(cardMarkup,'details');
assert.equal(rows.length,6);assert.equal(cards.length,2);
const ids={};for(const id of ['query','kind','priority','resetFilters','resultCount','noResults','filterWarning']){assert(html.includes('id="'+id+'"'));ids[id]=element({},'');}
ids.kind.value='Actionable';
const document={getElementById(id){assert(ids[id],id);return ids[id];},querySelectorAll(selector){if(selector==='#results tbody tr[data-kind]')return rows;if(selector==='#candidatesList details[data-kind]')return cards;throw Error(selector);}};
const context=vm.createContext({document});
vm.runInContext('String.prototype.includes=undefined; Array.from=undefined;',context);
new vm.Script(code).runInContext(context);
const count=()=>rows.filter(r=>r.style.display!=='none').length;
const cardCount=()=>cards.filter(r=>r.style.display!=='none').length;
function change(id,value,event='change'){ids[id].value=value;assert(ids[id].events[event]);ids[id].events[event]();}
function reset(){ids.resetFilters.events.click();}
let passed=0;
assert.equal(count(),4);assert.equal(cardCount(),2);assert.equal(ids.filterWarning.style.display,'none');assert.equal(ids.query.disabled,false);passed++;
change('priority','High');assert.equal(count(),2);assert.equal(cardCount(),1);passed++;
change('kind','Review');assert.equal(count(),0);assert.equal(ids.noResults.style.display,'block');passed++;
reset();assert.equal(count(),4);assert.equal(cardCount(),2);assert.equal(ids.noResults.style.display,'none');passed++;
change('query','  ThReAt  ','input');assert.equal(count(),1);assert.equal(cardCount(),1);passed++;
reset();change('kind','Information');assert.equal(count(),1);assert.equal(cardCount(),0);passed++;
change('kind','');change('priority','Low');assert.equal(count(),2);passed++;
change('query','<script>','keyup');assert.equal(count(),1);assert.equal(context.injected,undefined);passed++;
reset();change('kind','NotAssessed');assert.equal(count(),1);assert.equal(ids.resultCount.innerHTML,'Showing 1 of 6 findings');passed++;
reset();change('query','no such value','change');assert.equal(count(),0);assert.equal(cardCount(),0);passed++;
assert(!html.includes('<script>window.injected=1</script>'));assert(html.includes('<noscript>'));assert(html.includes('connect-src \'none\''));passed++;
console.log(JSON.stringify({passedGroups:passed,tests:'Search input/keyup/change, category, priority, combined filters, reset, counts, no-match notice, artifact cards, escaped evidence and missing modern helpers',limitation:'Document fixture execution; full browser rendering, PowerShell generation and Windows collectors were not executed.'},null,2));
