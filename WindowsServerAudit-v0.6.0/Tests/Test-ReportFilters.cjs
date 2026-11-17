/* node Tests/Test-ReportFilters.cjs
 * Runs actual filter JavaScript with a document fixture. No browser dependency.
 * This is logic/event testing, not PowerShell generation or browser rendering. */
const vm=require('vm'),assert=require('assert');
const {javascript,html}=require('./Build-ExampleReport.cjs');
const decode=s=>s.replace(/<[^>]+>/g,' ').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&amp;/g,'&');
function element(attributes,text){return {style:{},value:'',disabled:true,textContent:decode(text||''),innerHTML:'',events:{},getAttribute(n){return attributes[n];},addEventListener(n,f){this.events[n]=f;}};}
const markup=html.match(/<table id="results">[\s\S]*?<tbody>([\s\S]*?)<\/tbody>/)[1];
const rows=[...markup.matchAll(/<tr data-kind="([^"]+)" data-priority="([^"]+)"[^>]*>([\s\S]*?)<\/tr>/g)].map(m=>element({'data-kind':m[1],'data-priority':m[2]},m[3]));
assert.equal(rows.length,6);const ids={};for(const id of ['query','kind','priority','resetFilters','resultCount','noResults','filterWarning']){assert(html.includes('id="'+id+'"'));ids[id]=element({},'');}
ids.kind.value='Actionable';
const document={getElementById(id){assert(ids[id],id);return ids[id];},querySelectorAll(selector){assert.equal(selector,'#results tbody tr[data-kind]');return rows;}};
const context=vm.createContext({document});vm.runInContext('String.prototype.includes=undefined; Array.from=undefined;',context);new vm.Script(javascript).runInContext(context);
const count=()=>rows.filter(r=>r.style.display!=='none').length;
function change(id,value,event='change'){ids[id].value=value;assert(ids[id].events[event]);ids[id].events[event]();}
function reset(){ids.resetFilters.events.click();}
let passed=0;
assert.equal(count(),5);assert.equal(ids.query.disabled,false);assert.equal(ids.filterWarning.style.display,'none');passed++;
change('priority','High');assert.equal(count(),3);passed++;
change('kind','RunningScript');assert.equal(count(),0);assert.equal(ids.noResults.style.display,'block');passed++;
reset();assert.equal(count(),5);assert.equal(ids.noResults.style.display,'none');passed++;
change('query',' PyThOn ','input');assert.equal(count(),1);passed++;
reset();change('kind','SecurityWeakness');assert.equal(count(),2);passed++;
change('kind','Persistence');assert.equal(count(),1);passed++;
change('kind','');change('priority','Low');change('query','<script>','keyup');assert.equal(count(),1);assert.equal(context.injected,undefined);passed++;
reset();change('kind','NotAssessed');assert.equal(ids.resultCount.innerHTML,'Showing 1 of 6 findings');passed++;
reset();change('query','not present','change');assert.equal(count(),0);passed++;
assert(!html.includes('<script>window.injected=1</script>'));assert(!html.includes('<pre>'));assert(!html.includes('Collected execution entries'));passed++;
console.log(JSON.stringify({passedGroups:passed,scope:'Actual report filter logic, combined controls, escaping and compact-template guards',limitation:'Document fixture; Windows execution and full browser rendering are not tested.'},null,2));
