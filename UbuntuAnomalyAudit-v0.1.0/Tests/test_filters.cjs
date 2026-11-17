/* Dependency-free filter logic checks. Does not claim full browser rendering. */
const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('assert'),cp=require('child_process');
cp.execFileSync(process.env.PYTHON||'python3',['-B',path.join(__dirname,'build_example.py')]);
const source=fs.readFileSync(path.join(__dirname,'..','ExampleReport.html'),'utf8');
const code=source.match(/<script>([\s\S]*?)<\/script>/)[1];
assert(!/\b(?:const|let)\b|=>|\.includes\(/.test(code));
const decode=s=>s.replace(/<[^>]+>/g,' ').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
function element(attrs,text){return {disabled:true,value:'',style:{},textContent:decode(text||''),innerHTML:'',events:{},getAttribute(k){return attrs[k]},addEventListener(k,f){this.events[k]=f}}}
const rows=[...source.matchAll(/<tr data-kind="([^"]+)" data-priority="([^"]+)">([\s\S]*?)<\/tr>/g)].map(m=>element({'data-kind':m[1],'data-priority':m[2]},m[3]));
const ids={};for(const id of ['query','kind','priority','count','empty','reset','filterWarning']){assert(source.includes('id="'+id+'"'));ids[id]=element({},'')}
const document={getElementById(k){assert(ids[k]);return ids[k]},querySelectorAll(k){assert.equal(k,'#results tbody tr[data-kind]');return rows}};
const context=vm.createContext({document});vm.runInContext('String.prototype.includes=undefined;Array.from=undefined;',context);new vm.Script(code).runInContext(context);
const count=()=>rows.filter(r=>r.style.display!=='none').length;
function change(id,value,event='change'){ids[id].value=value;ids[id].events[event]()}
function reset(){ids.reset.events.click()}
let passed=0;
assert.equal(count(),4);assert.equal(ids.query.disabled,false);assert.equal(ids.filterWarning.style.display,'none');passed++;
change('priority','High');assert.equal(count(),3);passed++;
change('kind','RunningScript');assert.equal(count(),0);assert.equal(ids.empty.style.display,'block');passed++;
reset();assert.equal(count(),4);passed++;
change('query','  PyThOn  ','input');assert.equal(count(),1);passed++;
reset();change('kind','Persistence');assert.equal(count(),1);passed++;
reset();change('query','<script>','keyup');assert.equal(count(),1);assert.equal(context.injected,undefined);passed++;
reset();assert.equal(ids.count.innerHTML,'Showing 4 of 4 findings');passed++;
assert(!source.includes('<script>window.injected=1</script>'));assert(!source.includes('<pre>'));passed++;
console.log('Passed '+passed+' JavaScript filter fixture groups. Full browser rendering remains untested.');
