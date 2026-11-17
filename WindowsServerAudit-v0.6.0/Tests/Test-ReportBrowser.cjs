/* Optional full-browser regression. Requires Playwright and a Chromium browser.
 * Set CHROMIUM_PATH where the browser is installed. */
const assert=require('assert'),{pathToFileURL}=require('url');
const {example}=require('./Build-ExampleReport.cjs');
(async()=>{
 const {chromium}=require('playwright');
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||(process.platform==='linux'?'/usr/bin/chromium':undefined),args:['--no-sandbox']});
 try{
  const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(pathToFileURL(example).href);
  const count=()=>page.locator('#results tbody tr:visible').count();assert.equal(await count(),5);
  await page.fill('#query','python');assert.equal(await count(),1);await page.click('#resetFilters');
  await page.selectOption('#priority','High');assert.equal(await count(),3);await page.selectOption('#kind','RunningScript');assert.equal(await count(),0);
  assert(await page.locator('#noResults').isVisible());assert.equal(errors.length,0);console.log('Browser checks passed.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e.message);process.exitCode=1;});
