// Development-only browser test. Uses an explicit fixture API, never a real VPN.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const html = fs.readFileSync(path.join(__dirname, 'panel.html'), 'utf8');
const dnsCatalog = JSON.parse(require('node:child_process').execFileSync('python', ['-c', 'import json,panel; print(json.dumps(panel.DNS_PRESETS))'], {cwd:__dirname,encoding:'utf8'}));
const now = Math.floor(Date.now() / 1000);
const clients = [
 {id:'0123456789abcdef',name:'Diana-laptop',address:'10.203.240.2',enabled:true,status:'recent',recent:true,handshake:now-30,received:18000000,sent:64000000,receivedRate:12000,sentRate:48000,hints:[]},
 {id:'1123456789abcdef',name:'Pocket-stargazer',address:'10.203.240.3',enabled:true,status:'idle',recent:false,handshake:now-700,received:4200000,sent:9400000,hints:[{level:'info',text:'The device may be idle or offline.'}]},
 {id:'2123456789abcdef',name:'Archive-tablet',address:'10.203.240.4',enabled:false,status:'paused',recent:false,hints:[{level:'info',text:'Paused. Keys are preserved.'}]}
].map(c=>({...c,tuning:{profile:'default',mtu:1280,keepalive:25,dns:'1.1.1.1, 1.0.0.1'},dnsOverride:''}));
let savedPresetCount = 0;
function snapshot(){return {host:'vpn.example.com',port:51820,listenPort:51820,dns:'1.1.1.1, 1.0.0.1',mtu:1280,version:'UI-TEST-FIXTURE',error:null,unmanaged:0,clients,summary:{total:clients.length,enabled:clients.filter(c=>c.enabled).length,recent:clients.filter(c=>c.status==='recent').length,received:22200000,sent:73400000},traffic:{time:now,received:12000,sent:48000,history:Array.from({length:24},(_,i)=>({time:now-115+i*5,received:2000+(i%5)*2600,sent:10000+(i%7)*6000}))},profiles:{compatible:{label:'Compatibility',mtu:1280,keepalive:25},small:{label:'Small packets - IPv4 only',mtu:1200,keepalive:25}},connectionPresets:{},savedDnsPresets:{},dnsPresets:dnsCatalog};}
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.BROWSER_EXE||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 const page=await browser.newPage({viewport:{width:1440,height:1100},reducedMotion:'reduce'});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('https://diana.test/**',async route=>{
  const req=route.request(),url=new URL(req.url()),body=req.method()==='POST'?req.postDataJSON():null;
  let result={ok:true},type='application/json';
  if(url.pathname==='/')return route.fulfill({status:200,contentType:'text/html',body:html,headers:{'Content-Security-Policy':"default-src 'self'; img-src 'self' data: blob:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'"}});
  if(url.pathname==='/api/status')result=snapshot();
  else if(url.pathname==='/api/activity')result=[{time:now-30,text:'Created client Diana-laptop'}];
  else if(url.pathname==='/api/diagnostics')result={checks:[{label:'IPv4 forwarding',ok:true,detail:'1'},{label:'VPN internet NAT rule',ok:true,detail:'Present'}],note:'UI test fixture: not a real server diagnostic.'};
  else if(url.pathname.endsWith('/qr.svg'))return route.fulfill({status:200,contentType:'image/svg+xml',body:'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><path d="M0 0h100v100H0z" fill="white"/><path d="M10 10h20v20H10zM70 10h20v20H70zM10 70h20v20H10zM50 50h10v10H50z"/></svg>'});
  else if(url.pathname==='/api/clients'&&body){clients.push({...clients[0],id:'3123456789abcdef',name:body.name,address:'10.203.240.5',status:'new',handshake:0});}
  else if(url.pathname.endsWith('/details')){const c=clients.find(c=>url.pathname.includes(c.id));if(body.name)c.name=body.name;if(typeof body.enabled==='boolean'){c.enabled=body.enabled;c.status=c.enabled?'recent':'paused';}}
  else if(url.pathname==='/api/clients/bulk'){for(const c of clients)if(body.ids.includes(c.id)){c.enabled=body.action==='enable';c.status=c.enabled?'recent':'paused';}}
  else if(url.pathname==='/api/settings'){assert.equal(body.dns,dnsCatalog.begzar.dns);}
  else if(url.pathname==='/api/presets')savedPresetCount++;
  else if(url.pathname.endsWith('/tuning')){const c=clients.find(c=>url.pathname.includes(c.id));c.tuning={profile:body.profile,mtu:Number(body.mtu),keepalive:Number(body.keepalive),dns:body.dns||'1.1.1.1'};}
  return route.fulfill({status:200,contentType:type,body:JSON.stringify(result)});
 });
 try{
  await page.goto('https://diana.test/');await page.waitForFunction(()=>document.querySelector('#metric-total').textContent==='3');
  assert.equal(await page.locator('#server-status').textContent(),'WireGuard responding');
  await page.screenshot({path:process.env.SCREENSHOT_PATH||path.join(require('node:os').tmpdir(),'diana-overview-fixture.png'),fullPage:true});
  await page.locator('[data-view=devices]').click();assert.equal(await page.locator('.peer-card').count(),3);
  await page.locator('#search').fill('Pocket');assert.equal(await page.locator('.peer-card').count(),1);await page.locator('#search').fill('');
  await page.locator('#filter').selectOption('paused');assert.equal(await page.locator('.peer-card').count(),1);await page.locator('#filter').selectOption('all');
  const first=()=>page.locator('.peer-card').filter({has:page.locator('.peer-name',{hasText:'Diana-laptop'})});
  await first().getByRole('button',{name:'Pause',exact:true}).click();await page.waitForFunction(()=>STATE.clients[0].enabled===false);assert.equal(await first().getByRole('button',{name:'Resume',exact:true}).count(),1);
  await first().getByRole('button',{name:'Resume',exact:true}).click();await page.waitForFunction(()=>STATE.clients[0].enabled===true);
  await first().getByRole('button',{name:'QR code',exact:true}).click();await page.locator('#qr-dialog').waitFor({state:'visible'});assert.ok((await page.locator('#qr-image').getAttribute('src')).startsWith('blob:'));await page.locator('#qr-dialog [data-close]').click();
  await first().locator('summary').click();const form=first().locator('form');await form.locator('select').first().selectOption('custom');await form.locator('input[type=number]').first().fill('1200');await form.getByRole('button',{name:'Save device settings'}).click();await page.waitForFunction(()=>STATE.clients[0].tuning.mtu===1200);
  await page.locator('#add-device').click();await page.locator('#create input[name=name]').fill('New-device');await page.locator('#create .primary').click();await page.waitForFunction(()=>STATE.clients.length===4);
  await page.locator('[data-view=presets]').click();assert.equal(await page.locator('.dns-card').count(),34);
  await page.locator('#dns-region').selectOption('Iran');assert.equal(await page.locator('.dns-card').count(),9);
  await page.locator('#dns-search').fill('Radar');assert.equal(await page.locator('.dns-card').count(),1);assert.ok((await page.locator('.dns-card').textContent()).includes('foreign VPS'));
  await page.locator('#dns-search').fill('');await page.locator('#dns-region').selectOption('Global');await page.locator('#dns-category').selectOption('Family');assert.equal(await page.locator('.dns-card').count(),7);
  await page.locator('#dns-region').selectOption('all');await page.locator('#dns-category').selectOption('all');await page.locator('#dns-search').fill('Begzar');await page.locator('.dns-card').getByRole('button',{name:'Set as default'}).click();await page.locator('#confirm-submit').click();await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('Default DNS saved'));
  await page.locator('#dns-search').fill('');await page.locator('#connection-preset input[name=name]').fill('Mobile stable');await page.locator('#connection-preset input[name=mtu]').fill('1200');await page.locator('#connection-preset button').click();await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('Preset saved'));assert.equal(savedPresetCount,1);
  await page.locator('[data-view=tools]').click();await page.locator('#diagnose').click();await page.locator('.diagnostic-row').first().waitFor();assert.equal(await page.locator('.diagnostic-row').count(),2);
  await page.locator('[data-view=activity]').click();await page.locator('.activity-row').waitFor();
  await page.locator('#theme').click();assert.equal(await page.locator('html').getAttribute('data-theme'),'dawn');await page.locator('#theme').click();
  await page.setViewportSize({width:390,height:844});await page.locator('[data-view=overview]').click();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Mobile page overflows horizontally');
  await page.locator('[data-view=presets]').click();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Mobile catalog overflows');
  await page.screenshot({path:process.env.MOBILE_SCREENSHOT_PATH||path.join(require('node:os').tmpdir(),'diana-mobile-fixture.png'),fullPage:true});
  assert.deepEqual(errors,[]);console.log('PASS: dashboard, search/filter, pause/resume, QR, low-MTU edit, create, presets, diagnostics, activity, theme, mobile overflow; no browser errors.');
 }finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});

