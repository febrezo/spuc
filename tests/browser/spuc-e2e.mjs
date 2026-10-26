import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = 'http://127.0.0.1:18091';
const pattern = "[process:name = 'qa_spuc_stage4c_unique.exe']";
const createdTitle = 'SPUC QA Stage 4C created';
const editedTitle = 'SPUC QA Stage 4C edited';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function check(value, label) { if (!value) throw new Error('FAIL: ' + label); console.log('PASS: ' + label); }
async function rules() {
  const response = await fetch(root + '/api/rules?page=1&page_size=400');
  check(response.status === 200, 'GET /api/rules HTTP 200');
  return (await response.json()).entries || [];
}
let server, browser, page;
const logs = [];
let step = 'startup';
try {
  const config = await mkdtemp(join(tmpdir(), 'spuc-qa4c-config-'));
  await mkdir(join(config, 'cache'), { recursive: true });
  server = spawn('/usr/local/bin/spuc', [
    'web', '--host', '127.0.0.1', '--port', '18091',
    '--admin-user', 'qa-local', '--admin-password', 'qa-only-synthetic',
    '--no-login', '--no-open'
  ], { env: { ...process.env, HOME: config, SPUC_CONFIG_DIR: config, XDG_CONFIG_HOME: join(config, 'xdg'), XDG_CACHE_HOME: join(config, 'cache') }, stdio: ['ignore','pipe','pipe'] });
  server.stdout.on('data', chunk => logs.push(chunk.toString().slice(0, 500)));
  server.stderr.on('data', chunk => logs.push(chunk.toString().slice(0, 500)));
  let healthy = false;
  for (let i=0;i<120;i++) {
    if (server.exitCode !== null) throw new Error('Servidor SPUC cerrado prematuramente: ' + server.exitCode);
    try { if ((await fetch(root+'/healthz')).status === 200) { healthy=true; break; } } catch {}
    await delay(200);
  }
  check(healthy, 'SPUC HTTP en loopback del contenedor aislado');
  for (const [path,status] of Object.entries({
    '/healthz':200,'/':200,'/api/bootstrap':200,'/api/overview':200,
    '/api/abilities':404,'/api/adversaries':404
  })) {
    const result=await fetch(root+path);
    check(result.status===status, `HTTP ${status} ${path}`);
  }
  const overview=await (await fetch(root+'/api/overview')).json();
  check('rules_total' in overview.kpis && 'targets' in overview.kpis,'overview KPI contract');
  const initial = await rules();
  check(initial.length === 0, 'catálogo sintético vacío al comenzar');

  browser = await chromium.launch({ headless:true, args:['--no-sandbox','--disable-dev-shm-usage'] });
  const context = await browser.newContext({ viewport:{width:1440,height:900}, locale:'en-US' });
  page = await context.newPage();
  const errors=[], legacy=[], severe=[];
  page.on('pageerror', e => errors.push(String(e.message)));
  page.on('request', req => {
    try { if (/^\/api\/(abilities|adversaries)(\/|$)/.test(new URL(req.url()).pathname)) legacy.push(req.url()); } catch {}
  });
  page.on('response', response => {
    try { if (new URL(response.url()).pathname.startsWith('/api/') && response.status() >= 500) severe.push(response.url()+' '+response.status()); } catch {}
  });
  step='open-login';
  await page.goto(root, { waitUntil:'domcontentloaded', timeout:30000 });
  await page.locator('#boot-enter-button').waitFor({state:'visible',timeout:25000});
  await page.locator('#boot-enter-button').click();
  await page.locator('#panel-home.active').waitFor({state:'visible',timeout:20000});
  console.log('PASS: entrada en la aplicación');

  // Regress the full navigation menu before exercising write operations.
  // This checks the same retired-route fallback and KPI contract as Gate 3C.
  step='legacy-route-and-navigation';
  await page.evaluate(() => sessionStorage.setItem('spuc-web-last-route','adversaries-catalog'));
  await page.reload({waitUntil:'domcontentloaded'});
  await page.locator('#boot-enter-button').waitFor({state:'visible',timeout:20000});
  await page.locator('#boot-enter-button').click();
  await page.locator('#panel-home.active').waitFor({state:'visible',timeout:20000});
  console.log('PASS: legacy route falls back to Home');
  for (const name of ['dashboard','rules','rulelab','stix-objects','learning','settings']) {
    await page.locator(`.nav-item[data-route="${name}"]`).click();
    await page.locator(`#panel-${name}.active`).waitFor({state:'visible',timeout:20000});
    if (name==='dashboard') {
      await page.waitForFunction(()=>document.querySelectorAll('#kpi-grid .kpi-card').length===2);
      const value=await page.locator('#kpi-grid').innerText();
      check(!/undefined|NaN/.test(value),'dashboard with two valid KPIs');
    }
    console.log('PASS: navigation '+name);
  }


  step='create-in-rulelab';
  await page.locator('.nav-item[data-route="rulelab"]').click();
  await page.locator('#panel-rulelab.active').waitFor({state:'visible'});
  await page.locator('#rulelab-input').fill(pattern);
  await page.waitForFunction(() => document.getElementById('rulelab-save')?.disabled === false, null, {timeout:25000});
  await page.locator('#rulelab-save').click();
  await page.locator('#rulelab-save-dialog[open]').waitFor({state:'visible'});
  await page.locator('#rulelab-title').fill(createdTitle);
  await page.locator('#rulelab-description').fill('Synthetic browser-created test rule');
  await page.locator('#rulelab-tlp').selectOption('TLP:AMBER');
  await page.locator('#rulelab-pap').selectOption('PAP:GREEN');
  const save1=page.waitForResponse(r=>r.url().endsWith('/api/rules/save')&&r.request().method()==='POST', {timeout:20000});
  await page.locator('#rulelab-save-submit').click();
  check((await save1).status() === 200,'creación mediante controles y POST real');
  await page.locator('#rulelab-save-dialog').waitFor({state:'hidden'});
  let found=(await rules()).filter(x=>x.rule === pattern);
  check(found.length === 1 && found[0].name === createdTitle,'creación persistida y única');
  const id=found[0].id;
  check(found[0].tlp === 'TLP:AMBER' && found[0].pap === 'PAP:GREEN', 'TLP/PAP de formulario preservados');

  step='browse-rule-and-edit';
  await page.locator('.nav-item[data-route="rules"]').click();
  await page.locator('#panel-rules.active').waitFor({state:'visible'});
  await page.locator('#rules-view-cards').click();
  await page.locator(`#rules-cards [data-rule-card-id="${id}"]`).waitFor({state:'visible',timeout:20000});
  await page.locator(`#rules-cards [data-rule-card-id="${id}"] [data-action="rule-show"]`).click();
  await page.locator('#detail-dialog[open]').waitFor({state:'visible'});
  await page.locator('#detail-rule-edit-inline').click();
  await page.locator('#panel-rulelab.active').waitFor({state:'visible'});
  check(await page.locator('#rulelab-input').inputValue() === pattern, 'edición carga el patrón correcto');
  await page.locator('#rulelab-save').click();
  await page.locator('#rulelab-save-dialog[open]').waitFor({state:'visible'});
  await page.locator('#rulelab-title').fill(editedTitle);
  await page.locator('#rulelab-description').fill('Updated through Chromium editor');
  const save2=page.waitForResponse(r=>r.url().endsWith('/api/rules/save')&&r.request().method()==='POST', {timeout:20000});
  await page.locator('#rulelab-save-submit').click();
  check((await save2).status() === 200,'edición mediante controles y POST real');
  await page.locator('#rulelab-save-dialog').waitFor({state:'hidden'});
  found=(await rules()).filter(x=>x.rule === pattern);
  check(found.length === 1 && found[0].id === id && found[0].name === editedTitle, 'edición sin duplicación ni cambio de ID');

  step='reload-and-delete';
  await page.reload({waitUntil:'domcontentloaded'});
  await page.locator('#boot-enter-button').waitFor({state:'visible',timeout:20000});
  await page.locator('#boot-enter-button').click();
  await page.locator('.nav-item[data-route="rules"]').click();
  await page.locator('#panel-rules.active').waitFor({state:'visible'});
  await page.locator('#rules-view-table').click();
  const row=page.locator(`#rules-table [data-rule-row-id="${id}"]`);
  await row.waitFor({state:'visible',timeout:20000});
  check((await row.innerText()).includes(editedTitle), 'regla actualizada visible tras recargar Chromium');
  await row.locator('input[data-action="rule-select"]').check();
  await page.locator('#rules-delete-selected').click();
  await page.locator('#confirm-dialog[open]').waitFor({state:'visible'});
  const deleteResponse=page.waitForResponse(r=>r.url().includes('/api/rules/'+id)&&r.request().method()==='DELETE',{timeout:20000});
  await page.locator('#confirm-accept').click();
  check((await deleteResponse).status() === 200,'eliminación desde selección + confirmación UI');
  check((await rules()).every(x=>x.id!==id),'eliminación persistida en la API');
  await page.reload({waitUntil:'domcontentloaded'});
  await page.locator('#boot-enter-button').waitFor({state:'visible',timeout:20000});
  await page.locator('#boot-enter-button').click();
  await page.locator('.nav-item[data-route="rules"]').click();
  await page.locator('#panel-rules.active').waitFor({state:'visible'});
  check((await rules()).every(x=>x.id !== id),'la regla eliminada no reaparece tras recarga');
  // Stage 5F1: retired dispatch actions must remain inert even if a stale
  // DOM extension or restored browser fragment injects a legacy button.
  step='retired-action-injection';
  await page.evaluate(() => {
    for (const action of [
      'adversaries-empty-create', 'adversary-editor-save',
      'adversary-add-dummy-label', 'payload-catalog-delete-selected',
      'flow-step-remove', 'rule-copy-emulation',
    ]) {
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.action = action;
      button.dataset.id = 'qa-nonexistent';
      button.dataset.ability = 'qa-nonexistent';
      button.dataset.stepIndex = '0';
      document.body.append(button);
      button.click();
      button.remove();
    }
  });
  await page.waitForTimeout(250);
  check(legacy.length===0 && errors.length===0 && severe.length===0,
    'acciones legacy inyectadas sin peticiones ni excepciones');
  check(legacy.length===0,'sin llamadas a APIs retiradas');
  check(errors.length===0,'sin excepciones JS: '+errors.slice(0,3).join(' | '));
  check(severe.length===0,'sin respuestas API 5xx: '+severe.slice(0,3).join(' | '));
  const disk=JSON.parse(await readFile(join(config,'catalog','rules.json'),'utf8'));
  check(Array.isArray(disk) && disk.length===0,'rules.json sintético queda vacío al borrar');
  console.log('PASS: CI E2E — navigation + CRUD browser (synthetic, containerized)');
} catch (e) {
  console.error('FAIL/INVESTIGATE: etapa='+step+' — '+e.stack);
  console.error('SPUC logs (last lines): '+logs.slice(-8).join('').slice(-1800));
  process.exitCode=1;
} finally {
  if (browser) await browser.close().catch(()=>{});
  if (server) {
    server.kill('SIGTERM');
    await Promise.race([new Promise(resolve=>server.once('exit',resolve)), delay(3000)]);
  }
}
