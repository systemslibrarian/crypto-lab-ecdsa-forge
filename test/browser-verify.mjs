// Headless browser verification of the rendered app.
// Usage: serve `dist` on :4174 (npm run preview), then `node test/browser-verify.mjs`.
import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';

const APP_URL = 'http://localhost:4174/crypto-lab-ecdsa-forge/';
const SHOTS = 'verify-shots/';
mkdirSync(SHOTS, { recursive: true });

const errors = [];
const results = [];
const ok = (name, cond, extra = '') => results.push({ name, pass: !!cond, extra });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
page.on('console', (m) => {
  if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
});
page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));

await page.goto(APP_URL, { waitUntil: 'networkidle' });

// --- Structural checks ------------------------------------------------------
ok('continuous SVG rendered', await page.$('#viz-continuous svg .vc-curve'));
ok('discrete SVG rendered', await page.$('#viz-discrete svg .vd-dot'));
ok('toy attack default succeeds (badge.ok)', await page.$('#toy-attack-output .badge.ok'));
ok('glossary populated', (await page.$$('#reference .gl-item')).length >= 8);
ok('references populated', (await page.$$('#reference .ref-list li')).length >= 5);
ok('nav links present', (await page.$$('#topnav a')).length >= 6);

// --- Sweep the continuous slider; sum point must stay inside the 460x320 box -
const setRange = async (sel, v) =>
  page.$eval(
    sel,
    (el, val) => {
      el.value = val;
      el.dispatchEvent(new Event('input', { bubbles: true }));
    },
    String(v),
  );

let sumInside = true;
let worst = '';
for (let v = 0.2; v <= 4.0001; v += 0.1) {
  await setRange('#vc-slider', v.toFixed(2));
  const c = await page.$eval('#viz-continuous svg .vc-sum', (el) => ({
    cx: +el.getAttribute('cx'),
    cy: +el.getAttribute('cy'),
  }));
  if (c.cx < 0 || c.cx > 460 || c.cy < 0 || c.cy > 320) {
    sumInside = false;
    worst = `v=${v.toFixed(2)} → (${c.cx.toFixed(0)}, ${c.cy.toFixed(0)})`;
  }
}
ok('P+Q stays inside the SVG across the whole slider', sumInside, worst);

// Doubling mode renders a sum too.
await page.check('#vc-double');
ok('doubling renders 2P', await page.$('#viz-continuous svg .vc-sum'));
await page.uncheck('#vc-double');

// --- Exercise discrete + toy sliders; just assert no runtime errors ----------
for (let k = 1; k <= 18; k += 1) await setRange('#vd-slider', k);
for (const d of [1, 5, 12, 18]) await setRange('#toy-d', d);
for (const e of [0, 3, 14, 18]) await setRange('#toy-e2', e);
ok('toy output still present after sweeps', await page.$('#toy-attack-output p, #toy-attack-output .toy-out'));

// --- Run the real 256-bit attack -------------------------------------------
await page.click('#btn-attack');
await page.waitForFunction(
  () => document.querySelector('#victim-key')?.classList.contains('exposed'),
  { timeout: 8000 },
);
const full = await page.$eval('#attack-fullnums', (el) => el.textContent || '');
ok('real attack recovered key (✓ identical)', full.includes('✓ identical'));

// --- Screenshots: desktop dark, desktop light, mobile -----------------------
await page.screenshot({ path: `${SHOTS}desktop-dark.png`, fullPage: true });
await page.click('#theme-toggle');
await page.waitForTimeout(150);
await page.screenshot({ path: `${SHOTS}desktop-light.png`, fullPage: true });

const mobile = await browser.newPage({ viewport: { width: 390, height: 844 } });
await mobile.goto(APP_URL, { waitUntil: 'networkidle' });
await mobile.screenshot({ path: `${SHOTS}mobile-dark.png`, fullPage: true });

await browser.close();

// --- Report -----------------------------------------------------------------
console.log('\n=== Browser verification ===');
for (const r of results) console.log(`  ${r.pass ? 'ok ' : 'FAIL'}  ${r.name}${r.extra ? `  [${r.extra}]` : ''}`);
console.log(`\nconsole/page errors: ${errors.length}`);
for (const e of errors) console.log(`  - ${e}`);

const failed = results.filter((r) => !r.pass).length;
console.log(failed === 0 && errors.length === 0 ? '\nALL BROWSER CHECKS PASSED' : `\n${failed} check(s) failed, ${errors.length} error(s)`);
process.exit(failed === 0 && errors.length === 0 ? 0 : 1);
