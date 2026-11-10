// Visit TOKIWA pages as admin, record dialogs/console errors, screenshot.
// Usage: node tour.js <base> <jwtfile> <outdir> [route[#action] ...]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const [base, jwtFile, out, ...routes] = process.argv.slice(2);
  const token = fs.readFileSync(jwtFile, 'utf8').trim();
  const meRes = await fetch(base + '/api/v1/auth/me', { headers: { Authorization: 'Bearer ' + token } });
  const me = await meRes.json();
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'ja-JP', timezoneId: 'Asia/Tokyo' });
  await ctx.addInitScript((arg) => {
    try { localStorage.setItem('tokiwa.auth', JSON.stringify({ token: arg.t, user: arg.u })); } catch (e) { /* */ }
  }, { t: token, u: me });
  const page = await ctx.newPage();
  const log = { dialogs: [], errors: [], pages: {} };
  page.on('dialog', async (d) => { log.dialogs.push({ url: page.url(), type: d.type(), msg: d.message() }); await d.dismiss(); });
  page.on('pageerror', (e) => log.errors.push({ url: page.url(), err: String(e).slice(0, 300) }));
  page.on('console', (m) => { if (m.type() === 'error') log.errors.push({ url: page.url(), console: m.text().slice(0, 300) }); });
  for (const r of routes) {
    const [p, action] = r.split('#');
    const t0 = Date.now();
    await page.goto(base + p, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2500);
    if (action === 'expand') {
      const btns = await page.$$('button[aria-expanded="false"]');
      for (const b of btns.slice(0, 40)) { try { await b.click({ timeout: 1000 }); } catch (e) { /* */ } }
      await page.waitForTimeout(800);
    }
    if (action === 'rows') {
      const rows = await page.$$('tbody tr');
      if (rows.length) { try { await rows[0].click({ timeout: 1500 }); } catch (e) { /* */ } await page.waitForTimeout(1200); }
    }
    const name = p.replace(/[^a-z0-9]+/gi, '_').slice(0, 60) + (action ? '_' + action : '');
    await page.screenshot({ path: path.join(out, name + '.png'), fullPage: true });
    const heap = await page.evaluate(() => (performance.memory ? performance.memory.usedJSHeapSize : null));
    const dom = await page.evaluate(() => document.getElementsByTagName('*').length);
    log.pages[r] = { ms: Date.now() - t0, heap, dom };
  }
  fs.writeFileSync(path.join(out, 'tour-log.json'), JSON.stringify(log, null, 1));
  console.log(JSON.stringify({ dialogs: log.dialogs, errors: log.errors.slice(0, 8), pages: log.pages }));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
