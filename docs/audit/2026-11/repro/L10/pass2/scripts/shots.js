const { chromium } = require('playwright');
const fs = require('fs');
const [base, D, ...routes] = process.argv.slice(2);
(async () => {
  const token = fs.readFileSync(D + '/admin.jwt', 'utf8').trim();
  const me = await (await fetch(base + '/api/v1/auth/me', { headers: { Authorization: 'Bearer ' + token } })).json();
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await ctx.addInitScript((a) => localStorage.setItem('tokiwa.auth', JSON.stringify({ token: a.t, user: a.u })), { t: token, u: me });
  const page = await ctx.newPage();
  page.on('dialog', async (d) => { console.log('DIALOG', d.message()); await d.dismiss(); });
  for (const r of routes) {
    await page.goto(base + r); await page.waitForTimeout(2500);
    const name = r.replace(/[^a-z0-9]/gi, '_');
    await page.screenshot({ path: `${D}/../shot${name}.png`, fullPage: false });
    const t = await page.evaluate(() => document.body.innerText);
    const hits = t.split('\n').filter(l => /[‪-‮⁦-⁩​]/.test(l)).slice(0, 8);
    console.log(r, 'lines with bidi/zw:', JSON.stringify(hits));
  }
  await browser.close();
})();
