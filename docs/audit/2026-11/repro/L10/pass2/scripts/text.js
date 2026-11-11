const { chromium } = require('playwright');
const fs = require('fs');
const [base, D, re, ...routes] = process.argv.slice(2);
(async () => {
  const token = fs.readFileSync(D + '/admin.jwt', 'utf8').trim();
  const me = await (await fetch(base + '/api/v1/auth/me', { headers: { Authorization: 'Bearer ' + token } })).json();
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await ctx.addInitScript((a) => localStorage.setItem('tokiwa.auth', JSON.stringify({ token: a.t, user: a.u })), { t: token, u: me });
  const page = await ctx.newPage();
  for (const r of routes) {
    await page.goto(base + r); await page.waitForTimeout(2500);
    const t = await page.evaluate(() => document.body.innerText);
    console.log('==', r); console.log(t.split('\n').filter(l => new RegExp(re, 'i').test(l)).slice(0, 15).join('\n'));
  }
  await browser.close();
})();
