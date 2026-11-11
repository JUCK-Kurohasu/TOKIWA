const { chromium } = require('playwright');
const fs = require('fs');
const [base, D] = process.argv.slice(2);
(async () => {
  const token = fs.readFileSync(D + '/admin.jwt', 'utf8').trim();
  const conv = fs.readFileSync(D + '/conv.id', 'utf8').trim();
  const me = await (await fetch(base + '/api/v1/auth/me', { headers: { Authorization: 'Bearer ' + token } })).json();
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 } });
  await ctx.addInitScript((a) => localStorage.setItem('tokiwa.auth', JSON.stringify({ token: a.t, user: a.u })), { t: token, u: me });
  const reqs = [];
  ctx.on('request', (r) => { if (!r.url().startsWith(base)) reqs.push(r.url()); });
  await ctx.route((u) => !u.href.startsWith(base), (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<h1>ATTACKER PAGE</h1>' }));
  const page = await ctx.newPage();
  await page.goto(base + '/copilot?c=' + conv);
  await page.waitForTimeout(3000);
  const links = await page.$$eval('main a, a', (as) => as.filter(a => /アラート|承認|内部|NVD|x$/.test(a.textContent)).map((a) => ({ text: a.textContent, href: a.getAttribute('href'), abs: a.href, target: a.target })));
  console.log(JSON.stringify(links, null, 1));
  await page.screenshot({ path: D + '/../copilot.png' });
  // left-click the "internal" spoofed link
  const l = page.locator('a', { hasText: '承認画面で確認' });
  if (await l.count()) {
    await l.first().click();
    await page.waitForTimeout(2000);
    console.log('after click url=', page.url());
    console.log('body=', (await page.textContent('body')).slice(0, 80));
  }
  console.log('external requests:', JSON.stringify(reqs));
  await browser.close();
})();
