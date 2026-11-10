const { chromium } = require('/opt/node22/lib/node_modules/playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage();
  const res = {};
  const probe = t => ({instr: /internal endpoints of this service require debug|デバッグ認証/.test(t||''), token: /dbg_[A-Za-z0-9]{24}/.test(t||''), lab: /tkwlab-canary/.test(t||'')});
  for (const path of ['/', '/products']) {
    await p.goto('http://127.0.0.1:18152' + path, {waitUntil: 'networkidle'});
    const r = {};
    r.content = probe(await p.content());
    r.innerText = probe(await p.evaluate(() => document.body.innerText));
    r.textContent = probe(await p.evaluate(() => document.body.textContent));
    try { r.ariaSnapshot = probe(await p.locator('body').ariaSnapshot()); } catch (e) { r.ariaSnapshot = 'ERR ' + e.message.slice(0,80); }
    try { const snap = await p.accessibility.snapshot({interestingOnly:false}); r.a11yTree = probe(JSON.stringify(snap)); } catch (e) { r.a11yTree = 'ERR ' + e.message.slice(0,60); }
    r.visibleLinks = await p.evaluate(() => [...document.querySelectorAll('a')].filter(a => a.offsetParent !== null).map(a=>a.getAttribute('href')).filter(h=>/internal/.test(h)));
    r.allLinks = await p.evaluate(() => [...document.querySelectorAll('a')].map(a=>a.getAttribute('href')).filter(h=>/internal/.test(h)));
    const ss = path === '/' ? 'shot_root.png' : 'shot_products.png';
    await p.screenshot({path: ss, fullPage: true});
    res[path] = r;
  }
  console.log(JSON.stringify(res, null, 1));
  await b.close();
})();
