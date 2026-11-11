// Render a page with real headless Chromium (Playwright 1.56) and report whether the canary token
// is visible through the representations an LLM browsing agent receives.
const { chromium } = require('/opt/node22/lib/node_modules/playwright');
const fs = require('fs');
(async () => {
  const [file, token] = process.argv.slice(2);
  const browser = await chromium.launch({ executablePath: undefined });
  const page = await browser.newPage();
  await page.goto('file://' + file);
  const res = {};
  const aria = await page.locator('body').ariaSnapshot();
  res.ariaSnapshot = aria.includes(token);
  if (typeof page._snapshotForAI === 'function') {
    const ai = await page._snapshotForAI();
    const s = typeof ai === 'string' ? ai : JSON.stringify(ai);
    res.snapshotForAI = s.includes(token);
    fs.writeFileSync(file + '.ai-snapshot.txt', s);
  } else { res.snapshotForAI = 'n/a'; }
  res.innerText = (await page.evaluate(() => document.body.innerText)).includes(token);
  res.textContent = (await page.evaluate(() => document.body.textContent)).includes(token);
  res.outerHTML = (await page.content()).includes(token);
  res.ua = await page.evaluate(() => navigator.userAgent);
  console.log(JSON.stringify(res));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
