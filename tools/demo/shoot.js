// Screenshots of an attacker's walk through Maze, for docs/maze-demo.gif and docs/maze-journey.png.
// usage: node tools/demo/shoot.js <base-url> <out-dir>
// Run Maze with the demo decoys of config/layers.json and MAZE_DELAY_ENABLED=0 first.
const { chromium } = require('playwright');
const [base = 'http://127.0.0.1:5000', out = 'demo-frames'] = process.argv.slice(2);
(async () => {
  require('fs').mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 560, height: 520 }, deviceScaleFactor: 2 });
  const shot = (name) => page.screenshot({ path: `${out}/${name}.png` });
  const guess = async (password) => {
    await page.fill('#password', password);
    await page.click('button[type=submit]');
    await page.waitForLoadState();
  };
  await page.goto(base + '/'); await shot('1-start');
  await guess('123456'); await shot('2-wrong');
  await guess('admin123'); await shot('3-decoy1');          // decoy, layer 1
  await guess('SuperSecret99'); await shot('4-decoy2');     // decoy, layer 2
  await guess('root!2024'); await shot('5-final-wrong');    // final layer: only the real password works
  await page.click('text=Exit session'); await page.waitForLoadState(); await shot('6-exit');
  await page.fill('#layer1', 'admin123'); await page.fill('#layer2', 'SuperSecret99');
  await page.click('button[type=submit]'); await page.waitForLoadState(); await shot('7-back');
  await browser.close();
})();
