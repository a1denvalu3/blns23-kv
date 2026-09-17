import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));

  await page.goto(new URL('../dist/index.html', import.meta.url).href);
  await page.locator('.slide.active').waitFor();
  await page.evaluate(() => document.fonts.ready);
  await page.addStyleTag({
    content: '*, *::before, *::after { animation: none !important; transition: none !important; }',
  });

  const total = await page.locator('.slide').count();
  const viewports = [
    { width: 1280, height: 720 },
    { width: 960, height: 540 },
    { width: 800, height: 450 },
  ];

  for (const viewport of viewports) {
    await page.setViewportSize(viewport);

    for (let index = 0; index < total; index++) {
      await page.locator('.dot').nth(index).click();
      assert.equal(await page.locator('.slide-number').innerText(), `${index + 1} / ${total}`);

      const bounds = await page.locator('.slide.active').evaluate(slide => {
        slide.scrollTop = 0;
        const content = slide.querySelector('.slide-content');
        const titleTop = slide.querySelector('h1, h2').getBoundingClientRect().top;
        const scale = content.getBoundingClientRect().width / content.offsetWidth;
        const viewportBottom = slide.getBoundingClientRect().bottom;
        const navTop = document.querySelector('nav').getBoundingClientRect().top;

        slide.scrollTop = slide.scrollHeight;
        const contentBottom = Math.max(...Array.from(content.children,
          child => child.getBoundingClientRect().bottom));
        slide.scrollTop = 0;

        return { titleTop, scale, viewportBottom, navTop, contentBottom };
      });

      const label = `Slide ${index + 1} at ${viewport.width}×${viewport.height}`;
      assert.ok(bounds.titleTop >= 3, `${label}: title is clipped`);
      assert.ok(Math.abs(bounds.scale - 1) < 0.002, `${label}: content is scaled`);
      assert.ok(bounds.contentBottom <= bounds.viewportBottom + 1, `${label}: bottom is unreachable`);
      assert.ok(bounds.viewportBottom <= bounds.navTop, `${label}: navigation overlaps the slide`);
    }
  }

  await page.locator('.dot').first().click();
  await page.keyboard.press('ArrowLeft');
  assert.equal(await page.locator('.slide-number').innerText(), `1 / ${total}`);
  await page.keyboard.press('ArrowRight');
  assert.equal(await page.locator('.slide-number').innerText(), `2 / ${total}`);
  await page.keyboard.press('ArrowLeft');
  await page.keyboard.press('Space');
  assert.equal(await page.locator('.slide-number').innerText(), `2 / ${total}`);
  assert.equal(await page.locator('.katex-error').count(), 0, 'Invalid math markup');
  assert.deepEqual(errors, [], 'Browser rendering errors');

  console.log(`Checked ${total} slides at ${viewports.length} window sizes; navigation and math rendering passed.`);
} finally {
  await browser.close();
}
