import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const output = fileURLToPath(new URL('../dist/lattice-based-keyed-verification-credentials.pdf', import.meta.url));
const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(new URL('../dist/index.html', import.meta.url).href);
  await page.locator('.slide.active').waitFor();
  await page.emulateMedia({ media: 'print' });
  await page.addStyleTag({ content: await readFile(new URL('./pdf.css', import.meta.url), 'utf8') });
  await page.evaluate(() => document.fonts.ready);
  // Recharts finishes its initial JavaScript animation before PDF capture.
  await page.waitForTimeout(2000);

  const { total, overflow } = await page.evaluate(() => {
    const slides = [...document.querySelectorAll('.slide')];
    const overflow = [];
    slides.forEach((slide, index) => {
      slide.dataset.page = String(index + 1);
      slide.dataset.total = String(slides.length);
      const bounds = slide.getBoundingClientRect();
      const content = slide.querySelector('.slide-content');
      for (const child of content.children) {
        const box = child.getBoundingClientRect();
        if (box.top < bounds.top + 8 || box.bottom > bounds.bottom - 40) {
          overflow.push(`Slide ${index + 1}: vertical overflow in ${child.tagName}`);
        }
      }
      for (const math of slide.querySelectorAll('.math-block')) {
        if (math.scrollWidth > math.clientWidth + 1) {
          overflow.push(`Slide ${index + 1}: equation exceeds its container`);
        }
      }
    });
    return { total: slides.length, overflow };
  });

  assert.deepEqual(errors, [], 'Browser rendering errors');
  assert.equal(await page.locator('.katex-error').count(), 0, 'Invalid math markup');
  assert.deepEqual(overflow, [], 'PDF content would be clipped');
  await page.pdf({ path: output, preferCSSPageSize: true, printBackground: true, tagged: true });
  console.log(`Exported ${total} slides to ${output}`);
} finally {
  await browser.close();
}
