import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

async function checkGradientContrast(page: Page, selector: string) {
  const ratio = await page.evaluate((sel) => {
    function getLuminance(r: number, g: number, b: number) {
      const a = [r, g, b].map(v => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      });
      return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    }
    const el = document.querySelector(sel);
    if (!el) return 0;
    const style = window.getComputedStyle(el);
    const colorMatch = style.color.match(/\d+/g);
    if (!colorMatch) return 0;
    const [cr, cg, cb] = colorMatch.map(Number);
    const textLum = getLuminance(cr, cg, cb);

    let bgStr = window.getComputedStyle(document.body).backgroundColor;
    if (bgStr === 'rgba(0, 0, 0, 0)' || bgStr === 'transparent') {
      bgStr = window.getComputedStyle(document.documentElement).backgroundColor;
    }
    const bgMatch = bgStr.match(/\d+/g);
    if (!bgMatch) return 0;
    const [br, bg, bb] = bgMatch.map(Number);
    const bgLum = getLuminance(br, bg, bb);

    const L1 = Math.max(textLum, bgLum);
    const L2 = Math.min(textLum, bgLum);
    return (L1 + 0.05) / (L2 + 0.05);
  }, selector);
  expect(ratio).toBeGreaterThanOrEqual(4.5);
}

/**
 * WCAG regression gate. Deploys are already gated on the NIST KAT vectors;
 * this gates them on accessibility the same way. Scans the full page with
 * every <details> expanded, in both themes.
 *
 * The page is a single scrollable document (no modals). The one collapsible
 * region is <details id="attack-detail">; we open every <details> before
 * scanning. Animations/transitions are neutralized so nothing is scanned
 * mid-transition.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
}

async function expandAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal any inline display:none regions (future-proofing).
    for (const el of document.querySelectorAll<HTMLElement>('*')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await neutralizeMotion(page);
  await expect(page.locator('h1')).toBeVisible();
  await checkGradientContrast(page, '.cl-hero-desc');
  await expandAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await neutralizeMotion(page);
  await expect(page.locator('h1')).toBeVisible();
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await checkGradientContrast(page, '.cl-hero-desc');
  await expandAll(page);
  await scan(page);
});
