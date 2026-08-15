import { expect, test } from '@playwright/test';

/**
 * One theme, pinned, with no way to change it.
 *
 * This lab is dark. That is a fleet invariant rather than a local preference:
 * the shared header used to carry a theme toggle that persisted its choice, so
 * a single past click pinned a returning visitor to light forever, and the
 * light palettes read badly anyway. Both were removed fleet-wide.
 *
 * The catalog's `node tools/theme-sync.js check` holds all 175 labs to this by
 * reading their markup. This test is the half that runs in CI, where it blocks
 * the deploy — the source check only runs when somebody remembers to run it.
 *
 * The two halves catch different things and neither is redundant. This one sees
 * the RESOLVED theme, so it catches a boot script switched to light and a
 * toggle that renders. It cannot see `<html data-theme="light">` left behind by
 * a boot script that still pins dark, because the script wins before this
 * assertion runs — that mismatch costs a flash of the wrong theme on first
 * paint, and only the source check catches it.
 *
 * A lab's own toggle element may still sit in the DOM (the shared bar's CSS
 * hides it so the lab's theme JS keeps resolving), so what is asserted is that
 * none is VISIBLE, not that none exists.
 */
test('the page pins the dark theme and offers no way to leave it', async ({ page }) => {
  await page.goto('.');

  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.locator('#cl-theme-toggle')).toHaveCount(0);
  await expect(
    page.locator(
      '#theme-toggle:visible, #themeToggle:visible, .theme-toggle:visible,' +
        ' .theme-toggle-btn:visible, [data-theme-toggle]:visible',
    ),
  ).toHaveCount(0);
});
