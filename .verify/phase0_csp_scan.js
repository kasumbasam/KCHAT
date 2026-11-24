/**
 * Phase 0: report-only CSP violation scan.
 *
 * Opens the real app, signs in, and drives the screens that matter (Settings,
 * chat, Stories) while capturing every CSP report the browser sends. Nothing
 * is blocked - this is purely to learn what Phase 4 enforcement would break.
 */
const { chromium } = require('/opt/freecode-tools/node_modules/playwright');
const fs = require('fs');

const BASE = process.env.KCHAT_BASE || 'http://127.0.0.1:3000';
const OUT = '/home/ubuntu/project/test-results/phase0-csp.json';

const violations = [];
const consoleErrors = [];
const pageErrors = [];

function tag(entry) {
  return `${entry.directive} <- ${entry.blocked} @ ${entry.sourceFile || entry.documentUri}`;
}

async function main() {
  const browser = await chromium.launch({
    args: ['--no-sandbox', '--disable-dev-shm-usage']
  });
  const context = await browser.newContext({ viewport: { width: 420, height: 900 } });
  const page = await context.newPage();

  // Browser-generated CSP reports arrive as POST /api/csp-report on this page.
  page.on('request', request => {
    if (request.url().endsWith('/api/csp-report') && request.method() === 'POST') {
      try {
        const body = JSON.parse(request.postData() || '{}');
        const entry = body['csp-report'] || body.body || body;
        violations.push({
          directive: entry['effective-directive'] || entry['violated-directive'] || '',
          blocked: entry['blocked-uri'] || '',
          documentUri: entry['document-uri'] || '',
          sourceFile: entry['source-file'] || '',
          line: entry['line-number'] || null,
          disposition: entry['disposition'] || ''
        });
      } catch (error) {
        violations.push({ directive: 'unparsed', blocked: String(error).slice(0, 120) });
      }
    }
  });

  // Also catch Chromium's own securitypolicyviolation events, in case the
  // report-uri is queued rather than sent immediately.
  await page.addInitScript(() => {
    window.__cspEvents = [];
    document.addEventListener('securitypolicyviolation', event => {
      window.__cspEvents.push({
        directive: event.effectiveDirective || event.violatedDirective || '',
        blocked: event.blockedURI || '',
        sourceFile: event.sourceFile || '',
        line: event.lineNumber || null
      });
    });
  });

  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text().slice(0, 300));
  });
  page.on('pageerror', error => pageErrors.push(String(error).slice(0, 300)));

  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(1500);

  // Sign in through the real form so the authenticated UI is exercised.
  const phone = '+2567' + String(Date.now()).slice(-8);
  const username = 'cspscan' + Math.random().toString(16).slice(2, 6);

  const registered = await page.evaluate(async ({ phone, username }) => {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone_number: phone, password: 'password123', username })
    });
    const data = await response.json();
    return { ok: response.ok, data };
  }, { phone, username });

  if (registered.ok && registered.data.token) {
    await page.evaluate(token => {
      localStorage.setItem('kchat_token', token);
    }, registered.data.token);
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(2000);
  }

  // Drive the surfaces most likely to trip a CSP.
  const clicks = [
    '#menuSettings',
    '#subOpenAppearance',
    '#closeAppearanceButton',
    '#subOpenPrivacy',
    '#privacyBackButton',
    '#subOpenSecurity',
    '#closeSecurityButton',
    '#subOpenMyProfile',
    '#closeProfileButton',
    '#kchatDarkThemeChoice',
    '#kchatLightThemeChoice'
  ];

  for (const selector of clicks) {
    try {
      const element = await page.$(selector);
      if (element) {
        await element.click({ timeout: 2500, force: true });
        await page.waitForTimeout(350);
      }
    } catch (error) {
      // A missing or covered control is not a CSP problem; ignore.
    }
  }

  // Let queued reports flush.
  await page.waitForTimeout(2500);

  const inPageEvents = await page.evaluate(() => window.__cspEvents || []);

  await page.screenshot({
    path: '/home/ubuntu/project/test-results/screens/phase0-after.png',
    fullPage: false
  });

  await browser.close();

  // Merge request-borne reports with in-page events, de-duplicated.
  const all = [...violations, ...inPageEvents];
  const seen = new Set();
  const unique = [];

  for (const entry of all) {
    const key = `${entry.directive}|${entry.blocked}|${entry.sourceFile}|${entry.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(entry);
  }

  const result = {
    base: BASE,
    registered: registered.ok,
    reportCount: violations.length,
    inPageCount: inPageEvents.length,
    uniqueViolations: unique,
    consoleErrors,
    pageErrors
  };

  fs.mkdirSync('/home/ubuntu/project/test-results', { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(result, null, 2));

  console.log('report-only violations received :', violations.length);
  console.log('in-page securitypolicyviolation  :', inPageEvents.length);
  console.log('unique violations               :', unique.length);
  unique.slice(0, 25).forEach(entry => console.log('  ' + tag(entry)));
  console.log('console errors:', consoleErrors.length);
  consoleErrors.slice(0, 6).forEach(text => console.log('  ' + text));
  console.log('page errors:', pageErrors.length);
  pageErrors.slice(0, 6).forEach(text => console.log('  ' + text));
}

main().catch(error => {
  console.error('CSP scan failed:', error);
  process.exit(1);
});
