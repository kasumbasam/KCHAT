/* Phase 1, Step 1.4 - browser check for the unsaved-sender banner.
 *
 * The backend now hides a blocked peer's phone number from the inbox. The
 * banner renders `phone_number || username`, so with the number hidden it must
 * fall back to the username - and must still show the number for a normal
 * unsaved contact.
 *
 * Order matters: messages are sent BEFORE blocking, because blocking correctly
 * prevents further messages (403).
 *
 * Run (server on :3000, database running):
 *   PLAYWRIGHT_BROWSERS_PATH=/opt/freecode-tools/pw-browsers node .verify/phase1_banner_check.js
 */
const { chromium } = require('/opt/freecode-tools/node_modules/playwright');
const fs = require('fs');
const path = require('path');

const BASE = process.env.BASE || 'http://127.0.0.1:3000';
const RESULTS = [];

function check(name, ok, detail) {
  RESULTS.push({ name, ok: !!ok, detail: ok ? '' : String(detail || '').slice(0, 400) });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '\n      -> ' + String(detail || '').slice(0, 400)}`);
}

async function api(context, method, urlPath, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = 'Bearer ' + token;
  const res = await context.request.fetch(BASE + urlPath, {
    method,
    headers,
    data: body === undefined ? undefined : JSON.stringify(body),
  });
  let json = {};
  try { json = await res.json(); } catch {}
  return { status: res.status(), json };
}

function tag() { return Math.random().toString(16).slice(2, 8); }

async function register(context, prefix) {
  const t = tag();
  const res = await api(context, 'POST', '/api/register', {
    phone_number: '+2567' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0'),
    password: 'password123',
    username: prefix + t,
  });
  if (res.status !== 200) throw new Error('register failed: ' + JSON.stringify(res.json).slice(0, 200));
  return res.json;
}

(async () => {
  const browser = await chromium.launch();
  const results = { startedAt: new Date().toISOString(), base: BASE };

  try {
    const context = await browser.newContext();

    const alice = await register(context, 'bnrnorm');
    const bob = await register(context, 'bnrblk');
    const sender = await register(context, 'bnrsend');

    // 1. Sender messages BOTH accounts first.
    for (const target of [alice.username, bob.username]) {
      const sent = await api(context, 'POST', '/api/messages', {
        type: 'private', text: 'banner check', to: target,
      }, sender.token);
      check(`setup: sender messaged ${target}`, sent.status === 200 || sent.status === 201,
        `status=${sent.status} body=${JSON.stringify(sent.json).slice(0, 160)}`);
    }

    // 2. Only then does Bob block the sender.
    const block = await api(context, 'POST', '/api/blocks', { username: sender.username }, bob.token);
    check('setup: bob blocks the sender', block.status === 200, JSON.stringify(block.json).slice(0, 200));

    // Confirm the backend decision the banner depends on.
    const bobInbox = await api(context, 'GET', '/api/inbox', undefined, bob.token);
    const bobItem = (bobInbox.json.inbox || []).find(
      i => String(i.username).toLowerCase() === sender.username.toLowerCase());
    check('backend: blocked peer phone_number is null in bob\'s inbox',
      bobItem && bobItem.phone_number === null,
      `item=${JSON.stringify(bobItem && { u: bobItem.username, p: bobItem.phone_number, r: bobItem.restricted })}`);

    const aliceInbox = await api(context, 'GET', '/api/inbox', undefined, alice.token);
    const aliceItem = (aliceInbox.json.inbox || []).find(
      i => String(i.username).toLowerCase() === sender.username.toLowerCase());
    check('backend: normal peer keeps phone_number in alice\'s inbox',
      aliceItem && aliceItem.phone_number === sender.phone_number,
      `item=${JSON.stringify(aliceItem && { p: aliceItem.phone_number })}`);

    const page = await context.newPage();

    async function signIn(account) {
      await page.goto(BASE, { waitUntil: 'domcontentloaded' });
      // Use the app's own session helper so storage and cookies both match a real login.
      await page.evaluate(([t, u]) => saveKchatSession(t, u), [account.token, account.username]);
      await page.goto(BASE, { waitUntil: 'domcontentloaded' });
      await page.waitForTimeout(1500);
    }

    async function openChatWith(username) {
      const selector = `#chatList .chat-item[data-username]`;
      const appeared = await page.waitForFunction(
        ([sel, name]) => Array.from(document.querySelectorAll(sel))
          .some(el => (el.getAttribute('data-username') || '').toLowerCase() === name.toLowerCase()),
        [selector, username], { timeout: 20000 }
      ).then(() => true).catch(() => false);

      if (!appeared) return false;

      await page.evaluate(([sel, name]) => {
        const row = Array.from(document.querySelectorAll(sel))
          .find(el => (el.getAttribute('data-username') || '').toLowerCase() === name.toLowerCase());
        if (row) row.click();
      }, [selector, username]);

      await page.waitForTimeout(1500);
      return true;
    }

    async function readBanner() {
      return page.evaluate(() => {
        const notice = document.getElementById('unsavedChatNotice');
        return {
          visible: !!(notice && !notice.classList.contains('hidden')),
          label: (document.getElementById('unsavedChatLabel') || {}).textContent || '',
        };
      });
    }

    // ---- Case 1: normal unsaved contact still shows its number -------------
    await signIn(alice);
    const openedNormal = await openChatWith(sender.username);
    check('normal unsaved chat opened', openedNormal, 'chat row never appeared in the list');

    if (openedNormal) {
      const banner = await readBanner();
      check('normal contact banner is visible', banner.visible, JSON.stringify(banner));
      check('normal contact banner still shows the phone number',
        banner.label.includes(sender.phone_number),
        `label="${banner.label}" expected to contain "${sender.phone_number}"`);
    }

    // ---- Case 2: blocked sender falls back to username ---------------------
    await signIn(bob);
    const openedBlocked = await openChatWith(sender.username);
    check('blocked sender chat opened', openedBlocked, 'chat row never appeared in the list');

    if (openedBlocked) {
      const banner = await readBanner();
      check('blocked sender banner is visible', banner.visible, JSON.stringify(banner));
      check('blocked sender banner does NOT leak the phone number',
        !banner.label.includes(sender.phone_number),
        `label="${banner.label}" must not contain "${sender.phone_number}"`);
      check('blocked sender banner falls back to the username',
        banner.label.includes(sender.username),
        `label="${banner.label}" expected to contain "${sender.username}"`);
    }

    const failed = RESULTS.filter(r => !r.ok);
    results.finishedAt = new Date().toISOString();
    results.checks = RESULTS;
    results.passed = RESULTS.length - failed.length;
    results.total = RESULTS.length;

    fs.mkdirSync(path.join(__dirname, '..', 'test-results'), { recursive: true });
    fs.writeFileSync(
      path.join(__dirname, '..', 'test-results', 'phase1-banner-check.json'),
      JSON.stringify(results, null, 2)
    );

    console.log(`\npassed ${results.passed}/${results.total}`);
    await browser.close();
    if (failed.length) { console.log('FAILED'); process.exit(1); }
  } catch (error) {
    console.log('ERROR ' + (error && error.message));
    await browser.close();
    process.exit(1);
  }
})();
