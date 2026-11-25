/**
 * KCHAT service worker.
 *
 * Scope of caching is deliberately tiny. Only the static application shell
 * (this page, its manifest, its icons and two static script/image assets) is
 * ever stored. Everything private stays on the network:
 *
 *   - /api/* responses (messages, contacts, stories, profile, AI history)
 *   - /ws/* WebSocket upgrades
 *   - anything requested with an Authorization header
 *   - any non-GET request
 *
 * Session tokens live in localStorage and in the kchat_session cookie, so they
 * are never part of a cached response either. Activation deletes every cache
 * this worker does not own, and a new worker version replaces the old one as
 * soon as it activates, so an update is picked up without reinstalling.
 */

const VERSION = 'v1';
const SHELL_CACHE = `kchat-shell-${VERSION}`;

// Only these exact same-origin paths may be cached.
const SHELL_ASSETS = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/kchat-ai-logo.svg',
  '/kchat-ai-launcher.js'
];

// Anything under these prefixes is private or stateful and must never be cached.
const NETWORK_ONLY_PREFIXES = ['/api/', '/ws/'];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(SHELL_CACHE);
    // One failed asset must not abort the whole install.
    await Promise.all(SHELL_ASSETS.map(async path => {
      try {
        await cache.add(new Request(path, { credentials: 'same-origin' }));
      } catch (error) {
        // Ignore: the shell still works from the network for that asset.
      }
    }));
    // Activate the new worker immediately rather than waiting for every tab
    // to close, so an update is never stuck behind an old session.
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.map(name => {
      if (name !== SHELL_CACHE) return caches.delete(name);
      return null;
    }));
    await self.clients.claim();
  })());
});

function isPrivateRequest(request, url) {
  if (url.origin !== self.location.origin) return true;
  if (request.method !== 'GET') return true;
  if (request.headers.get('authorization')) return true;
  if (NETWORK_ONLY_PREFIXES.some(prefix => url.pathname.startsWith(prefix))) return true;
  return false;
}

function isShellPath(url) {
  return SHELL_ASSETS.includes(url.pathname);
}

self.addEventListener('fetch', event => {
  const { request } = event;
  if (request.method !== 'GET') return;

  let url;
  try {
    url = new URL(request.url);
  } catch {
    return;
  }

  // Private data: pass straight through, never read, never store.
  if (isPrivateRequest(request, url)) return;

  // The navigations KCHAT makes itself are the app shell. Serve it from the
  // cache first so the app opens instantly, then refresh it in the background.
  if (request.mode === 'navigate' && url.pathname === '/') {
    event.respondWith((async () => {
      const cache = await caches.open(SHELL_CACHE);
      const cached = await cache.match('/');
      const network = fetch(request).then(response => {
        if (response && response.ok) cache.put('/', response.clone());
        return response;
      }).catch(() => null);

      if (cached) {
        event.waitUntil(network);
        return cached;
      }
      const fresh = await network;
      if (fresh) return fresh;
      // Offline with nothing cached: let the browser show its own message.
      return Response.error();
    })());
    return;
  }

  // Static shell assets: cache first, revalidate quietly.
  if (isShellPath(url)) {
    event.respondWith((async () => {
      const cache = await caches.open(SHELL_CACHE);
      const cached = await cache.match(url.pathname);
      if (cached) {
        event.waitUntil(fetch(request).then(response => {
          if (response && response.ok) return cache.put(url.pathname, response);
          return null;
        }).catch(() => null));
        return cached;
      }
      const response = await fetch(request);
      if (response && response.ok) {
        const copy = response.clone();
        event.waitUntil(cache.put(url.pathname, copy));
      }
      return response;
    })());
    return;
  }

  // Everything else (fonts, third-party CDNs, unknown same-origin files) goes
  // to the network untouched and is never cached.
});
