const CACHE_NAME = "scamshield-v2";
const STATIC_ASSETS = [
  "/",
];

// Install: cache only the shell page (icons don't exist yet)
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

// Activate: clean up old caches
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Fetch: network-first for API and Next.js internals, cache-first only for true static assets
self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== "GET") return;

  // Always go to network for Next.js internals (HMR, chunks, static builds)
  // This prevents stale JS chunks after hot-module-replacement recompiles
  if (url.pathname.startsWith("/_next/")) return;

  // Network-first for API calls — never serve stale API responses from cache
  if (url.pathname.startsWith("/api/")) {
    event.respondWith(
      fetch(request).catch(() =>
        new Response(JSON.stringify({ error: "Network unavailable" }), {
          status: 503,
          headers: { "Content-Type": "application/json" },
        })
      )
    );
    return;
  }

  // Cache-first for true static assets (images, fonts, icons)
  if (
    url.pathname.match(/\.(png|jpg|jpeg|gif|webp|svg|ico|woff|woff2|ttf)$/)
  ) {
    event.respondWith(
      caches.match(request).then((cachedResponse) => {
        if (cachedResponse) return cachedResponse;
        return fetch(request).then((response) => {
          if (response && response.status === 200) {
            const responseClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(request, responseClone);
            });
          }
          return response;
        });
      })
    );
    return;
  }

  // For all other requests (HTML pages), network-first with cache fallback
  event.respondWith(
    fetch(request)
      .then((response) => {
        if (response && response.status === 200) {
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, responseClone);
          });
        }
        return response;
      })
      .catch(() => {
        return caches.match(request).then((cached) => {
          if (cached) return cached;
          if (request.mode === "navigate") {
            return caches.match("/");
          }
          return new Response("Offline", {
            status: 503,
            statusText: "Service Unavailable",
          });
        });
      })
  );
});
