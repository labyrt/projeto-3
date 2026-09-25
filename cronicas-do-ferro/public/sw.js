const CACHE='cronicas-do-ferro-v9';
const ASSETS=['/','/index.html','/manifest.json','/icon.svg','/assets/player_hunter.svg','/assets/player_guardian.svg','/assets/player_occult.svg','/assets/npc_ilyra.svg','/assets/npc_smith.svg','/assets/npc_shop.svg','/assets/enemy_wolf.svg','/assets/enemy_slime.svg','/assets/enemy_skeleton.svg','/assets/enemy_boss.svg'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(u.pathname.startsWith('/api/')) return;
  if(e.request.method!=='GET') return;
  e.respondWith(fetch(e.request).then(r=>{const copy=r.clone();caches.open(CACHE).then(c=>c.put(e.request,copy));return r}).catch(()=>caches.match(e.request).then(r=>r||caches.match('/index.html'))));
});
