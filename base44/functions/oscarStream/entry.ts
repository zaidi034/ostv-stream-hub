import { createClientFromRequest } from 'npm:@base44/sdk@0.8.44';
import { fetchJson, mapWatchLinks, mapDownloadLinks, mapChannelStreams } from '../../shared/oscar-api.ts';

// Cache TTLs: one upstream API call per item per window, no matter how many
// app users request it — keeps us far below the upstream rate limits.
const TTL = {
  movie: 6 * 3600 * 1000,
  episode: 6 * 3600 * 1000,
  channel: 30 * 60 * 1000, // live channel links go stale faster
};

// keep only stream links that actually respond with a playable HLS manifest;
// dead ones (302 -> dead http host, 403, no CORS) would only produce
// "تعذر تشغيل البث" in the player.
async function checkStream(s) {
  try {
    const res = await fetch(s.url.split('#')[0], { redirect: 'follow', signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    // mixed content: the browser blocks http:// targets on an https page
    if (!res.url.startsWith('https:')) return null;
    const ct = res.headers.get('content-type') || '';
    if (ct.toLowerCase().includes('mpegurl')) return s;
    const body = await res.text();
    return body.includes('#EXTM3U') ? s : null;
  } catch {
    return null;
  }
}

async function buildPayload(type, data) {
  if (type === 'channel') {
    const streams = mapChannelStreams(data);
    const checked = await Promise.all(streams.map(checkStream));
    const alive = checked.filter(Boolean);
    return { streams: alive.length ? alive : streams };
  }
  const out = { watch_links: mapWatchLinks(data.watch_links) };
  if (type === 'movie') out.download_links = mapDownloadLinks(data.download_links);
  return out;
}

export default async function (req) {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();
    if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });

    const body = await req.json();
    const type = String(body.type || '');
    const id = parseInt(body.id, 10);
    if (!id) return Response.json({ error: 'id required' }, { status: 400 });
    const paths = {
      movie: '/movies/show.php?id=',
      episode: '/episodes/show.php?id=',
      channel: '/channels/show.php?id=',
    };
    if (!paths[type]) {
      return Response.json({ error: 'type must be movie|episode|channel' }, { status: 400 });
    }

    // 1) fresh cache hit -> zero upstream calls
    let cached = null;
    try {
      const rows = await base44.entities.StreamCache.filter({ type, source_id: id }, null, 1);
      cached = rows[0] || null;
    } catch (e) {
      // cache read failure should not break playback
    }
    const now = Date.now();
    if (cached && now - cached.fetched_at < TTL[type]) {
      return Response.json(JSON.parse(cached.payload));
    }

    // 2) cache miss or expired -> hit the upstream API once, then store
    let out = null;
    try {
      const data = await fetchJson(paths[type] + id);
      if (data) out = await buildPayload(type, data);
    } catch (e) {
      // upstream error -> fall through to stale cache
    }

    if (out) {
      try {
        if (cached) {
          await base44.entities.StreamCache.update(cached.id, {
            payload: JSON.stringify(out),
            fetched_at: now,
          });
        } else {
          await base44.entities.StreamCache.create({
            type,
            source_id: id,
            payload: JSON.stringify(out),
            fetched_at: now,
          });
        }
      } catch (e) {
        // cache write failure should not break playback
      }
      return Response.json(out);
    }

    // 3) upstream unavailable (blocked/throttled) -> serve stale cache if any
    if (cached) {
      const stale = JSON.parse(cached.payload);
      stale.stale = true;
      return Response.json(stale);
    }
    return Response.json({ error: 'not found' }, { status: 404 });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}