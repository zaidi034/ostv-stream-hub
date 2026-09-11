import { createClientFromRequest } from 'npm:@base44/sdk@0.8.44';
import {
  fetchJson,
  mapMovieDetails,
  mapSerieDetails,
  mapEpisodeDetails,
  mapChannelDetails,
} from '../../shared/oscar-api.ts';

const MAX_SPAN = 600;
const CONCURRENCY = 2;

async function mapLimit(items, limit, worker) {
  const out = new Array(items.length);
  let next = 0;
  async function run() {
    while (next < items.length) {
      const idx = next++;
      out[idx] = await worker(items[idx]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
  return out;
}

async function importItems(base44, entityName, items) {
  const Entity = base44.entities[entityName];
  // one lookup instead of a per-item filter (avoids API rate limits)
  const existing = {};
  try {
    const all = await Entity.list(null, 5000);
    for (const r of all) existing[r.source_id] = r.id;
  } catch (e) {
    // if lookup fails we still create, risking duplicates only
  }
  const toCreate = [];
  const toUpdate = [];
  for (const it of items) {
    const id = existing[it.filter.source_id];
    if (id) toUpdate.push({ id, ...it.data });
    else toCreate.push(it.data);
  }
  let created = 0;
  let updated = 0;
  let errors = 0;
  const lastError = [];
  for (let i = 0; i < toCreate.length; i += 100) {
    const chunk = toCreate.slice(i, i + 100);
    try {
      await Entity.bulkCreate(chunk);
      created += chunk.length;
    } catch (e) {
      errors += chunk.length;
      if (lastError.length < 3) lastError.push(String(e.message || e));
    }
  }
  for (let i = 0; i < toUpdate.length; i += 100) {
    const chunk = toUpdate.slice(i, i + 100);
    try {
      await Entity.bulkUpdate(chunk);
      updated += chunk.length;
    } catch (e) {
      errors += chunk.length;
      if (lastError.length < 3) lastError.push(String(e.message || e));
    }
  }
  return { created, updated, errors, lastError };
}

export default async function (req) {
  try {
    const base44 = createClientFromRequest(req);
    const user = await base44.auth.me();
    if (!user || user.role !== 'admin') {
      return Response.json({ error: 'Admin access required' }, { status: 403 });
    }

    const body = await req.json();
    const type = String(body.type || '');
    const types = {
      movies: { entity: 'Movie', path: 'movies', map: mapMovieDetails },
      series: { entity: 'Serie', path: 'series', map: mapSerieDetails },
      episodes: { entity: 'Episode', path: 'episodes', map: mapEpisodeDetails },
    };
    if (type !== 'channels' && !types[type]) {
      return Response.json({ error: 'type must be channels|movies|series|episodes' }, { status: 400 });
    }

    const start = Math.max(1, parseInt(body.start, 10) || 1);
    const end = Math.min(parseInt(body.end, 10) || start, start + MAX_SPAN - 1);

    if (type === 'channels') {
      const groups = (await fetchJson('/channels/collections.php')) || [];
      const items = [];
      for (const group of groups) {
        for (const ch of group.channels || []) {
          const full = await fetchJson('/channels/show.php?id=' + ch.id);
          if (full) items.push({ filter: { source_id: ch.id }, data: mapChannelDetails(full, group.name) });
        }
      }
      const res = await importItems(base44, 'Channel', items);
      return Response.json({ type, found: items.length, ...res });
    }

    const cfg = types[type];
    const ids = [];
    for (let i = start; i <= end; i++) ids.push(i);
    const results = await mapLimit(ids, CONCURRENCY, async (id) => {
      try {
        return { id, data: await fetchJson('/' + cfg.path + '/show.php?id=' + id) };
      } catch (e) {
        return { id, data: null };
      }
    });
    const items = results
      .filter((r) => r.data)
      .map((r) => ({ filter: { source_id: r.id }, data: cfg.map(r.data) }));
    const res = await importItems(base44, cfg.entity, items);
    return Response.json({ type, scanned: ids.length, found: items.length, ...res });
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 });
  }
}