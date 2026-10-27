'use strict';

const tables = new Map();
const collator = new Intl.Collator('en', {numeric: true, sensitivity: 'base'});
const severities = new Map(['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'].map((value, index) => [value, index]));
const cacheName = 'outcrop-result-rows-v1';
const cacheEntryLimit = 10;
const cacheByteLimit = 128 * 1024 * 1024;

async function openCache() {
  try {return await caches.open(cacheName);} catch {return null;}
}

async function pruneCache(cache, url, incomingBytes) {
  const keys = await cache.keys();
  const entries = [];
  let bytes = incomingBytes;
  for (const key of keys) {
    // Only one revision of each artifact is useful. Other scans are kept
    // within a small FIFO budget instead of growing browser storage forever.
    if (new URL(key.url).pathname === new URL(url).pathname) {
      await cache.delete(key);
      continue;
    }
    const response = await cache.match(key);
    const size = Number(response.headers.get('X-Outcrop-Bytes')) || 0;
    entries.push({key, size});
    bytes += size;
  }
  while (entries.length && (entries.length >= cacheEntryLimit || bytes > cacheByteLimit)) {
    const oldest = entries.shift();
    await cache.delete(oldest.key);
    bytes -= oldest.size;
  }
}

async function saveRows(cache, url, rows) {
  if (!cache) return false;
  try {
    // Cache the projected JSON, not hundreds of MB of tool metadata. A hit
    // avoids both the download and decoding the original document again.
    const body = new Blob([JSON.stringify(rows)], {type: 'application/json'});
    const response = () => new Response(body, {headers: {'X-Outcrop-Bytes': String(body.size)}});
    await pruneCache(cache, url, body.size);
    try {
      await cache.put(url, response());
    } catch (error) {
      if (error.name !== 'QuotaExceededError') throw error;
      for (const key of await cache.keys()) await cache.delete(key);
      await cache.put(url, response());
    }
    return true;
  } catch {return false;}
}

function text(value) {
  return value === undefined || value === null || value === '' ? '不明' : String(value);
}

function packageRow(value) {
  return [text(value.name), text(value.version), text(value.type), text(value.foundBy),
    text((value.locations || []).map(location => location.path || location.accessPath || '不明').join(', '))];
}

function matchRow(value) {
  return [text(value.vulnerability?.id), text(value.artifact?.name), text(value.artifact?.version),
    text(value.vulnerability?.severity), text(value.vulnerability?.fix?.versions?.join(', '))];
}

async function downloadRows(kind, url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const document = await response.json();
  const values = kind === 'packages' ? document?.artifacts : document?.matches;
  if (!Array.isArray(values)) throw new Error('Invalid result format');

  // Keep only display columns. Large tool documents stay off the UI thread
  // and become collectible before the next artifact is decoded.
  return values.map(kind === 'packages' ? packageRow : matchRow);
}

async function readRows(kind, url, cache) {
  if (cache) {
    try {
      const response = await cache.match(url);
      if (response) {
        const rows = await response.json();
        if (Array.isArray(rows) && rows.every(row => Array.isArray(row) && row.length === 5 && row.every(value => typeof value === 'string'))) {
          return {rows, saved: true};
        }
        await cache.delete(url);
      }
    } catch {
      // A damaged or unavailable local entry must not hide valid results.
      try {await cache.delete(url);} catch {}
    }
  }
  const rows = await downloadRows(kind, url);
  return {rows, saved: await saveRows(cache, url, rows)};
}

function selectRows(table, request) {
  const query = request.query.trim().toLocaleLowerCase();
  const key = JSON.stringify([query, request.column, request.descending]);
  if (key === table.selectionKey) return;

  const indices = [];
  for (let index = 0; index < table.rows.length; index++) {
    if (!query || table.rows[index].some(value => value.toLocaleLowerCase().includes(query))) indices.push(index);
  }
  if (request.column !== null) {
    indices.sort((left, right) => {
      const a = table.rows[left][request.column];
      const b = table.rows[right][request.column];
      const comparison = table.kind === 'matches' && request.column === 3
        ? (severities.get(a) ?? 6) - (severities.get(b) ?? 6)
        : collator.compare(a, b);
      return (request.descending ? -comparison : comparison) || left - right;
    });
  }
  table.selectionKey = key;
  table.indices = indices;
}

function sendWindow(table, request) {
  selectRows(table, request);
  const start = Math.min(Math.max(0, request.start), Math.max(0, table.indices.length - 1));
  const indices = table.indices.slice(start, start + 60);
  postMessage({type: 'rows', kind: table.kind, sequence: request.sequence,
    total: table.rows.length, count: table.indices.length, start,
    rows: indices.map(index => table.rows[index])});
}

async function loadTables(sources) {
  const cache = await openCache();
  let saved = true;
  // Decode sequentially to avoid retaining two full source documents at once.
  for (const {kind, url} of sources) {
    try {
      const result = await readRows(kind, url, cache);
      saved = saved && result.saved;
      tables.set(kind, {kind, rows: result.rows});
      postMessage({type: 'ready', kind});
    } catch (error) {
      saved = false;
      postMessage({type: 'failure', kind, message: error.message});
    }
  }
  postMessage({type: 'cache-ready', available: Boolean(cache), saved});
}

async function clearCachedResults(sources) {
  try {
    const cache = await openCache();
    if (!cache) throw new Error('Cache unavailable');
    const paths = sources.map(source => new URL(source.url, self.location.href).pathname);
    for (const key of await cache.keys()) {
      if (paths.includes(new URL(key.url).pathname)) await cache.delete(key);
    }
    postMessage({type: 'cache-cleared'});
  } catch {
    postMessage({type: 'cache-failure'});
  }
}

self.onmessage = event => {
  const request = event.data;
  if (request.type === 'load') {
    loadTables(request.sources);
  } else if (request.type === 'clear-cache') {
    clearCachedResults(request.sources);
  } else if (request.type === 'window' && tables.has(request.kind)) {
    sendWindow(tables.get(request.kind), request);
  }
};
