// A stand-in for GET /api/clients (routes/client_routes.py get_clients) for the
// jsdom picker drivers: the same filters, OS grouping, sort, paging and
// ids=1 answer, over an in-memory fleet. Keep it in step with the route; the
// route's own rules are tested in tests/test_client_routes_fleet.py.
//
//   const api = fakeClientsApi(fleet);    // fleet: [{client_id, hostname, os, labels, last_seen_at, last_ip}]
//   w.fetch = api.fetch;                  // api.calls: every URL asked for
'use strict';

const ONLINE_SECONDS = 600;

function osKey(os) {
  const s = String(os || '').trim().toLowerCase();
  if (!s) return 'Unknown';
  if (s === 'windows' || s.startsWith('win')) return 'Windows';
  if (s === 'linux') return 'Linux';
  if (['darwin', 'macos', 'osx', 'mac'].includes(s)) return 'macOS';
  return s.charAt(0).toUpperCase() + s.slice(1);
}
const RANK = { Windows: 0, Linux: 1, macOS: 2 };
const rank = k => (k === 'Unknown' ? [3, ''] : [k in RANK ? RANK[k] : 2.5, k]);
const online = (c, now) => !!c.last_seen_at && now - c.last_seen_at / 1e6 < ONLINE_SECONDS;

function fakeClientsApi(fleet) {
  const calls = [];
  const api = {
    calls,
    fleet,
    fetch: async (url) => {
      calls.push(url);
      const q = new URL(url, 'http://x').searchParams;
      const now = Date.now() / 1000;
      const all = api.fleet;
      const facets = { os: {}, labels: {}, online: 0 };
      for (const c of all) {
        const k = osKey(c.os);
        facets.os[k] = (facets.os[k] || 0) + 1;
        for (const l of c.labels || []) facets.labels[l] = (facets.labels[l] || 0) + 1;
        if (online(c, now)) facets.online++;
      }
      const search = (q.get('search') || '').trim().toLowerCase();
      const os = new Set((q.get('os') || '').split(',').filter(Boolean));
      const labels = new Set((q.get('label') || '').split(',').filter(Boolean));
      const onlineOnly = q.get('online') === '1';
      let rows = all.filter(c => {
        if (os.size && !os.has(osKey(c.os))) return false;
        if (labels.size && !(c.labels || []).some(l => labels.has(String(l)))) return false;
        if (onlineOnly && !online(c, now)) return false;
        if (search) {
          const hay = [c.hostname, c.os, c.os_version, (c.labels || []).join(' '), c.client_id, c.last_ip]
            .map(x => String(x || '')).join(' ').toLowerCase();
          return hay.includes(search);
        }
        return true;
      });
      const groups = {};
      for (const c of rows) groups[osKey(c.os)] = (groups[osKey(c.os)] || 0) + 1;
      rows = rows.slice().sort((a, b) => {
        const ra = rank(osKey(a.os)), rb = rank(osKey(b.os));
        if (ra[0] !== rb[0]) return ra[0] - rb[0];
        if (ra[1] !== rb[1]) return ra[1] < rb[1] ? -1 : 1;
        const oa = online(a, now), ob = online(b, now);
        if (oa !== ob) return oa ? -1 : 1;
        const ha = String(a.hostname || '').toLowerCase(), hb = String(b.hostname || '').toLowerCase();
        if (ha !== hb) return ha < hb ? -1 : 1;
        return String(a.client_id) < String(b.client_id) ? -1 : 1;
      });
      let body;
      if (q.get('ids') === '1') {
        body = { ids: rows.map(c => [c.client_id, c.hostname || '']), total: all.length, filtered: rows.length };
      } else {
        const offset = Number(q.get('offset') || 0), limit = Number(q.get('limit') || 0);
        const page = limit > 0 ? rows.slice(offset, offset + limit) : rows.slice(offset);
        body = { items: page, total: all.length, filtered: rows.length, offset,
                 truncated: offset + page.length < rows.length, facets, groups, imported: 0 };
      }
      return { ok: true, json: async () => body };
    },
  };
  return api;
}

module.exports = { fakeClientsApi, osKey };
