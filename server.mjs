import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { questionnaire, evaluatePolicy, combineAssessment } from './src/policy.mjs';

export async function startReviewServer(scan, locations = new Map()) {
  const token = randomBytes(32).toString('hex');
  const assets = new Map(await Promise.all(['index.html', 'app.js', 'style.css'].map(async name => [name, await readFile(new URL(`./web/${name}`, import.meta.url))])));
  let origin;
  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    const end = (code, text) => { res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(text); };
    if (req.headers.host !== new URL(origin).host) return end(403, '접근 거부');
    if (req.headers.origin && req.headers.origin !== origin) return end(403, '접근 거부');
    if (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site'])) return end(403, '접근 거부');
    let url;
    try { url = new URL(req.url, origin); } catch { return end(400, '잘못된 요청'); }
    const name = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    if (req.method === 'GET' && assets.has(name)) {
      res.writeHead(200, { 'Content-Type': name.endsWith('.js') ? 'text/javascript; charset=utf-8' : name.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/html; charset=utf-8' });
      return res.end(assets.get(name));
    }
    const auth = Buffer.from(req.headers.authorization || '');
    const expected = Buffer.from(`Bearer ${token}`);
    if (auth.length !== expected.length || !timingSafeEqual(auth, expected)) return end(403, '접근 거부');
    if (req.method === 'GET' && url.pathname === '/api/review') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ scan, questionnaire }));
    }
    if (req.method === 'GET' && url.pathname === '/api/location') {
      const id = url.searchParams.get('id');
      if (!/^F\d{5}$/.test(id || '') || !locations.has(id)) return end(404, '위치를 찾을 수 없음');
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ relativePath: locations.get(id) }));
    }
    if (req.method !== 'POST' || url.pathname !== '/api/assess') return end(404, '찾을 수 없음');
    if (req.headers.origin !== origin || req.headers['content-type'] !== 'application/json') return end(403, '접근 거부');
    let size = 0;
    const chunks = [];
    try {
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 16384) { end(413, '입력 한도 초과'); return; }
        chunks.push(chunk);
      }
      const answers = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!answers || Array.isArray(answers) || typeof answers !== 'object') return end(400, '선택 항목을 확인하세요.');
      const allowed = new Map(questionnaire.map(q => [q.id, new Set(q.options.map(o => o.value))]));
      if (Object.entries(answers).some(([key, value]) => !allowed.has(key) || !allowed.get(key).has(value))) return end(400, '선택 항목을 확인하세요.');
      const report = combineAssessment(scan, evaluatePolicy(answers));
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(report));
    } catch { if (!res.headersSent) end(400, '평가를 완료하지 못했습니다.'); }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  server.maxConnections = 16;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  origin = `http://127.0.0.1:${server.address().port}`;
  return { server, url: `${origin}/#${token}`, origin, token };
}
