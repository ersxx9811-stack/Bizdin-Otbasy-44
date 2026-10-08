// Біздің отбасы — шағын web-app сервері (тек Node.js ішкі модульдері, қосымша пакет керек емес).
// Іске қосу:  ADMIN_PASSWORD="сіздің-құпия-сөз" node server/server.mjs
// Деректер (бөлім → тақырып → фото) және фото файлдары DATA_DIR папкасында сақталады.
import http from 'node:http';
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, unlinkSync, createReadStream, statSync } from 'node:fs';
import { join, extname, resolve, sep } from 'node:path';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const PORT = Number(process.env.PORT || 8080);
const ROOT = resolve(process.env.STATIC_DIR || 'site');
const DATA = resolve(process.env.DATA_DIR || 'data');
const MEDIA = join(DATA, 'media');
const DB_FILE = join(DATA, 'db.json');
const MAX_PHOTO = 15 * 1024 * 1024;
const MAX_MUSIC = 40 * 1024 * 1024;
mkdirSync(MEDIA, { recursive: true });

// ---------- Құпия сөз: тек серверде, ортада (env) сақталады ----------
let PASS = process.env.ADMIN_PASSWORD;
if (!PASS) {
  PASS = randomBytes(6).toString('hex');
  console.warn(`\n⚠  ADMIN_PASSWORD берілмеген. Уақытша құпия сөз: ${PASS}\n   (Тұрақты құпия сөз үшін ADMIN_PASSWORD ортаны орнатыңыз.)\n`);
}
const SALT = Buffer.from('bizdin-otbasy');
const PASS_HASH = scryptSync(PASS, SALT, 32);
const SECRET_FILE = join(DATA, '.secret');
if (!existsSync(SECRET_FILE)) writeFileSync(SECRET_FILE, randomBytes(32).toString('hex'), { mode: 0o600 });
const SECRET = readFileSync(SECRET_FILE, 'utf8');
const sign = (s) => createHmac('sha256', SECRET).update(s).digest('base64url');
const SESSION_MS = 1000 * 60 * 60 * 24 * 14;
const makeToken = () => { const exp = String(Date.now() + SESSION_MS); return exp + '.' + sign(exp + '|' + PASS_HASH.toString('hex').slice(0, 16)); };
const okToken = (t) => {
  if (!t) return false; const [exp, sig] = t.split('.'); if (!exp || !sig || Number(exp) < Date.now()) return false;
  const want = sign(exp + '|' + PASS_HASH.toString('hex').slice(0, 16));
  return sig.length === want.length && timingSafeEqual(Buffer.from(sig), Buffer.from(want));
};
const cookieOf = (req, k) => (req.headers.cookie || '').split(/;\s*/).map((c) => c.split('=')).find(([n]) => n === k)?.[1];
const isAdmin = (req) => okToken(cookieOf(req, 'sid'));

// Құпия сөзді көп қайтара тексеруден қорғау
const fails = new Map();
const ipOf = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
const blocked = (ip) => { const f = fails.get(ip); return f && f.n >= 6 && Date.now() - f.t < 10 * 60 * 1000; };
const noteFail = (ip) => { const f = fails.get(ip); fails.set(ip, f && Date.now() - f.t < 10 * 60 * 1000 ? { n: f.n + 1, t: Date.now() } : { n: 1, t: Date.now() }); };

// ---------- Деректер қоры: sections → topics → photos ----------
let db = { sections: [], topics: [], photos: [], settings: {} };
if (existsSync(DB_FILE)) db = JSON.parse(readFileSync(DB_FILE, 'utf8'));
db.settings ||= {}; db.settings.slots ||= {}; db.settings.hidden ||= []; db.settings.music ??= null;
let writing = Promise.resolve();
const save = () => { const tmp = DB_FILE + '.tmp'; writeFileSync(tmp, JSON.stringify(db)); renameSync(tmp, DB_FILE); };
const rid = () => randomBytes(8).toString('hex');
const clean = (s) => String(s ?? '').replace(/\s+/g, ' ').trim().slice(0, 80);
const rmFile = (n) => { try { unlinkSync(join(MEDIA, n)); } catch {} };
const dropSlots = (ids) => { for (const k of Object.keys(db.settings.slots)) if (ids.some((i) => db.settings.slots[k] === 'u:' + i)) delete db.settings.slots[k]; };
const rmPhoto = (p) => { rmFile(p.file); if (p.thumb) rmFile(p.thumb); };
const pub = (p) => ({ id: p.id, topicId: p.topicId, name: p.name, w: p.w, h: p.h, at: p.at, url: '/media/' + p.file, thumb: '/media/' + (p.thumb || p.file) });

const MIME = { '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.ogg': 'audio/ogg', '.wav': 'audio/wav', '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.webp': 'image/webp', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.woff': 'font/woff', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon' };
const sniff = (b) => (b[0] === 0xff && b[1] === 0xd8 ? '.jpg' : b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) ? '.png' : b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP' ? '.webp' : null);

const sniffAudio = (b) => (b.slice(0, 3).toString() === 'ID3' || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0) ? '.mp3' : b.slice(4, 8).toString() === 'ftyp' ? '.m4a' : b.slice(0, 4).toString() === 'OggS' ? '.ogg' : b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WAVE' ? '.wav' : null);
const MIME_A = { '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.ogg': 'audio/ogg', '.wav': 'audio/wav' };
const musicPub = () => (db.settings.music ? { url: '/media/' + db.settings.music.file, name: db.settings.music.name } : null);
const settingsPub = () => ({ slots: db.settings.slots, hidden: db.settings.hidden, music: musicPub() });
const lib = () => db.photos.slice().sort((a, b) => a.at.localeCompare(b.at)).map((p) => { const t = db.topics.find((x) => x.id === p.topicId); const s = t && db.sections.find((x) => x.id === t.sectionId); return { ...pub(p), topicName: t?.name || '', sectionName: s?.name || '' }; });

const json = (res, code, obj, headers = {}) => { const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers }); res.end(b); };
const fail = (res, code, msg) => json(res, code, { error: msg });
const body = (req, limit) => new Promise((ok, no) => {
  const chunks = []; let n = 0;
  req.on('data', (c) => { n += c.length; if (n > limit) { no(Object.assign(new Error('big'), { code: 413 })); req.destroy(); } else chunks.push(c); });
  req.on('end', () => ok(Buffer.concat(chunks))); req.on('error', no);
});
const jbody = async (req) => { try { return JSON.parse((await body(req, 20_000)).toString() || '{}'); } catch { return null; } };

function tree() {
  return db.sections.map((s) => ({
    id: s.id, name: s.name,
    topics: db.topics.filter((t) => t.sectionId === s.id).map((t) => {
      const ph = db.photos.filter((p) => p.topicId === t.id);
      return { id: t.id, sectionId: s.id, name: t.name, count: ph.length, cover: ph[0] ? pub(ph[0]).thumb : null };
    }),
  }));
}

async function api(req, res, url) {
  const m = req.method, p = url.pathname;
  if (m === 'GET' && p === '/api/me') return json(res, 200, { admin: isAdmin(req) });
  if (m === 'GET' && p === '/api/settings') return json(res, 200, settingsPub());
  if (m === 'GET' && p === '/api/library') return json(res, 200, { photos: lib() });
  if (m === 'GET' && p === '/api/albums') return json(res, 200, { sections: tree() });
  let r;
  if (m === 'GET' && (r = p.match(/^\/api\/topics\/(\w+)$/))) {
    const t = db.topics.find((x) => x.id === r[1]); if (!t) return fail(res, 404, 'Тақырып табылмады');
    const s = db.sections.find((x) => x.id === t.sectionId);
    return json(res, 200, { topic: { id: t.id, name: t.name, sectionId: t.sectionId, sectionName: s?.name }, photos: db.photos.filter((x) => x.topicId === t.id).map(pub) });
  }
  if (m === 'POST' && p === '/api/login') {
    const ip = ipOf(req);
    if (blocked(ip)) return fail(res, 429, 'Тым көп қате әрекет. 10 минуттан кейін қайталаңыз.');
    const b = await jbody(req); if (!b) return fail(res, 400, 'Сұраныс дұрыс емес');
    const got = scryptSync(String(b.password ?? ''), SALT, 32);
    if (!timingSafeEqual(got, PASS_HASH)) { noteFail(ip); return fail(res, 401, 'Құпия сөз қате'); }
    fails.delete(ip);
    const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    return json(res, 200, { admin: true }, { 'Set-Cookie': `sid=${makeToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
  }
  if (m === 'POST' && p === '/api/logout') return json(res, 200, { admin: false }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });

  // --- Төмендегілер тек админге ---
  if (!isAdmin(req)) return fail(res, 401, 'Бұл әрекет үшін админ ретінде кіру керек');
  if (req.headers['x-app'] !== '1') return fail(res, 400, 'Сұраныс дұрыс емес');

  if (m === 'POST' && p === '/api/sections') {
    const b = await jbody(req); const name = clean(b?.name); if (!name) return fail(res, 400, 'Атауын жазыңыз');
    const s = { id: rid(), name }; db.sections.push(s); save(); return json(res, 201, s);
  }
  if ((r = p.match(/^\/api\/sections\/(\w+)$/))) {
    const s = db.sections.find((x) => x.id === r[1]); if (!s) return fail(res, 404, 'Бөлім табылмады');
    if (m === 'PATCH') { const b = await jbody(req); const name = clean(b?.name); if (!name) return fail(res, 400, 'Атауын жазыңыз'); s.name = name; save(); return json(res, 200, s); }
    if (m === 'DELETE') {
      const tids = db.topics.filter((t) => t.sectionId === s.id).map((t) => t.id);
      dropSlots(db.photos.filter((x) => tids.includes(x.topicId)).map((x) => x.id)); db.photos.filter((x) => tids.includes(x.topicId)).forEach(rmPhoto);
      db.photos = db.photos.filter((x) => !tids.includes(x.topicId)); db.topics = db.topics.filter((t) => t.sectionId !== s.id);
      db.sections = db.sections.filter((x) => x.id !== s.id); save(); return json(res, 200, { ok: true });
    }
  }
  if (m === 'POST' && (r = p.match(/^\/api\/sections\/(\w+)\/topics$/))) {
    if (!db.sections.some((x) => x.id === r[1])) return fail(res, 404, 'Бөлім табылмады');
    const b = await jbody(req); const name = clean(b?.name); if (!name) return fail(res, 400, 'Атауын жазыңыз');
    const t = { id: rid(), sectionId: r[1], name }; db.topics.push(t); save(); return json(res, 201, t);
  }
  if ((r = p.match(/^\/api\/topics\/(\w+)$/))) {
    const t = db.topics.find((x) => x.id === r[1]); if (!t) return fail(res, 404, 'Тақырып табылмады');
    if (m === 'PATCH') { const b = await jbody(req); const name = clean(b?.name); if (!name) return fail(res, 400, 'Атауын жазыңыз'); t.name = name; save(); return json(res, 200, t); }
    if (m === 'DELETE') {
      dropSlots(db.photos.filter((x) => x.topicId === t.id).map((x) => x.id)); db.photos.filter((x) => x.topicId === t.id).forEach(rmPhoto);
      db.photos = db.photos.filter((x) => x.topicId !== t.id); db.topics = db.topics.filter((x) => x.id !== t.id); save(); return json(res, 200, { ok: true });
    }
  }
  if (m === 'PUT' && (r = p.match(/^\/api\/topics\/(\w+)\/photos$/))) {
    if (!db.topics.some((x) => x.id === r[1])) return fail(res, 404, 'Тақырып табылмады');
    let buf; try { buf = await body(req, MAX_PHOTO); } catch (e) { return fail(res, e.code === 413 ? 413 : 400, e.code === 413 ? 'Фото тым үлкен (15 МБ-тан аспауы керек)' : 'Жүктеу үзілді'); }
    const ext = sniff(buf); if (!ext) return fail(res, 415, 'Бұл файл фото емес (JPG, PNG немесе WEBP керек)');
    const id = rid(); const file = id + ext; writeFileSync(join(MEDIA, file), buf);
    const w = Math.max(1, Math.min(20000, Number(url.searchParams.get('w')) || 4)), h = Math.max(1, Math.min(20000, Number(url.searchParams.get('h')) || 3));
    const ph = { id, topicId: r[1], file, thumb: null, name: clean(url.searchParams.get('name')).replace(/\.[^.]+$/, ''), w, h, at: new Date().toISOString() };
    db.photos.push(ph); save(); return json(res, 201, pub(ph));
  }
  if (m === 'PUT' && (r = p.match(/^\/api\/photos\/(\w+)\/thumb$/))) {
    const ph = db.photos.find((x) => x.id === r[1]); if (!ph) return fail(res, 404, 'Фото табылмады');
    let buf; try { buf = await body(req, 3 * 1024 * 1024); } catch { return fail(res, 413, 'Нобай тым үлкен'); }
    const ext = sniff(buf); if (!ext) return fail(res, 415, 'Фото емес');
    const file = ph.id + '-t' + ext; writeFileSync(join(MEDIA, file), buf); ph.thumb = file; save(); return json(res, 200, pub(ph));
  }
  if (m === 'PUT' && (r = p.match(/^\/api\/slots\/([a-z0-9-]{1,40})$/))) {
    const b = await jbody(req); const ref = String(b?.ref ?? '');
    if (!/^[su]:[\w-]{1,40}$/.test(ref) || (ref[0] === 'u' && !db.photos.some((x) => x.id === ref.slice(2)))) return fail(res, 400, 'Фото дұрыс таңдалмады');
    db.settings.slots[r[1]] = ref; save(); return json(res, 200, settingsPub());
  }
  if (m === 'DELETE' && (r = p.match(/^\/api\/slots\/([a-z0-9-]{1,40})$/))) { delete db.settings.slots[r[1]]; save(); return json(res, 200, settingsPub()); }
  if (m === 'PUT' && p === '/api/hidden') {
    const b = await jbody(req); const id = String(b?.id ?? '');
    if (!/^[\w-]{1,40}$/.test(id)) return fail(res, 400, 'Фото дұрыс емес');
    db.settings.hidden = db.settings.hidden.filter((x) => x !== id); if (b.hidden) db.settings.hidden.push(id); save(); return json(res, 200, settingsPub());
  }
  if (m === 'PUT' && p === '/api/music') {
    let buf; try { buf = await body(req, MAX_MUSIC); } catch (e) { return fail(res, e.code === 413 ? 413 : 400, e.code === 413 ? 'Файл тым үлкен (40 МБ-тан аспауы керек)' : 'Жүктеу үзілді'); }
    const ext = sniffAudio(buf); if (!ext) return fail(res, 415, 'Бұл аудио файл емес (MP3, M4A, OGG немесе WAV керек)');
    const file = 'music-' + rid() + ext; writeFileSync(join(MEDIA, file), buf);
    if (db.settings.music) rmFile(db.settings.music.file);
    db.settings.music = { file, name: clean(url.searchParams.get('name')).replace(/\.[^.]+$/, '') || 'Музыка' }; save(); return json(res, 200, settingsPub());
  }
  if (m === 'DELETE' && p === '/api/music') { if (db.settings.music) rmFile(db.settings.music.file); db.settings.music = null; save(); return json(res, 200, settingsPub()); }
  if (m === 'PATCH' && (r = p.match(/^\/api\/photos\/(\w+)$/))) {
    const ph = db.photos.find((x) => x.id === r[1]); if (!ph) return fail(res, 404, 'Фото табылмады');
    const b = await jbody(req); if (!b) return fail(res, 400, 'Сұраныс дұрыс емес');
    if (b.name !== undefined) ph.name = clean(b.name);
    if (b.topicId !== undefined) { if (!db.topics.some((x) => x.id === b.topicId)) return fail(res, 404, 'Тақырып табылмады'); ph.topicId = b.topicId; }
    save(); return json(res, 200, pub(ph));
  }
  if (m === 'DELETE' && (r = p.match(/^\/api\/photos\/(\w+)$/))) {
    const ph = db.photos.find((x) => x.id === r[1]); if (!ph) return fail(res, 404, 'Фото табылмады');
    rmPhoto(ph); db.photos = db.photos.filter((x) => x.id !== ph.id); dropSlots([ph.id]); save(); return json(res, 200, { ok: true });
  }
  return fail(res, 404, 'Табылмады');
}

function serveFile(req, res, file, cache) {
  const st = statSync(file); const type = MIME[extname(file).toLowerCase()] || 'application/octet-stream';
  const etag = `W/"${st.size}-${Math.floor(st.mtimeMs)}"`;
  const h = { 'Content-Type': type, 'Cache-Control': cache, ETag: etag, 'Accept-Ranges': 'bytes', 'X-Content-Type-Options': 'nosniff' };
  if (req.headers['if-none-match'] === etag && !req.headers.range) { res.writeHead(304); return res.end(); }
  const rg = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
  if (rg && (rg[1] || rg[2])) {
    let a = rg[1] ? Number(rg[1]) : Math.max(0, st.size - Number(rg[2])), z = rg[1] && rg[2] ? Number(rg[2]) : st.size - 1;
    z = Math.min(z, st.size - 1);
    if (a > z || a >= st.size) { res.writeHead(416, { 'Content-Range': `bytes */${st.size}` }); return res.end(); }
    res.writeHead(206, { ...h, 'Content-Range': `bytes ${a}-${z}/${st.size}`, 'Content-Length': z - a + 1 });
    if (req.method === 'HEAD') return res.end(); return createReadStream(file, { start: a, end: z }).pipe(res);
  }
  res.writeHead(200, { ...h, 'Content-Length': st.size });
  if (req.method === 'HEAD') return res.end(); createReadStream(file).pipe(res);
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x'); const p = decodeURIComponent(url.pathname);
    if (p.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    let base = ROOT, rel = p, cache = 'public, max-age=3600';
    if (p.startsWith('/media/')) { base = MEDIA; rel = p.slice(6); cache = 'public, max-age=31536000, immutable'; }
    else if (p.endsWith('/')) rel = p + 'index.html';
    const f = resolve(join(base, rel));
    if ((f !== base && !f.startsWith(base + sep)) || !existsSync(f) || statSync(f).isDirectory()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Табылмады'); }
    serveFile(req, res, f, /\.html$/.test(f) ? 'no-cache' : cache);
  } catch (e) { console.error(e); if (!res.headersSent) fail(res, 500, 'Сервер қатесі'); else res.end(); }
}).listen(PORT, () => console.log(`Сайт: http://localhost:${PORT}   (деректер: ${DATA})`));
