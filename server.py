import base64, hashlib, hmac, io, json, os, secrets, sqlite3, time, uuid, threading, shutil, datetime
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import quote, unquote, urlparse

try:
    import qrcode
    from qrcode.image.svg import SvgImage
except ImportError:
    qrcode = None
    SvgImage = None

ROOT = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.join(ROOT, 'vendor')
if os.path.isdir(VENDOR) and VENDOR not in __import__('sys').path:
    __import__('sys').path.insert(0, VENDOR)
DB_FILE = os.environ.get('DB_FILE', os.path.join('/app/data' if os.path.isdir('/app/data') else ROOT, 'rsp_smart_clinic.db'))
SESSIONS = {}
LOGIN_ATTEMPTS = {}
SESSION_TTL = int(os.environ.get('SESSION_TTL_SECONDS', '28800'))
MAX_LOGIN_ATTEMPTS = 8
LOGIN_WINDOW = 600
REG_ATTEMPTS = {}
REG_WINDOW = 900
MAX_REG_ATTEMPTS = 6
BACKUP_INTERVAL = int(os.environ.get('BACKUP_INTERVAL_SECONDS', '86400'))
BACKUP_DIR = os.environ.get('BACKUP_DIR', os.path.join(ROOT, 'backups'))


def conn():
    c = sqlite3.connect(DB_FILE, timeout=20)
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS registrations (id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS auth_config (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, changed_at TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS clinic_settings (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL)')
    c.commit()
    ensure_auth(c)
    ensure_settings(c)
    return c


def default_db():
    return {'patients': [], 'schedules': [], 'certs': [], 'audit': [], 'followUps': [], 'build': 73}


def pbkdf2(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 210_000)


def ensure_auth(c):
    row = c.execute('SELECT username FROM auth_config WHERE id=1').fetchone()
    if row:
        return
    user = os.environ.get('ADMIN_USER', 'admin').strip() or 'admin'
    pw = os.environ.get('ADMIN_PASSWORD', '').strip()
    if not pw:
        if os.environ.get('APP_ENV','').lower() == 'production':
            raise RuntimeError('ADMIN_PASSWORD wajib diisi pada lingkungan production.')
        pw = 'GantiPasswordKuat123!'
    salt = secrets.token_bytes(16)
    c.execute("INSERT INTO auth_config(id,username,salt,password_hash,changed_at) VALUES(1,?,?,?,datetime('now'))", (user, salt, pbkdf2(pw, salt)))
    c.commit()


def verify_password(c, username, password):
    row = c.execute('SELECT username,salt,password_hash FROM auth_config WHERE id=1').fetchone()
    if not row or not hmac.compare_digest(str(username), row[0]):
        return False
    return hmac.compare_digest(pbkdf2(str(password), row[1]), row[2])


def change_password(c, username, new_password):
    salt = secrets.token_bytes(16)
    c.execute("UPDATE auth_config SET salt=?, password_hash=?, changed_at=datetime('now') WHERE id=1", (salt, pbkdf2(new_password, salt)))
    c.commit()


def ensure_settings(c):
    row = c.execute('SELECT data FROM clinic_settings WHERE id=1').fetchone()
    if row:
        return
    data = {'clinicName':'RSP SMART CLINIC','tagline':'Rumah sunat modern, sunat aman dan menyenangkan','address':'','phone':'','whatsapp':'','publicBaseUrl':os.environ.get('PUBLIC_BASE_URL','').strip().rstrip('/') }
    c.execute('INSERT INTO clinic_settings(id,data) VALUES(1,?)', (json.dumps(data, ensure_ascii=False),))
    c.commit()


def get_settings(c):
    row = c.execute('SELECT data FROM clinic_settings WHERE id=1').fetchone()
    try: return json.loads(row[0]) if row else {}
    except Exception: return {}

def put_settings(c, data):
    c.execute('INSERT INTO clinic_settings(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data', (json.dumps(data, ensure_ascii=False),))
    c.commit()


def create_backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not os.path.exists(DB_FILE): return None
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    target = os.path.join(BACKUP_DIR, f'rsp_smart_clinic_{stamp}.db')
    src = sqlite3.connect(DB_FILE)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    files = sorted([os.path.join(BACKUP_DIR,x) for x in os.listdir(BACKUP_DIR) if x.endswith('.db')])
    for old in files[:-14]:
        try: os.remove(old)
        except OSError: pass
    return target

def backup_worker():
    while True:
        try: create_backup()
        except Exception as e: print('Backup otomatis gagal:', e)
        time.sleep(BACKUP_INTERVAL)


def get_state(c):
    row = c.execute('SELECT data FROM app_state WHERE id=1').fetchone()
    if not row:
        return default_db()
    try:
        data = json.loads(row[0])
        if not isinstance(data, dict):
            return default_db()
        return data
    except Exception:
        return default_db()


def put_state(c, data):
    c.execute(
        'INSERT INTO app_state(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
        (json.dumps(data, ensure_ascii=False),)
    )
    c.commit()


def public_base(handler=None):
    configured = os.environ.get('PUBLIC_BASE_URL', '').strip().rstrip('/')
    if not configured:
        try:
            c=conn(); configured=str(get_settings(c).get('publicBaseUrl','')).strip().rstrip('/'); c.close()
        except Exception:
            configured=''
    if configured:
        return configured
    if handler is not None:
        forwarded = handler.headers.get('X-Forwarded-Proto', '').split(',')[0].strip().lower()
        proto = 'https' if forwarded == 'https' else 'http'
        host = handler.headers.get('X-Forwarded-Host') or handler.headers.get('Host') or 'localhost:8080'
        return f'{proto}://{host}'
    return 'http://localhost:8080'


def configured_public_base():
    configured = os.environ.get('PUBLIC_BASE_URL', '').strip().rstrip('/')
    if not configured:
        try:
            c=conn(); configured=str(get_settings(c).get('publicBaseUrl','')).strip().rstrip('/'); c.close()
        except Exception:
            configured=''
    return configured

def public_qr_target(token):
    base = configured_public_base()
    if not base or not re.match(r'^https://', base, re.I):
        return None
    return base + '/verify/' + quote(token, safe='')

def ensure_qr_data(data, handler=None):
    if qrcode is None or not isinstance(data, dict):
        return data
    base = configured_public_base()
    if not base or not re.match(r'^https://', base, re.I):
        return data
    changed = False
    for cert in data.get('certs', []):
        if not isinstance(cert, dict):
            continue
        token = str(cert.get('token') or cert.get('id') or '')
        if token:
            target = base + '/verify/' + quote(token, safe='')
            # Regenerate when the public domain changes. Older builds kept stale QR data.
            if cert.get('qrTarget') != target or not cert.get('qrData'):
                qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=5, border=4)
                qr.add_data(target)
                qr.make(fit=True)
                img = qr.make_image(image_factory=SvgImage)
                buf = io.BytesIO()
                img.save(buf)
                cert['qrTarget'] = target
                cert['qrData'] = 'data:image/svg+xml;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')
                changed = True
    return data


def cert_by_token(c, token):
    for cert in get_state(c).get('certs', []):
        if str(cert.get('token', '')) == str(token):
            return cert
    return None


def safe_html(x):
    return (str(x).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;').replace("'", '&#39;'))


def verify_html(cert, settings=None):
    settings = settings or {}
    clinic = safe_html(settings.get('clinicName') or 'RSP SMART CLINIC')
    tagline = safe_html(settings.get('tagline') or 'Rumah sunat modern, sunat aman dan menyenangkan')
    no = safe_html(cert.get('no', ''))
    name = safe_html(cert.get('name', ''))
    date = safe_html(cert.get('date', ''))
    return f'''<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Verifikasi Sertifikat {no}</title><style>body{{margin:0;font-family:Arial;background:#f3faf6;color:#173a2c}}.wrap{{max-width:700px;margin:auto;padding:28px 18px}}.card{{background:#fff;border-radius:18px;padding:28px;box-shadow:0 12px 35px #0001}}.ok{{color:#087f45;font-weight:800}}.row{{padding:12px 0;border-bottom:1px solid #e6eee9}}button{{border:0;border-radius:10px;padding:12px 18px;background:#087f45;color:#fff;font-weight:700;cursor:pointer;margin-top:18px}}small{{color:#68756f}}.brand{{font-weight:800;font-size:22px;margin-bottom:20px}}</style></head><body><div class="wrap"><div class="card"><div class="brand">{clinic}</div><p><small>{tagline}</small></p><h1>Verifikasi Sertifikat</h1><p class="ok">✓ Sertifikat terdaftar dan valid.</p><div class="row"><small>Nomor Sertifikat</small><br><b>{no}</b></div><div class="row"><small>Nama Pasien</small><br><b>{name}</b></div><div class="row"><small>Tanggal Sertifikat</small><br><b>{date}</b></div><p><small>Halaman resmi verifikasi sertifikat RSP SMART CLINIC.</small></p><button onclick="window.print()">Cetak / Simpan PDF</button></div></div></body></html>'''


def cookie_value(headers, key):
    raw = headers.get('Cookie', '')
    for part in raw.split(';'):
        part = part.strip()
        if part.startswith(key + '='):
            return part.split('=', 1)[1]
    return ''


def session_user(handler):
    sid = cookie_value(handler.headers, 'rsp_session')
    if not sid:
        return None
    item = SESSIONS.get(sid)
    if not item:
        return None
    if item['expires'] < time.time():
        SESSIONS.pop(sid, None)
        return None
    item['expires'] = time.time() + SESSION_TTL
    return item['user']


def admin_configured():
    try:
        c=conn(); row=c.execute('SELECT 1 FROM auth_config WHERE id=1').fetchone(); c.close(); return bool(row)
    except Exception:
        return False


def origin_allowed(handler):
    origin = handler.headers.get('Origin', '')
    if not origin:
        return True
    expected = public_base(handler)
    return origin.rstrip('/') == expected.rstrip('/')


class Handler(SimpleHTTPRequestHandler):
    server_version = 'RSP-SMART-CLINIC/74'

    def log_message(self, fmt, *args):
        print('%s - %s' % (self.address_string(), fmt % args))

    def _json(self, status, obj, extra=None):
        raw = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get('Content-Length', '0'))
        if n > 5 * 1024 * 1024:
            raise ValueError('payload terlalu besar')
        return json.loads(self.rfile.read(n) or b'{}')

    def _require_admin(self):
        if not admin_configured():
            self._json(503, {'ok': False, 'error': 'Admin belum dikonfigurasi. Isi ADMIN_USER dan ADMIN_PASSWORD.'})
            return False
        if not session_user(self):
            self._json(401, {'ok': False, 'error': 'Sesi admin tidak valid atau sudah habis.'})
            return False
        return True

    def _serve_login(self):
        path = os.path.join(ROOT, 'admin', 'login.html')
        try:
            raw = open(path, 'rb').read()
        except OSError:
            self.send_error(500, 'Login page tidak tersedia')
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _serve_static_admin(self):
        rel = urlparse(self.path).path.lstrip('/')
        if not rel:
            rel = 'admin/index.html'
        path = os.path.normpath(os.path.join(ROOT, rel))
        if not path.startswith(os.path.join(ROOT, 'admin')) or not os.path.isfile(path):
            self.send_error(404)
            return
        self.send_response(200)
        ctype = 'text/html; charset=utf-8' if path.endswith('.html') else 'application/octet-stream'
        if path.endswith('.png'): ctype = 'image/png'
        self.send_header('Content-Type', ctype)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('Cache-Control', 'no-store' if path.endswith('.html') else 'public,max-age=86400')
        size = os.path.getsize(path)
        self.send_header('Content-Length', str(size))
        self.end_headers()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk: break
                self.wfile.write(chunk)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', public_base(self))
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.end_headers()

    def do_GET(self):
        p = urlparse(self.path).path

        if p in ('/admin', '/admin/'):
            if session_user(self):
                self.send_response(302); self.send_header('Location', '/admin/index.html'); self.end_headers()
            else:
                self._serve_login()
            return

        if p.startswith('/admin/'):
            if not session_user(self):
                self.send_response(302); self.send_header('Location', '/admin/'); self.end_headers(); return
            self._serve_static_admin(); return

        # Public website routes are intentionally outside the admin auth wall.
        # This fixes the Admin -> Website Publik button and gives the public site
        # stable URLs on both local and production deployments.
        if p in ('/website', '/website/'):
            self.send_response(302); self.send_header('Location', '/website/public.html'); self.end_headers(); return
        if p.startswith('/website/'):
            rel = p.lstrip('/')
            path = os.path.normpath(os.path.join(ROOT, rel))
            website_root = os.path.join(ROOT, 'website')
            if path == website_root:
                path = os.path.join(website_root, 'public.html')
            if not path.startswith(website_root) or not os.path.isfile(path):
                self.send_error(404); return
            ctype='text/html; charset=utf-8' if path.endswith('.html') else 'application/octet-stream'
            if path.endswith('.webmanifest'): ctype='application/manifest+json'
            if path.endswith('.js'): ctype='application/javascript; charset=utf-8'
            if path.endswith('.css'): ctype='text/css; charset=utf-8'
            if path.endswith('.png'): ctype='image/png'
            raw=open(path,'rb').read()
            self.send_response(200); self.send_header('Content-Type',ctype); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','strict-origin-when-cross-origin'); self.send_header('Cache-Control','no-store' if path.endswith('.html') else 'public,max-age=86400'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return

        if p in ('/public', '/public/'):
            self.send_response(302); self.send_header('Location','/website/public.html'); self.end_headers(); return

        if p == '/api/health':
            return self._json(200, {'ok': True, 'build': os.environ.get('RSP_BUILD', '74'), 'service': 'RSP SMART CLINIC', 'time': datetime.datetime.now(datetime.timezone.utc).isoformat()})

        if p == '/api/auth/me':
            return self._json(200, {'authenticated': bool(session_user(self)), 'user': session_user(self)})

        if p == '/api/public-status':
            c=conn(); data=get_settings(c); c.close()
            base=str(data.get('publicBaseUrl','')).strip().rstrip('/')
            valid=bool(base and re.match(r'^https://[^\s/]+(?:/[^\s]*)?$', base, re.I))
            return self._json(200, {'ok': True, 'configured': valid, 'publicBaseUrl': base, 'verifyPath': '/verify/<token>', 'message': 'Alamat publik HTTPS siap digunakan.' if valid else 'Alamat publik HTTPS belum dikonfigurasi.'})

        if p == '/api/public-settings':
            c=conn(); data=get_settings(c); c.close()
            safe={k:data.get(k,'') for k in ['clinicName','tagline','address','phone','whatsapp','publicBaseUrl']}
            return self._json(200,safe)

        if p == '/api/settings':
            if not self._require_admin(): return
            c=conn(); data=get_settings(c); c.close(); return self._json(200,data)

        if p == '/api/backups':
            if not self._require_admin(): return
            os.makedirs(BACKUP_DIR, exist_ok=True)
            rows=[]
            for name in sorted(os.listdir(BACKUP_DIR), reverse=True):
                if name.endswith('.db'):
                    path=os.path.join(BACKUP_DIR,name); rows.append({'name':name,'size':os.path.getsize(path),'modified':datetime.datetime.fromtimestamp(os.path.getmtime(path)).isoformat()})
            return self._json(200,rows)

        if p == '/api/db':
            if not self._require_admin(): return
            c = conn(); data = get_state(c); data = ensure_qr_data(data, self); put_state(c, data)
            return self._json(200, data)

        if p == '/api/registrations':
            if not self._require_admin(): return
            c = conn(); rows = c.execute('SELECT data FROM registrations ORDER BY created_at DESC').fetchall()
            return self._json(200, [json.loads(x[0]) for x in rows])

        if p.startswith('/api/certificate/'):
            token = unquote(p.rsplit('/', 1)[-1]); c = conn(); cert = cert_by_token(c, token)
            if not cert: return self._json(404, {'ok': False, 'error': 'Sertifikat tidak ditemukan'})
            return self._json(200, {'valid': True, 'no': cert.get('no',''), 'name': cert.get('name',''), 'date': cert.get('date',''), 'clinic': 'RSP SMART CLINIC'})

        if p.startswith('/verify/'):
            token = unquote(p.rsplit('/', 1)[-1]); c = conn(); cert = cert_by_token(c, token)
            if not cert:
                self.send_response(404); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write(b'<h1>Sertifikat tidak ditemukan</h1>'); return
            settings=get_settings(c); raw = verify_html(cert, settings).encode('utf-8')
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length', str(len(raw))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('X-Frame-Options','DENY'); self.end_headers(); self.wfile.write(raw); return

        if p.startswith('/api/qr/'):
            token = unquote(p.rsplit('/', 1)[-1]); c = conn(); cert = cert_by_token(c, token)
            if not cert or qrcode is None: return self._json(404, {'ok': False, 'error': 'QR tidak tersedia'})
            target = public_qr_target(token)
            if not target:
                return self._json(409, {'ok': False, 'error': 'Alamat publik HTTPS belum dikonfigurasi. Buka Pengaturan → Alamat publik verifikasi sertifikat.'})
            qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=5, border=4)
            qr.add_data(target); qr.make(fit=True)
            img = qr.make_image(image_factory=SvgImage); buf = io.BytesIO(); img.save(buf); raw = buf.getvalue()
            self.send_response(200); self.send_header('Content-Type','image/svg+xml'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Cache-Control','public,max-age=31536000'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw); return

        return super().do_GET()

    def do_POST(self):
        p = urlparse(self.path).path

        if p == '/api/auth/login':
            if not admin_configured(): return self._json(503, {'ok': False, 'error': 'ADMIN_USER dan ADMIN_PASSWORD belum diisi.'})
            ip = self.client_address[0]
            now = time.time(); attempts = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < LOGIN_WINDOW]
            if len(attempts) >= MAX_LOGIN_ATTEMPTS: return self._json(429, {'ok': False, 'error': 'Terlalu banyak percobaan login. Coba lagi beberapa menit.'})
            try: body = self._body()
            except Exception: return self._json(400, {'ok': False, 'error': 'JSON tidak valid'})
            user = str(body.get('username','')); pw = str(body.get('password',''))
            c = conn(); ok = verify_password(c, user, pw)
            if not ok:
                c.close()
                attempts.append(now); LOGIN_ATTEMPTS[ip] = attempts
                return self._json(401, {'ok': False, 'error': 'Username atau password salah.'})
            LOGIN_ATTEMPTS.pop(ip, None)
            c.execute('UPDATE app_state SET data=data WHERE id=1')
            c.close()
            sid = secrets.token_urlsafe(32); SESSIONS[sid] = {'user': user, 'expires': time.time()+SESSION_TTL}
            secure = '; Secure' if self.headers.get('X-Forwarded-Proto','').lower() == 'https' else ''
            cookie = f'rsp_session={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{secure}'
            return self._json(200, {'ok': True, 'user': user}, {'Set-Cookie': cookie})

        if p == '/api/auth/logout':
            sid = cookie_value(self.headers, 'rsp_session'); SESSIONS.pop(sid, None)
            return self._json(200, {'ok': True}, {'Set-Cookie': 'rsp_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'})

        if p == '/api/auth/change-password':
            if not self._require_admin(): return
            try: body=self._body()
            except Exception: return self._json(400, {'ok':False,'error':'JSON tidak valid'})
            current=str(body.get('currentPassword','')); new=str(body.get('newPassword',''))
            if len(new) < 10: return self._json(400, {'ok':False,'error':'Password baru minimal 10 karakter.'})
            c=conn(); user=session_user(self)
            if not verify_password(c,user,current): c.close(); return self._json(401, {'ok':False,'error':'Password lama salah.'})
            change_password(c,user,new); c.close()
            # revoke all sessions so the new credential is required everywhere
            SESSIONS.clear()
            return self._json(200, {'ok':True,'message':'Password berhasil diganti. Silakan login kembali.'}, {'Set-Cookie':'rsp_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'})

        if p == '/api/auth/logout-all':
            if not self._require_admin(): return
            SESSIONS.clear()
            return self._json(200, {'ok':True,'message':'Semua sesi telah dikeluarkan.'}, {'Set-Cookie':'rsp_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'})

        if p == '/api/settings':
            if not self._require_admin(): return
            if not origin_allowed(self): return self._json(403, {'ok':False,'error':'Origin tidak diizinkan'})
            try: body=self._body()
            except Exception: return self._json(400, {'ok':False,'error':'JSON tidak valid'})
            c=conn(); current=get_settings(c); current.update({k:str(body.get(k,current.get(k,''))).strip() for k in ['clinicName','tagline','address','phone','whatsapp','publicBaseUrl']}); put_settings(c,current); c.close(); return self._json(200, current)

        if p == '/api/backup/create':
            if not self._require_admin(): return
            path=create_backup(); return self._json(200, {'ok':True,'name':os.path.basename(path) if path else None})

        if p == '/api/registrations':
            ip = self.client_address[0]
            now = time.time(); attempts=[t for t in REG_ATTEMPTS.get(ip,[]) if now-t < REG_WINDOW]
            if len(attempts) >= MAX_REG_ATTEMPTS:
                return self._json(429, {'ok':False,'error':'Terlalu banyak pendaftaran dari jaringan ini. Silakan coba lagi nanti.'})
            try: body = self._body()
            except Exception: return self._json(400, {'ok': False, 'error': 'JSON tidak valid'})
            if not isinstance(body, dict) or not str(body.get('name','')).strip() or not str(body.get('wa','')).strip():
                return self._json(400, {'ok': False, 'error': 'Nama anak dan WhatsApp wajib diisi.'})
            # Honeypot for simple bots; the public form can submit an empty field.
            if str(body.get('website','')).strip():
                return self._json(400, {'ok':False,'error':'Pendaftaran tidak valid.'})
            attempts.append(now); REG_ATTEMPTS[ip]=attempts
            body.pop('website', None)
            body.setdefault('id', 'WEB-' + uuid.uuid4().hex[:10].upper()); body.setdefault('status', 'BARU')
            c = conn(); c.execute('INSERT OR REPLACE INTO registrations(id,data,created_at) VALUES(?,?,datetime(\'now\'))', (body['id'], json.dumps(body, ensure_ascii=False))); c.commit(); c.close()
            return self._json(201, {'ok': True, 'id': body['id']})

        if p in ('/api/db','/api/import'):
            if not self._require_admin(): return
            if not origin_allowed(self): return self._json(403, {'ok': False, 'error': 'Origin tidak diizinkan'})
            try: body = self._body()
            except Exception: return self._json(400, {'ok': False, 'error': 'JSON tidak valid'})
            if p == '/api/db':
                if not isinstance(body, dict): return self._json(400, {'ok': False, 'error': 'Format database tidak valid'})
                c = conn(); body = ensure_qr_data(body, self); put_state(c, body); return self._json(200, {'ok': True})
            c = conn(); put_state(c, body); return self._json(200, {'ok': True, 'message': 'Data berhasil diimpor'})

        return self._json(404, {'ok': False, 'error': 'Not found'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8080'))
    conn().close(); os.makedirs(BACKUP_DIR, exist_ok=True); os.chdir(ROOT)
    threading.Thread(target=backup_worker, daemon=True).start()
    print(f"RSP SMART CLINIC BUILD {os.environ.get('RSP_BUILD','73')} berjalan di http://0.0.0.0:{port}")
    ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever()
