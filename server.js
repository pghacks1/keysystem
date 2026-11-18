// ============================================================
// PGHACKS1 KEY SERVER — MAIN SERVER
// Node.js + Express + SQLite
// ============================================================

const express  = require('express');
const Database = require('better-sqlite3');
const crypto   = require('crypto');
const cors     = require('cors');
const path     = require('path');
const cfg      = require('./config');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── DATABASE SETUP ────────────────────────────────────────
const db = new Database(cfg.DB_PATH);

db.exec(`
CREATE TABLE IF NOT EXISTS keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_text    TEXT    UNIQUE NOT NULL,
    status      TEXT    DEFAULT 'active',
    expiry_date TEXT    DEFAULT NULL,
    max_devices INTEGER DEFAULT 1,
    note        TEXT    DEFAULT '',
    created_at  TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key_text    TEXT    NOT NULL,
    device_id   TEXT    NOT NULL,
    first_seen  TEXT    DEFAULT (datetime('now')),
    last_seen   TEXT    DEFAULT (datetime('now')),
    UNIQUE(key_text, device_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS activity_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_text   TEXT,
    device_id  TEXT,
    action     TEXT,
    result     TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
`);

// ── HELPERS ───────────────────────────────────────────────
function md5(str) {
    return crypto.createHash('md5').update(str).digest('hex');
}

function generateKey(prefix = 'PGH') {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let key = prefix + '-';
    for (let g = 0; g < 4; g++) {
        for (let i = 0; i < 4; i++) {
            key += chars[Math.floor(Math.random() * chars.length)];
        }
        if (g < 3) key += '-';
    }
    return key;
}

function logActivity(key_text, device_id, action, result) {
    try {
        db.prepare(`INSERT INTO activity_log (key_text, device_id, action, result) VALUES (?,?,?,?)`)
          .run(key_text, device_id || '', action, result);
    } catch(e) {}
}

function isExpiredDate(expiry_date) {
    if (!expiry_date) return false;
    return new Date(expiry_date) < new Date();
}

function checkSession(req) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (!token) return false;
    const session = db.prepare(`SELECT * FROM sessions WHERE token = ?`).get(token);
    if (!session) return false;
    const created = new Date(session.created_at);
    const now = new Date();
    const hours = (now - created) / (1000 * 60 * 60);
    if (hours > cfg.SESSION_TIMEOUT_HOURS) {
        db.prepare(`DELETE FROM sessions WHERE token = ?`).run(token);
        return false;
    }
    return true;
}

// ── KEY VERIFICATION ENDPOINT (Lua calls this) ───────────
// POST /server
// Body: game=PUBG&user_key=KEY&serial=DEVICE_UUID
app.post('/server', (req, res) => {
    const { game, user_key, serial } = req.body;
    const now = Math.floor(Date.now() / 1000);

    if (!game || !user_key || !serial) {
        logActivity(user_key, serial, 'verify', 'missing_params');
        return res.json({ status: false, reason: 'Missing parameters.' });
    }

    if (game !== cfg.GAME) {
        logActivity(user_key, serial, 'verify', 'wrong_game');
        return res.json({ status: false, reason: 'Invalid game.' });
    }

    // Find key
    const keyRow = db.prepare(`SELECT * FROM keys WHERE key_text = ?`).get(user_key);

    if (!keyRow) {
        logActivity(user_key, serial, 'verify', 'key_not_found');
        return res.json({ status: false, reason: 'Invalid key.' });
    }

    if (keyRow.status === 'blocked') {
        logActivity(user_key, serial, 'verify', 'key_blocked');
        return res.json({ status: false, reason: 'Key is blocked.' });
    }

    if (isExpiredDate(keyRow.expiry_date)) {
        // Auto-mark as expired
        db.prepare(`UPDATE keys SET status = 'expired' WHERE key_text = ?`).run(user_key);
        logActivity(user_key, serial, 'verify', 'key_expired');
        return res.json({ status: false, reason: 'Key has expired.' });
    }

    // Check device limit
    const deviceCount = db.prepare(
        `SELECT COUNT(DISTINCT device_id) as cnt FROM devices WHERE key_text = ?`
    ).get(user_key).cnt;

    const deviceExists = db.prepare(
        `SELECT id FROM devices WHERE key_text = ? AND device_id = ?`
    ).get(user_key, serial);

    if (!deviceExists && deviceCount >= keyRow.max_devices) {
        logActivity(user_key, serial, 'verify', 'max_devices');
        return res.json({ status: false, reason: 'Max Devices' });
    }

    // Register/update device
    db.prepare(`
        INSERT INTO devices (key_text, device_id) VALUES (?,?)
        ON CONFLICT(key_text, device_id) DO UPDATE SET last_seen = datetime('now')
    `).run(user_key, serial);

    // Generate token: MD5(game + '-' + key + '-' + serial + '-' + secret)
    const token = md5(`${game}-${user_key}-${serial}-${cfg.SECRET}`);

    logActivity(user_key, serial, 'verify', 'success');

    // Calculate expiry epoch
    let expiryEpoch = null;
    if (keyRow.expiry_date) {
        expiryEpoch = Math.floor(new Date(keyRow.expiry_date).getTime() / 1000);
    }

    res.json({
        status: true,
        data: {
            token: token,
            rng: now,
            ...(expiryEpoch ? { expiry: expiryEpoch } : {})
        }
    });
});

// ── ADMIN: LOGIN ──────────────────────────────────────────
app.post('/admin/login', (req, res) => {
    const { password } = req.body;
    if (password !== cfg.ADMIN_PASSWORD) {
        return res.json({ success: false, message: 'Wrong password!' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare(`INSERT INTO sessions (token) VALUES (?)`).run(token);
    res.json({ success: true, token });
});

// ── ADMIN MIDDLEWARE ──────────────────────────────────────
function requireAdmin(req, res, next) {
    if (!checkSession(req)) {
        return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    next();
}

// ── ADMIN: STATS ──────────────────────────────────────────
app.get('/admin/stats', requireAdmin, (req, res) => {
    const total   = db.prepare(`SELECT COUNT(*) as c FROM keys`).get().c;
    const active  = db.prepare(`SELECT COUNT(*) as c FROM keys WHERE status = 'active'`).get().c;
    const blocked = db.prepare(`SELECT COUNT(*) as c FROM keys WHERE status = 'blocked'`).get().c;
    const expired = db.prepare(`SELECT COUNT(*) as c FROM keys WHERE status = 'expired'`).get().c;
    const devices = db.prepare(`SELECT COUNT(DISTINCT device_id) as c FROM devices`).get().c;
    const logins  = db.prepare(`SELECT COUNT(*) as c FROM activity_log WHERE action = 'verify' AND result = 'success'`).get().c;

    res.json({ success: true, data: { total, active, blocked, expired, devices, logins } });
});

// ── ADMIN: LIST KEYS ──────────────────────────────────────
app.get('/admin/keys', requireAdmin, (req, res) => {
    const { search, status, page = 1 } = req.query;
    const limit = 50;
    const offset = (page - 1) * limit;

    let where = '1=1';
    const params = [];
    if (search) { where += ` AND key_text LIKE ?`; params.push(`%${search}%`); }
    if (status) { where += ` AND status = ?`; params.push(status); }

    const keys = db.prepare(`
        SELECT k.*,
               (SELECT COUNT(DISTINCT device_id) FROM devices WHERE key_text = k.key_text) as device_count,
               (SELECT MAX(last_seen) FROM devices WHERE key_text = k.key_text) as last_login
        FROM keys k WHERE ${where}
        ORDER BY k.created_at DESC LIMIT ? OFFSET ?
    `).all([...params, limit, offset]);

    const total = db.prepare(`SELECT COUNT(*) as c FROM keys WHERE ${where}`).get(params).c;

    res.json({ success: true, data: keys, total, page: +page, pages: Math.ceil(total/limit) });
});

// ── ADMIN: GENERATE KEY(S) ────────────────────────────────
app.post('/admin/keys/generate', requireAdmin, (req, res) => {
    const {
        count = 1,
        prefix = 'PGH',
        expiry_date = null,
        max_devices = cfg.DEFAULT_MAX_DEVICES,
        note = ''
    } = req.body;

    const generated = [];
    const stmt = db.prepare(`
        INSERT INTO keys (key_text, expiry_date, max_devices, note)
        VALUES (?, ?, ?, ?)
    `);

    const n = Math.min(parseInt(count) || 1, 100);
    for (let i = 0; i < n; i++) {
        let key;
        let tries = 0;
        do {
            key = generateKey(prefix);
            tries++;
        } while (tries < 20 && db.prepare(`SELECT id FROM keys WHERE key_text = ?`).get(key));

        stmt.run(key, expiry_date || null, parseInt(max_devices) || 1, note);
        generated.push(key);
    }

    logActivity(null, null, 'generate', `${n} keys generated`);
    res.json({ success: true, keys: generated });
});

// ── ADMIN: GET SINGLE KEY ─────────────────────────────────
app.get('/admin/keys/:key', requireAdmin, (req, res) => {
    const keyRow = db.prepare(`SELECT * FROM keys WHERE key_text = ?`).get(req.params.key);
    if (!keyRow) return res.json({ success: false, message: 'Key not found' });
    const devices = db.prepare(`SELECT * FROM devices WHERE key_text = ? ORDER BY last_seen DESC`).all(req.params.key);
    res.json({ success: true, data: keyRow, devices });
});

// ── ADMIN: UPDATE KEY ─────────────────────────────────────
app.put('/admin/keys/:key', requireAdmin, (req, res) => {
    const { status, expiry_date, max_devices, note } = req.body;
    const keyRow = db.prepare(`SELECT id FROM keys WHERE key_text = ?`).get(req.params.key);
    if (!keyRow) return res.json({ success: false, message: 'Key not found' });

    db.prepare(`
        UPDATE keys SET
            status      = COALESCE(?, status),
            expiry_date = COALESCE(?, expiry_date),
            max_devices = COALESCE(?, max_devices),
            note        = COALESCE(?, note)
        WHERE key_text = ?
    `).run(status||null, expiry_date||null, max_devices||null, note||null, req.params.key);

    logActivity(req.params.key, null, 'update', `status=${status}`);
    res.json({ success: true });
});

// ── ADMIN: DELETE KEY ─────────────────────────────────────
app.delete('/admin/keys/:key', requireAdmin, (req, res) => {
    db.prepare(`DELETE FROM devices WHERE key_text = ?`).run(req.params.key);
    db.prepare(`DELETE FROM keys WHERE key_text = ?`).run(req.params.key);
    logActivity(req.params.key, null, 'delete', 'deleted');
    res.json({ success: true });
});

// ── ADMIN: BLOCK / UNBLOCK ────────────────────────────────
app.post('/admin/keys/:key/block', requireAdmin, (req, res) => {
    db.prepare(`UPDATE keys SET status = 'blocked' WHERE key_text = ?`).run(req.params.key);
    logActivity(req.params.key, null, 'block', 'blocked');
    res.json({ success: true });
});

app.post('/admin/keys/:key/unblock', requireAdmin, (req, res) => {
    db.prepare(`UPDATE keys SET status = 'active' WHERE key_text = ?`).run(req.params.key);
    logActivity(req.params.key, null, 'unblock', 'active');
    res.json({ success: true });
});

// ── ADMIN: RESET DEVICES ──────────────────────────────────
app.delete('/admin/keys/:key/devices', requireAdmin, (req, res) => {
    db.prepare(`DELETE FROM devices WHERE key_text = ?`).run(req.params.key);
    logActivity(req.params.key, null, 'reset_devices', 'cleared');
    res.json({ success: true });
});

// ── ADMIN: ACTIVITY LOG ───────────────────────────────────
app.get('/admin/logs', requireAdmin, (req, res) => {
    const logs = db.prepare(`
        SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 200
    `).all();
    res.json({ success: true, data: logs });
});

// ── SERVE ADMIN PANEL ─────────────────────────────────────
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// ── START ─────────────────────────────────────────────────
app.listen(cfg.PORT, () => {
    console.log(`\n✅ PGHACKS1 Key Server running on port ${cfg.PORT}`);
    console.log(`📊 Admin panel: http://localhost:${cfg.PORT}/admin`);
    console.log(`🔑 Key verify: POST http://localhost:${cfg.PORT}/server\n`);
});
