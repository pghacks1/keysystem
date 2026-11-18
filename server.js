// ============================================================
// PGHACKS1 KEY SERVER — MAIN SERVER
// Node.js + Express + sqlite3 (async)
// ============================================================

const express  = require('express');
const sqlite3  = require('sqlite3').verbose();
const crypto   = require('crypto');
const cors     = require('cors');
const path     = require('path');
const cfg      = require('./config');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── DATABASE SETUP ────────────────────────────────────────
const db = new sqlite3.Database(cfg.DB_PATH);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        key_text    TEXT    UNIQUE NOT NULL,
        status      TEXT    DEFAULT 'active',
        expiry_date TEXT    DEFAULT NULL,
        max_devices INTEGER DEFAULT 1,
        note        TEXT    DEFAULT '',
        created_at  TEXT    DEFAULT (datetime('now'))
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        key_text    TEXT    NOT NULL,
        device_id   TEXT    NOT NULL,
        first_seen  TEXT    DEFAULT (datetime('now')),
        last_seen   TEXT    DEFAULT (datetime('now')),
        UNIQUE(key_text, device_id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        token      TEXT PRIMARY KEY,
        created_at TEXT DEFAULT (datetime('now'))
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS activity_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        key_text   TEXT,
        device_id  TEXT,
        action     TEXT,
        result     TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )`);
});

// ── HELPERS ───────────────────────────────────────────────
function md5(str) {
    return crypto.createHash('md5').update(str).digest('hex');
}

function generateKey(prefix = 'PG') {
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
    db.run(`INSERT INTO activity_log (key_text, device_id, action, result) VALUES (?,?,?,?)`,
        [key_text || '', device_id || '', action, result], () => {});
}

function isExpiredDate(expiry_date) {
    if (!expiry_date) return false;
    return new Date(expiry_date) < new Date();
}

function checkSession(req, cb) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (!token) return cb(false);
    db.get(`SELECT * FROM sessions WHERE token = ?`, [token], (err, session) => {
        if (err || !session) return cb(false);
        const created = new Date(session.created_at);
        const hours = (new Date() - created) / (1000 * 60 * 60);
        if (hours > cfg.SESSION_TIMEOUT_HOURS) {
            db.run(`DELETE FROM sessions WHERE token = ?`, [token]);
            return cb(false);
        }
        cb(true);
    });
}

function requireAdmin(req, res, next) {
    checkSession(req, (ok) => {
        if (!ok) return res.status(401).json({ success: false, message: 'Unauthorized' });
        next();
    });
}

// ── KEY VERIFICATION ENDPOINT (Lua calls this) ───────────
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

    db.get(`SELECT * FROM keys WHERE key_text = ?`, [user_key], (err, keyRow) => {
        if (err || !keyRow) {
            logActivity(user_key, serial, 'verify', 'key_not_found');
            return res.json({ status: false, reason: 'Invalid key.' });
        }
        if (keyRow.status === 'blocked') {
            logActivity(user_key, serial, 'verify', 'key_blocked');
            return res.json({ status: false, reason: 'Key is blocked.' });
        }
        if (isExpiredDate(keyRow.expiry_date)) {
            db.run(`UPDATE keys SET status = 'expired' WHERE key_text = ?`, [user_key]);
            logActivity(user_key, serial, 'verify', 'key_expired');
            return res.json({ status: false, reason: 'Key has expired.' });
        }

        db.get(`SELECT COUNT(DISTINCT device_id) as cnt FROM devices WHERE key_text = ?`, [user_key], (err2, row) => {
            const deviceCount = row ? row.cnt : 0;
            db.get(`SELECT id FROM devices WHERE key_text = ? AND device_id = ?`, [user_key, serial], (err3, deviceExists) => {
                if (!deviceExists && deviceCount >= keyRow.max_devices) {
                    logActivity(user_key, serial, 'verify', 'max_devices');
                    return res.json({ status: false, reason: 'Max Devices' });
                }

                db.run(`INSERT INTO devices (key_text, device_id) VALUES (?,?)
                    ON CONFLICT(key_text, device_id) DO UPDATE SET last_seen = datetime('now')`,
                    [user_key, serial]);

                const token = md5(`${game}-${user_key}-${serial}-${cfg.SECRET}`);
                logActivity(user_key, serial, 'verify', 'success');

                let expiryEpoch = null;
                if (keyRow.expiry_date) {
                    expiryEpoch = Math.floor(new Date(keyRow.expiry_date).getTime() / 1000);
                }

                res.json({
                    status: true,
                    data: {
                        token,
                        rng: now,
                        ...(expiryEpoch ? { expiry: expiryEpoch } : {})
                    }
                });
            });
        });
    });
});

// ── ADMIN: LOGIN ──────────────────────────────────────────
app.post('/admin/login', (req, res) => {
    const { password } = req.body;
    if (password !== cfg.ADMIN_PASSWORD) {
        return res.json({ success: false, message: 'Wrong password!' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    db.run(`INSERT INTO sessions (token) VALUES (?)`, [token]);
    res.json({ success: true, token });
});

// ── ADMIN: STATS ──────────────────────────────────────────
app.get('/admin/stats', requireAdmin, (req, res) => {
    const results = {};
    db.get(`SELECT COUNT(*) as c FROM keys`, [], (e, r) => { results.total = r.c;
    db.get(`SELECT COUNT(*) as c FROM keys WHERE status = 'active'`, [], (e, r) => { results.active = r.c;
    db.get(`SELECT COUNT(*) as c FROM keys WHERE status = 'blocked'`, [], (e, r) => { results.blocked = r.c;
    db.get(`SELECT COUNT(*) as c FROM keys WHERE status = 'expired'`, [], (e, r) => { results.expired = r.c;
    db.get(`SELECT COUNT(DISTINCT device_id) as c FROM devices`, [], (e, r) => { results.devices = r.c;
    db.get(`SELECT COUNT(*) as c FROM activity_log WHERE action = 'verify' AND result = 'success'`, [], (e, r) => {
        results.logins = r.c;
        res.json({ success: true, data: results });
    });});});});});});
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

    db.all(`
        SELECT k.*,
               (SELECT COUNT(DISTINCT device_id) FROM devices WHERE key_text = k.key_text) as device_count,
               (SELECT MAX(last_seen) FROM devices WHERE key_text = k.key_text) as last_login
        FROM keys k WHERE ${where}
        ORDER BY k.created_at DESC LIMIT ? OFFSET ?
    `, [...params, limit, offset], (err, keys) => {
        db.get(`SELECT COUNT(*) as c FROM keys WHERE ${where}`, params, (err2, row) => {
            const total = row ? row.c : 0;
            res.json({ success: true, data: keys || [], total, page: +page, pages: Math.ceil(total/limit) });
        });
    });
});

// ── ADMIN: GENERATE KEY(S) ────────────────────────────────
app.post('/admin/keys/generate', requireAdmin, (req, res) => {
    const { count = 1, prefix = 'PG', expiry_date = null, max_devices = cfg.DEFAULT_MAX_DEVICES, note = '' } = req.body;
    const n = Math.min(parseInt(count) || 1, 100);
    const generated = [];

    function insertNext(i) {
        if (i >= n) {
            logActivity(null, null, 'generate', `${n} keys generated`);
            return res.json({ success: true, keys: generated });
        }
        const key = generateKey(prefix);
        db.run(`INSERT OR IGNORE INTO keys (key_text, expiry_date, max_devices, note) VALUES (?,?,?,?)`,
            [key, expiry_date || null, parseInt(max_devices) || 1, note],
            function(err) {
                if (!err && this.changes > 0) {
                    generated.push(key);
                    insertNext(i + 1);
                } else {
                    insertNext(i); // retry with new key
                }
            }
        );
    }
    insertNext(0);
});

// ── ADMIN: GET SINGLE KEY ─────────────────────────────────
app.get('/admin/keys/:key', requireAdmin, (req, res) => {
    db.get(`SELECT * FROM keys WHERE key_text = ?`, [req.params.key], (err, keyRow) => {
        if (!keyRow) return res.json({ success: false, message: 'Key not found' });
        db.all(`SELECT * FROM devices WHERE key_text = ? ORDER BY last_seen DESC`, [req.params.key], (err2, devices) => {
            res.json({ success: true, data: keyRow, devices: devices || [] });
        });
    });
});

// ── ADMIN: UPDATE KEY ─────────────────────────────────────
app.put('/admin/keys/:key', requireAdmin, (req, res) => {
    const { status, expiry_date, max_devices, note } = req.body;
    db.run(`UPDATE keys SET
        status      = COALESCE(?, status),
        expiry_date = COALESCE(?, expiry_date),
        max_devices = COALESCE(?, max_devices),
        note        = COALESCE(?, note)
        WHERE key_text = ?`,
        [status||null, expiry_date||null, max_devices||null, note||null, req.params.key],
        () => {
            logActivity(req.params.key, null, 'update', `status=${status}`);
            res.json({ success: true });
        }
    );
});

// ── ADMIN: DELETE KEY ─────────────────────────────────────
app.delete('/admin/keys/:key', requireAdmin, (req, res) => {
    db.run(`DELETE FROM devices WHERE key_text = ?`, [req.params.key]);
    db.run(`DELETE FROM keys WHERE key_text = ?`, [req.params.key]);
    logActivity(req.params.key, null, 'delete', 'deleted');
    res.json({ success: true });
});

// ── ADMIN: BLOCK / UNBLOCK ────────────────────────────────
app.post('/admin/keys/:key/block', requireAdmin, (req, res) => {
    db.run(`UPDATE keys SET status = 'blocked' WHERE key_text = ?`, [req.params.key]);
    logActivity(req.params.key, null, 'block', 'blocked');
    res.json({ success: true });
});

app.post('/admin/keys/:key/unblock', requireAdmin, (req, res) => {
    db.run(`UPDATE keys SET status = 'active' WHERE key_text = ?`, [req.params.key]);
    logActivity(req.params.key, null, 'unblock', 'active');
    res.json({ success: true });
});

// ── ADMIN: RESET DEVICES ──────────────────────────────────
app.delete('/admin/keys/:key/devices', requireAdmin, (req, res) => {
    db.run(`DELETE FROM devices WHERE key_text = ?`, [req.params.key]);
    logActivity(req.params.key, null, 'reset_devices', 'cleared');
    res.json({ success: true });
});

// ── ADMIN: ACTIVITY LOG ───────────────────────────────────
app.get('/admin/logs', requireAdmin, (req, res) => {
    db.all(`SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 200`, [], (err, logs) => {
        res.json({ success: true, data: logs || [] });
    });
});

// ── SERVE ADMIN PANEL ─────────────────────────────────────
app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'admin.html')); });
app.get('/admin', (req, res) => { res.sendFile(path.join(__dirname, 'admin.html')); });

// ── START ─────────────────────────────────────────────────
app.listen(cfg.PORT, () => {
    console.log(`\n✅ PGHACKS1 Key Server running on port ${cfg.PORT}`);
    console.log(`📊 Admin panel: http://localhost:${cfg.PORT}/admin`);
    console.log(`🔑 Key verify: POST http://localhost:${cfg.PORT}/server\n`);
});
