"""
Storage for the scheme checker: a single SQLite file (data/yogyatasetu.db, created on first run).

Privacy: a normal check never stores what the person pasted. We keep only a fingerprint of the text
(sha256 of the normalised text) and a salted fingerprint of the visitor's IP, so we can say
"12 people checked this message". The text itself is stored only when someone presses "Report as scam".

Tables
  checks        one row per check:   hash, verdict, matched scheme, fake id, language, visitor fingerprint, time
  reports       one row per report:  hash, message text, note, verdict at the time, status (open / scam / safe / dismissed)
  labels        decisions by the admin for an exact message: hash -> scam | safe
  fakes_custom  fake schemes added from the admin page (same shape as data/fakes.json)
  meta          random salt and secret key, made on first run
"""
import hashlib
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY, hash TEXT NOT NULL, verdict TEXT NOT NULL, matched TEXT, fake TEXT,
  lang TEXT, visitor TEXT, via TEXT, created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS checks_hash ON checks(hash);
CREATE INDEX IF NOT EXISTS checks_created ON checks(created);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY, hash TEXT NOT NULL, text TEXT NOT NULL, note TEXT, verdict TEXT, lang TEXT,
  visitor TEXT, status TEXT NOT NULL DEFAULT 'open', created TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reports_hash ON reports(hash);
CREATE TABLE IF NOT EXISTS labels (hash TEXT PRIMARY KEY, label TEXT NOT NULL CHECK (label IN ('scam', 'safe')),
  sample TEXT, note TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS fakes_custom (id TEXT PRIMARY KEY, data TEXT NOT NULL, created TEXT NOT NULL);
"""

REPORT_STATUSES = ('open', 'scam', 'safe', 'dismissed')


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class Store:
    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.Lock()
        with self.db() as c:
            c.executescript(SCHEMA)
            for k in ('salt', 'secret'):
                if not c.execute('SELECT 1 FROM meta WHERE k=?', (k,)).fetchone():
                    c.execute('INSERT INTO meta (k, v) VALUES (?, ?)', (k, secrets.token_hex(32)))
            self.salt = c.execute("SELECT v FROM meta WHERE k='salt'").fetchone()[0]
            self.secret = c.execute("SELECT v FROM meta WHERE k='secret'").fetchone()[0]
        self._labels = None

    @contextmanager
    def db(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        try:
            c.execute('PRAGMA journal_mode=WAL')
            yield c
            c.commit()
        finally:
            c.close()

    def visitor(self, ip):
        """Salted fingerprint of an IP address (the IP itself is never stored)."""
        return hashlib.sha256((self.salt + (ip or '')).encode()).hexdigest()[:20]

    # ------------------------------------------------------------ checks
    def log_check(self, res, lang, ip, via='web'):
        if res.get('verdict') == 'empty':
            return
        with self.db() as c:
            c.execute('INSERT INTO checks (hash, verdict, matched, fake, lang, visitor, via, created) VALUES (?,?,?,?,?,?,?,?)',
                      (res['hash'], res['verdict'], (res.get('matched') or {}).get('id'), res.get('fake'), lang,
                       self.visitor(ip), via, now()))

    def counts(self, h):
        """How many different people checked / reported this exact text."""
        with self.db() as c:
            seen = c.execute('SELECT COUNT(DISTINCT visitor) FROM checks WHERE hash=?', (h,)).fetchone()[0]
            rep = c.execute("SELECT COUNT(DISTINCT visitor) FROM reports WHERE hash=? AND status != 'dismissed'", (h,)).fetchone()[0]
        return {'seen': seen, 'reports': rep}

    # ------------------------------------------------------------ reports
    def add_report(self, h, text, note, verdict, lang, ip):
        """Returns False if this visitor already reported this text."""
        v = self.visitor(ip)
        with self.db() as c:
            if c.execute('SELECT 1 FROM reports WHERE hash=? AND visitor=?', (h, v)).fetchone():
                return False
            c.execute('INSERT INTO reports (hash, text, note, verdict, lang, visitor, created) VALUES (?,?,?,?,?,?,?)',
                      (h, text, note or None, verdict, lang, v, now()))
        return True

    def report_groups(self, status='open', limit=200):
        with self.db() as c:
            rows = c.execute(
                'SELECT hash, COUNT(DISTINCT visitor) n, MAX(created) last, MIN(created) first, '
                "GROUP_CONCAT(NULLIF(note, ''), ' | ') notes, MAX(verdict) verdict, MAX(id) rid "
                'FROM reports WHERE status=? GROUP BY hash ORDER BY n DESC, last DESC LIMIT ?', (status, limit)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d['text'] = c.execute('SELECT text FROM reports WHERE id=?', (r['rid'],)).fetchone()[0]
                d['seen'] = c.execute('SELECT COUNT(DISTINCT visitor) FROM checks WHERE hash=?', (r['hash'],)).fetchone()[0]
                out.append(d)
        return out

    def set_report_status(self, h, status):
        assert status in REPORT_STATUSES
        with self.db() as c:
            c.execute("UPDATE reports SET status=? WHERE hash=? AND status='open'", (status, h))

    def sample_text(self, h):
        with self.db() as c:
            r = c.execute('SELECT text FROM reports WHERE hash=? ORDER BY id DESC LIMIT 1', (h,)).fetchone()
        return r[0] if r else None

    # ------------------------------------------------------------ labels
    def labels(self):
        if self._labels is None:
            with self.db() as c:
                self._labels = {r['hash']: r['label'] for r in c.execute('SELECT hash, label FROM labels')}
        return self._labels

    def label_rows(self):
        with self.db() as c:
            return [dict(r) for r in c.execute('SELECT * FROM labels ORDER BY created DESC')]

    def set_label(self, h, label, note=None):
        with self._lock, self.db() as c:
            if label in ('scam', 'safe'):
                c.execute('INSERT OR REPLACE INTO labels (hash, label, sample, note, created) VALUES (?,?,?,?,?)',
                          (h, label, self.sample_text(h), note, now()))
                c.execute("UPDATE reports SET status=? WHERE hash=? AND status='open'", (label, h))
            else:
                c.execute('DELETE FROM labels WHERE hash=?', (h,))
            self._labels = None

    # ------------------------------------------------------------ custom fakes
    def custom_fakes(self):
        with self.db() as c:
            return [json.loads(r['data']) for r in c.execute('SELECT data FROM fakes_custom ORDER BY created')]

    def add_fake(self, f):
        with self.db() as c:
            c.execute('INSERT OR REPLACE INTO fakes_custom (id, data, created) VALUES (?,?,?)',
                      (f['id'], json.dumps(f, ensure_ascii=False), now()))

    def delete_fake(self, fid):
        with self.db() as c:
            c.execute('DELETE FROM fakes_custom WHERE id=?', (fid,))

    # ------------------------------------------------------------ numbers for the admin page
    def stats(self):
        week = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec='seconds')
        with self.db() as c:
            q = lambda sql, *a: c.execute(sql, a).fetchone()[0]
            by_verdict = {r[0]: r[1] for r in c.execute('SELECT verdict, COUNT(*) FROM checks GROUP BY verdict')}
            top_fakes = [dict(r) for r in c.execute(
                'SELECT fake, COUNT(*) n FROM checks WHERE fake IS NOT NULL GROUP BY fake ORDER BY n DESC LIMIT 8')]
            top_real = [dict(r) for r in c.execute(
                "SELECT matched, COUNT(*) n FROM checks WHERE matched IS NOT NULL AND verdict IN ('real','caution') "
                'GROUP BY matched ORDER BY n DESC LIMIT 8')]
            langs = {r[0]: r[1] for r in c.execute('SELECT lang, COUNT(*) FROM checks GROUP BY lang ORDER BY 2 DESC')}
            return {
                'checks': q('SELECT COUNT(*) FROM checks'),
                'checks_week': q('SELECT COUNT(*) FROM checks WHERE created >= ?', week),
                'people': q('SELECT COUNT(DISTINCT visitor) FROM checks'),
                'reports_open': q("SELECT COUNT(DISTINCT hash) FROM reports WHERE status='open'"),
                'labels': q('SELECT COUNT(*) FROM labels'),
                'by_verdict': by_verdict, 'top_fakes': top_fakes, 'top_real': top_real, 'langs': langs,
            }


class RateLimit:
    """Simple in-memory sliding window: at most `n` hits per `seconds` for each key."""

    def __init__(self, n, seconds):
        self.n, self.seconds = n, seconds
        self.hits = {}
        self._lock = threading.Lock()

    def ok(self, key):
        t = datetime.now().timestamp()
        with self._lock:
            q = [x for x in self.hits.get(key, []) if t - x < self.seconds]
            if len(q) >= self.n:
                self.hits[key] = q
                return False
            q.append(t)
            self.hits[key] = q
            if len(self.hits) > 5000:  # forget old visitors
                self.hits = {k: v for k, v in self.hits.items() if v and t - v[-1] < self.seconds}
            return True
