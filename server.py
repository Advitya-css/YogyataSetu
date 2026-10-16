"""
YogyataSetu website.

Run:    python server.py         then open http://127.0.0.1:5000
Data:   data/schemes.json        all schemes (edit, then restart)
        data/states.json         state names, languages and service centres
Text:   i18n/<language>.json     interface text for each language
Check:  checker.py + store.py    "Is this scheme real?" checker; its database is data/yogyatasetu.db
Admin:  /admin                   review reports. Open from this computer, or set YS_ADMIN_KEY to log in from elsewhere
"""
import csv
import hmac
import json
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from urllib.parse import quote_plus, urlencode, urlparse

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request, session, url_for

import checker as checker_mod
from store import RateLimit, Store

BASE = Path(__file__).resolve().parent
app = Flask(__name__, template_folder=str(BASE / 'Templates'), 
            static_folder=str(BASE / 'public' / 'static'), static_url_path='/static')  # public/ is served by Vercel's CDN
app.json.ensure_ascii = False

# ---------------------------------------------------------------- languages
LANGS = [  # code, name in its own script, BCP-47 for speech
    ('en', 'English', 'en-IN'), ('hi', 'हिन्दी', 'hi-IN'), ('bn', 'বাংলা', 'bn-IN'), ('mr', 'मराठी', 'mr-IN'),
    ('te', 'తెలుగు', 'te-IN'), ('ta', 'தமிழ்', 'ta-IN'), ('gu', 'ગુજરાતી', 'gu-IN'), ('kn', 'ಕನ್ನಡ', 'kn-IN'),
    ('ml', 'മലയാളം', 'ml-IN'), ('or', 'ଓଡ଼ିଆ', 'or-IN'), ('pa', 'ਪੰਜਾਬੀ', 'pa-IN'), ('as', 'অসমীয়া', 'as-IN'),
]
LANG_CODES = [c for c, _, _ in LANGS]
UI = {}
for code in LANG_CODES:
    f = BASE / 'i18n' / f'{code}.json'
    if f.exists():
        UI[code] = json.loads(f.read_text(encoding='utf-8'))
LANG_CODES = [c for c in LANG_CODES if c in UI]

OCCUPATIONS = ['student', 'farmer', 'jobseeker', 'worker', 'business', 'homemaker', 'salaried', 'retired', 'other']
GENDERS = ['female', 'male', 'transgender']
CATEGORIES = ['welfare', 'health', 'education', 'farmers', 'jobs', 'women', 'housing', 'food', 'business', 'ids']
FLAGS = ['bpl', 'minority', 'disability', 'widow', 'pregnant']

# ---------------------------------------------------------------- data
SCHEMES = json.loads((BASE / 'data' / 'schemes.json').read_text(encoding='utf-8'))
STATES = json.loads((BASE / 'data' / 'states.json').read_text(encoding='utf-8'))
BY_ID = {s['id']: s for s in SCHEMES}
STATE_LIST = sorted({s['state'] for s in SCHEMES if s['state']}, key=lambda x: x)
REPORTS_FILE = BASE / 'data' / 'reports.csv'


@app.before_request
def fix_vercel_path():
    original_path = request.headers.get('x-matched-path') or request.environ.get('HTTP_X_MATCHED_PATH')
    if original_path:
        request.environ['PATH_INFO'] = original_path


def get_lang():
    lang = request.args.get('lang') or request.cookies.get('lang')
    if lang not in UI:
        best = request.accept_languages.best_match(LANG_CODES) if request else None
        lang = best or 'en'
    return lang


@app.after_request
def remember_lang(resp):
    if request.args.get('lang') in UI:
        resp.set_cookie('lang', request.args['lang'], max_age=60 * 60 * 24 * 365, samesite='Lax')
    return resp


# ---------------------------------------------------------------- text helpers
class Text:
    def __init__(self, lang):
        self.lang = lang
        self.ui = UI[lang]

    def t(self, key, **kw):
        s = self.ui.get(key) or UI['en'].get(key, key)
        try:
            return s.format(**kw) if kw else s
        except (KeyError, IndexError):
            return s

    def st_name(self, state):
        info = STATES.get(state, {})
        return info.get('names', {}).get(self.lang) or state

    def centre(self, state):
        c = STATES.get(state, {}).get('centre')
        if not c:
            return self.t('p_csc')
        return c.get(self.lang) or c.get('en')

    def sx(self, s, field):
        """Scheme text in the current language, falling back to English."""
        tx = s['text']
        return (tx.get(self.lang) or {}).get(field) or tx['en'][field]

    def has_lang(self, s):
        return self.lang in s['text'] and bool(s['text'][self.lang].get('benefit'))

    def occ_name(self, o):
        return self.ui.get('on_' + o) or self.t('ol_' + o)

    def note(self, s):
        n = s.get('note') or {}
        return n.get(self.lang) or n.get('en', '')

    def age_text(self, s):
        a, b = s['age']
        if a <= 0 and b >= 120:
            return self.t('age_any')
        if b >= 120:
            return self.t('age_plus', a=a)
        if a <= 0:
            return self.t('age_upto', b=b)
        return self.t('age_range', a=a, b=b)

    def where(self, s):
        return self.t('central') if s['level'] == 'central' else self.t('state_scheme', s=self.st_name(s['state']))

    def need_text(self, group):
        parts = [self.t('n_' + p) for p in group.split('|')]
        return f' {self.t("or_word")} '.join(parts)

    def needs_text(self, s):
        return ', '.join(self.need_text(g) for g in s['needs'])

    def place(self, key, state):
        return self.centre(state) if key == 'state_centre' else self.t('p_' + key)

    def step(self, s, key, params):
        """Return (icon, text, link) for one apply step."""
        icon = STEP_ICON.get(key, 'form')
        p = dict(params)
        link = None
        if key == 'web':
            link = p.get('url')
        if key == 'checklist' and p.get('url'):
            link = p['url']
        if key == 'visit':
            places = [self.place(x, s['state'] or '') for x in p.get('places', [])]
            p['places'] = f' {self.t("or_word")} '.join(places)
        if key == 'or_state_centre':
            p['centre'] = self.centre(s['state'])
        if key == 'call':
            link = 'tel:' + p.get('phone', '').replace('-', '')
        return icon, self.t('s_' + key, **p), link


STEP_ICON = {
    'web': 'web', 'tap': 'tap', 'aadhaar': 'ids', 'otp': 'otp', 'state': 'web', 'land': 'farmers', 'upload': 'upload',
    'submit': 'submit', 'ekyc': 'fingerprint', 'fingerprint': 'fingerprint', 'face_auth': 'phone', 'status': 'web',
    'register': 'phone', 'form': 'form', 'fee': 'money', 'fee_first': 'money', 'premium': 'money', 'deposit': 'money',
    'ask': 'form', 'wait': 'wait', 'state_portal': 'web', 'state_portal_or_nsp': 'web', 'card': 'card', 'app': 'phone',
    'hospital': 'hospital', 'call': 'call', 'call_ambulance': 'call', 'visit': 'visit', 'or_state_centre': 'visit',
    'or_csc': 'visit', 'or_bank': 'visit', 'school': 'school', 'institute_verify': 'school', 'auto_school': 'school',
    'show_id_bus': 'bus', 'auto_free': 'auto', 'auto_bill': 'auto', 'auto_pmkisan': 'auto', 'auto_land': 'auto',
    'find_canteen': 'food', 'bank': 'money', 'checklist': 'web', 'checklist_self': 'web', 'project': 'form',
    'register_pregnancy': 'health', 'hospital_delivery': 'hospital', 'go_on_9th': 'hospital', 'tb_register': 'hospital',
    'medical_board': 'hospital', 'join_shg': 'women', 'demand_work': 'jobs', 'jobcard': 'card', 'home_delivery': 'auto',
    'door_to_door': 'visit', 'choose_course': 'education', 'visit_centre': 'visit', 'training': 'education',
    'exam': 'education', 'soil_sample': 'farmers', 'vendor': 'tap', 'electricity': 'form', 'build_toilet': 'housing',
    'onorc': 'food', 'link_janaadhaar': 'ids', 'book_slot': 'web', 'camp': 'visit', 'wait_': 'wait',
}
CAT_ICON = {'health': 'health', 'education': 'education', 'farmers': 'farmers', 'jobs': 'jobs', 'women': 'women',
            'housing': 'housing', 'food': 'food', 'business': 'business', 'welfare': 'welfare', 'ids': 'ids',
            'community': 'community'}


@app.context_processor
def inject():
    lang = get_lang()
    tx = Text(lang)
    args = request.args.to_dict()
    lang_urls = {}
    for c in LANG_CODES:
        a = dict(args, lang=c)
        lang_urls[c] = request.path + '?' + urlencode(a)
    speech = dict((c, b) for c, _, b in LANGS)[lang]
    return dict(lang=lang, LANGS=[l for l in LANGS if l[0] in UI], lang_urls=lang_urls, speech_lang=speech,
                STATE_LIST=STATE_LIST, OCCUPATIONS=OCCUPATIONS, GENDERS=GENDERS, CATEGORIES=CATEGORIES, FLAGS=FLAGS,
                total=len(SCHEMES), central_count=sum(1 for s in SCHEMES if s['level'] == 'central'),
                state_count=len(STATE_LIST), CAT_ICON=CAT_ICON, tx=tx, t=tx.t, domain=domain,
                PX=url_for('static', filename='pixels.svg'))


@app.template_filter('ucfirst')
def ucfirst(text):
    return text[:1].upper() + text[1:] if text else text


def domain(url):
    try:
        netloc = urlparse(url).netloc.replace('www.', '')
        return netloc or url
    except Exception:
        return url


# ---------------------------------------------------------------- eligibility engine
def read_profile(args):
    errors = []
    raw_age = (args.get('age') or '').strip()
    age = None
    if raw_age:
        try:
            f_age = float(raw_age)
            if not 0 <= f_age <= 120:
                raise ValueError
            age = int(f_age)
        except (ValueError, OverflowError):
            errors.append('err_age')
            age = None
    gender = args.get('gender') if args.get('gender') in GENDERS else ''
    occupation = args.get('occupation') if args.get('occupation') in OCCUPATIONS else ''
    state = args.get('state') if (args.get('state') in STATE_LIST or args.get('state') == 'other') else ''
    area = args.get('area') if args.get('area') in ('rural', 'urban') else ''
    caste = args.get('caste') if args.get('caste') in ('general', 'sc', 'st', 'obc') else ''
    truthy = {'1', 'true', 'True', True, 1}
    more = args.get('more') in truthy
    flags = {f: args.get(f) in truthy for f in FLAGS}
    return dict(age=age, raw_age=raw_age, gender=gender, occupation=occupation, state=state, area=area, caste=caste,
                more=more, flags=flags), errors


def need_value(opt, p):
    """True / False / None (unknown) for one requirement."""
    if opt == 'woman':
        return p['gender'] == 'female'
    if opt in ('rural', 'urban'):
        return (p['area'] == opt) if p['area'] else None
    if opt in ('sc', 'st', 'obc'):
        return (p['caste'] == opt) if p['caste'] else None
    if opt in FLAGS:
        if p['flags'].get(opt):
            return True
        if opt in ('widow', 'pregnant') and p['gender'] != 'female':
            return False
        return False if p['more'] else None
    return None


def needs_status(s, p):
    overall = True
    for group in s['needs']:
        vals = [need_value(o, p) for o in group.split('|')]
        if any(v is True for v in vals):
            continue
        if all(v is False for v in vals):
            return False
        overall = None
    return overall


def match(p):
    best, also, maybe = [], [], []
    for s in SCHEMES:
        if s['kind'] == 'program':
            continue
        if s['level'] == 'state' and s['state'] != p['state']:
            continue
        if s.get('only_states') and p['state'] not in s['only_states']:
            continue
        a, b = s['age']
        if p['age'] is not None and not (a <= p['age'] <= b):
            continue
        if s['gender'] != 'all' and s['gender'] != p['gender']:
            continue
        if s['occ'] and p['occupation'] not in s['occ']:
            continue
        ns = needs_status(s, p)
        if ns is False:
            continue
        reasons = []
        if s['occ']:
            reasons.append(('why_occ', {'o': p['occupation']}))
        if s['gender'] != 'all':
            reasons.append(('why_gender', {'g': s['gender']}))
        if a > 0 or b < 120:
            reasons.append(('why_age', {'a': p['age'], 'r': s}))
        if s['id'] == 'pm-jay' and p['age'] is not None and p['age'] >= 70:
            reasons.append(('why_70', {}))
        reasons.append(('why_central', {}) if s['level'] == 'central' else ('why_state', {'s': s['state']}))
        item = (s, reasons)
        if ns is None:
            maybe.append(item)
        elif s['occ'] or s['needs'] or s['gender'] != 'all' or s['level'] == 'state' or a >= 25 or b <= 60:
            best.append(item)
        else:
            also.append(item)
    key = lambda i: (CATEGORIES.index(i[0]['cat'][0]) if i[0]['cat'][0] in CATEGORIES else 99, i[0]['level'] == 'central', i[0]['name'])
    best.sort(key=lambda i: (not i[0]['occ'], not i[0]['needs'], i[0]['level'] == 'central', key(i)))
    also.sort(key=key)
    maybe.sort(key=key)
    return best, also, maybe


# ---------------------------------------------------------------- pages
@app.route('/')
def home():
    counts = {c: sum(1 for s in SCHEMES if c in s['cat']) for c in CATEGORIES}
    state_counts = {st: sum(1 for s in SCHEMES if s['state'] == st) for st in STATE_LIST}
    return render_template('home.html', counts=counts, state_counts=state_counts, profile=read_profile({})[0],
                           page='home')


@app.route('/find')
def find():
    profile, errors = read_profile(request.args)
    complete = profile['age'] is not None and profile['gender'] and profile['occupation'] and profile['state']
    if not request.args or not complete or errors:
        if request.args and not complete and not errors and any(request.args.get(k) for k in ('age', 'gender', 'occupation', 'state')):
            errors.append('err_required')
        return render_template('find.html', profile=profile, errors=errors, searched=False, page='find')
    best, also, maybe = match(profile)
    return render_template('find.html', profile=profile, errors=[], searched=True, page='find', best=best, also=also,
                           maybe=maybe)


@app.route('/schemes')
def browse():
    q = (request.args.get('q') or '').strip().lower()
    st = request.args.get('state', '')
    level = request.args.get('level', '')
    cat = request.args.get('cat', '')
    items = []
    for s in SCHEMES:
        if st and not (s['state'] == st or s['level'] == 'central'):
            continue
        if level and s['level'] != level:
            continue
        if cat and cat not in s['cat']:
            continue
        if q:
            hay = [s['name'], s['state']] + [v for t in s['text'].values() for v in t.values()]
            hay += list(STATES.get(s['state'], {}).get('names', {}).values())
            hay = ' '.join(hay).lower()
            if not all(w in hay for w in q.split()):
                continue
        items.append(s)
    items.sort(key=lambda s: (s['level'] != 'central', s['state'], s['name']))
    return render_template('browse.html', items=items, q=request.args.get('q', ''), f_state=st, f_level=level,
                           f_cat=cat, page='browse')


@app.route('/scheme/<sid>')
def scheme(sid):
    s = BY_ID.get(sid)
    if not s:
        abort(404)
    tx = Text(get_lang())
    docs = list(s['docs'])
    extra = STATES.get(s['state'], {}).get('id_doc')
    if extra and extra not in docs:
        docs.insert(0, extra)
    steps = [tx.step(s, k, p) for k, p in s['steps']]
    search_url = 'https://www.google.com/search?q=' + quote_plus(f'"{s["name"]}" site:gov.in OR site:nic.in')
    related = [x for x in SCHEMES if x['id'] != s['id'] and x['cat'][0] == s['cat'][0]
               and (x['level'] == 'central' or x['state'] == s['state'])][:5]
    return render_template('scheme.html', s=s, docs=docs, steps=steps, search_url=search_url, related=related,
                           reported=request.args.get('reported'), page='scheme')


@app.route('/saved')
def saved():
    return render_template('saved.html', page='saved')


@app.route('/saved/items')
def saved_items():
    ids = [i for i in (request.args.get('ids') or '').split(',') if i in BY_ID]
    return render_template('_list.html', items=[BY_ID[i] for i in ids])


@app.route('/about')
def about():
    return render_template('about.html', page='about')


@app.route('/report/<sid>', methods=['POST'])
def report(sid):
    if sid not in BY_ID:
        abort(404)
    text = (request.form.get('text') or '').strip()[:1000]
    if text:
        clean_text = text.replace('\r\n', ' ').replace('\n', ' ')
        if clean_text.startswith(('=', '+', '-', '@', '\t', '\r')):
            clean_text = "'" + clean_text
        row = [datetime.now().isoformat(timespec='seconds'), sid, BY_ID[sid]['name'], get_lang(), clean_text]
        try:
            new = not REPORTS_FILE.exists()
            with open(REPORTS_FILE, 'a', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                if new:
                    w.writerow(['time', 'scheme_id', 'scheme_name', 'language', 'report'])
                w.writerow(row)
        except OSError:
            try:
                tmp_file = Path('/tmp') / 'reports.csv'
                new = not tmp_file.exists()
                with open(tmp_file, 'a', newline='', encoding='utf-8') as f:
                    w = csv.writer(f)
                    if new:
                        w.writerow(['time', 'scheme_id', 'scheme_name', 'language', 'report'])
                    w.writerow(row)
            except Exception:
                pass
    return redirect(url_for('scheme', sid=sid, reported=1) + '#report')


# ---------------------------------------------------------------- "Is this scheme real?" checker
CHECKER = checker_mod.load(BASE)
_default_db = (Path('/tmp') / 'yogyatasetu.db') if os.environ.get('VERCEL') else (BASE / 'data' / 'yogyatasetu.db')
STORE = Store(os.environ.get('YS_DB') or _default_db)
for _f in STORE.custom_fakes():
    CHECKER.add_fake(_f)
app.secret_key = os.environ.get('YS_SECRET') or STORE.secret
ADMIN_KEY = os.environ.get('YS_ADMIN_KEY', '')
CHECK_LIMIT = RateLimit(30, 5 * 60)      # 30 checks in 5 minutes per visitor
REPORT_LIMIT = RateLimit(10, 60 * 60)    # 10 reports an hour per visitor
TONE = {'real': 'good', 'official': 'good', 'caution': 'warn', 'unsure': 'warn', 'unknown': 'plain',
        'suspicious': 'bad', 'fake': 'bad', 'scam': 'bad'}
VERDICT_ICON = {'good': 'shield', 'warn': 'warn', 'plain': 'search', 'bad': 'stop'}
EXAMPLES = {
    'en': [('ex_real', 'PM Kisan Samman Nidhi'), ('ex_fake', 'PM Free Laptop Yojana 2026'),
           ('ex_scam', 'Congratulations! You are selected for PM Awas Yojana. Pay ₹2,500 registration fee on UPI '
                       'pmawas@ybl today to get your house.'),
           ('ex_link', 'http://pmkisan-gov.in/register')],
    'hi': [('ex_real', 'प्रधानमंत्री किसान सम्मान निधि'), ('ex_fake', 'प्रधानमंत्री फ्री लैपटॉप योजना'),
           ('ex_scam', 'बधाई हो! आपका चयन पीएम आवास योजना में हुआ है। घर पाने के लिए आज ही ₹2,500 रजिस्ट्रेशन शुल्क '
                       'UPI pmawas@ybl पर भेजें।'),
           ('ex_link', 'http://pmkisan-gov.in/register')],
}
HELP = {'cyber': 'https://cybercrime.gov.in', 'chakshu': 'https://sancharsaathi.gov.in/sfc/',
        'pib_wa': 'https://wa.me/918799711259', 'myscheme': 'https://www.myscheme.gov.in'}


def client_ip():
    if os.environ.get('YS_BEHIND_PROXY') == '1' or os.environ.get('VERCEL'):
        return (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()
    return request.remote_addr or ''


def scheme_brief(s, tx, external=False):
    return {'id': s['id'], 'name': s['name'], 'where': tx.where(s), 'amount': tx.sx(s, 'amount'),
            'benefit': tx.sx(s, 'benefit'), 'url': url_for('scheme', sid=s['id'], _external=external),
            'official': s.get('link') or None, 'official_host': domain(s['link']) if s.get('link') else None,
            'helpline': s.get('helpline') or None}


def present(res, tx, external=False):
    """Turn a checker result into what the page / API shows, in the visitor's language."""
    v = res['verdict']
    m = res.get('matched')
    f = CHECKER.fake(res['fake']) if res.get('fake') else None
    fake = None
    if f:
        claim = f.get('claim') or {}
        fake = {'id': f['id'], 'kind': f.get('kind', 'fake'), 'name': f['name'],
                'claim': claim.get(tx.lang) or claim.get('en', ''), 'source': f.get('source'),
                'source_host': domain(f['source']) if f.get('source') else None, 'source2': f.get('source2'),
                'checked': f.get('checked')}
    sigs = [{'id': s['id'], 'sev': s['sev'], 'ev': s['ev'], 'text': tx.t('sig_' + s['id'])} for s in res['signals']]
    links = [{'url': ln['url'], 'host': ln['host'], 'status': ln['status'], 'label': tx.t('l_' + ln['status']),
              'why': tx.t('sig_' + ln['signal']) if ln['signal'] else ''} for ln in res['links']]
    tone = TONE.get(v, 'plain')
    return {
        'verdict': v, 'tone': tone, 'icon': VERDICT_ICON[tone],
        'title': tx.t(f'v_{v}_t'), 'body': tx.t(f'v_{v}_b', n=len(SCHEMES)),
        'confirmed': bool(res.get('confirmed')),
        'scheme': scheme_brief(BY_ID[m['id']], tx, external) if m and m['id'] in BY_ID else None,
        'also': [scheme_brief(BY_ID[i], tx, external) for i in res.get('also', []) if i in BY_ID],
        'suggest': [scheme_brief(BY_ID[i], tx, external) for i in res.get('suggest', []) if i in BY_ID],
        'fake': fake, 'signals': sigs, 'links': links, 'highlights': res.get('spans', []),
        'seen': res.get('seen', 0), 'reports': res.get('reports', 0), 'hash': res['hash'],
    }


def run_check(text, lang, state=None, via='web'):
    """Check one text. Returns (result, error_key)."""
    text = (text or '')[:checker_mod.MAX_LEN]
    if not text.strip():
        return None, 'err_empty'
    if not CHECK_LIMIT.ok(STORE.visitor(client_ip())):
        return None, 'err_rate'
    res = CHECKER.check(text, labels=STORE.labels(), state=state)
    try:
        STORE.log_check(res, lang, client_ip(), via)
        res.update(STORE.counts(res['hash']))
    except Exception as e:  # the check still works if the database is busy or read-only
        app.logger.warning('could not save check: %s', e)
    return res, None


@app.route('/check', methods=['GET', 'POST'])
def check():
    lang = get_lang()
    tx = Text(lang)
    q = (request.values.get('q') or '')[:checker_mod.MAX_LEN]
    result, segs, error = None, None, None
    asked = request.method == 'POST' or 'q' in request.args
    if asked:
        res, error = run_check(q, lang)
        if res:
            result = present(res, tx)
            if res['spans'] and (len(q) > 50 or len(res['spans']) > 1):
                segs = checker_mod.segments(q, res['spans'])
    status = 429 if error == 'err_rate' else 200
    share_url = url_for('check', q=q, lang=lang, _external=True) if result and len(q) <= 300 else None
    return render_template('check.html', q=q, result=result, segs=segs, error=error, page='check',
                           examples=EXAMPLES.get(lang, EXAMPLES['en']), reported=request.args.get('reported'),
                           HELP=HELP, share_url=share_url), status


@app.route('/check/report', methods=['POST'])
def check_report():
    lang = get_lang()
    q = (request.form.get('q') or '')[:checker_mod.MAX_LEN]
    note = (request.form.get('note') or '').strip()[:500]
    if q.strip() and REPORT_LIMIT.ok(STORE.visitor(client_ip())):
        res = CHECKER.check(q, labels=STORE.labels())
        STORE.add_report(res['hash'], q, note, res['verdict'], lang, client_ip())
    return redirect(url_for('check', reported=1, lang=lang) + '#result')


# ---------------------------------------------------------------- admin (review reports, add fakes)
def admin_token():
    return hmac.new(app.secret_key.encode(), ADMIN_KEY.encode(), 'sha256').hexdigest()


def is_admin():
    if ADMIN_KEY:
        return hmac.compare_digest(session.get('admin', ''), admin_token())
    return request.remote_addr in ('127.0.0.1', '::1')


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_hex(16)
    return session['csrf']


def csrf_ok():
    return hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf', '-'))


@app.route('/admin')
def admin():
    if not is_admin():
        return render_template('admin.html', page='admin', login=True, has_key=bool(ADMIN_KEY),
                               bad=request.args.get('bad')), (401 if ADMIN_KEY else 403)
    status = request.args.get('status', 'open')
    if status not in ('open', 'scam', 'safe', 'dismissed'):
        status = 'open'
    groups = STORE.report_groups(status)
    for g in groups:
        r = CHECKER.check(g['text'], labels=STORE.labels())
        g['now'] = r['verdict']
        g['now_scheme'] = (r.get('matched') or {}).get('id')
        g['now_fake'] = r.get('fake')
    custom = {f['id'] for f in STORE.custom_fakes()}
    fakes = [dict(f, custom=f['id'] in custom) for f in CHECKER.fakes]
    return render_template('admin.html', page='admin', login=False, stats=STORE.stats(), groups=groups,
                           status=status, labels=STORE.label_rows(), fakes=fakes, csrf=csrf_token(), BY_ID=BY_ID,
                           done=request.args.get('done'), has_key=bool(ADMIN_KEY))


@app.route('/admin/login', methods=['POST'])
def admin_login():
    if ADMIN_KEY and hmac.compare_digest(request.form.get('key', ''), ADMIN_KEY):
        session['admin'] = admin_token()
        return redirect(url_for('admin'))
    return redirect(url_for('admin', bad=1))


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('home'))


@app.route('/admin/action', methods=['POST'])
def admin_action():
    if not is_admin() or not csrf_ok():
        abort(403)
    h = request.form.get('hash', '')
    act = request.form.get('action')
    if not re.fullmatch(r'[0-9a-f]{32}', h):
        abort(400)
    if act in ('scam', 'safe'):
        STORE.set_label(h, act, (request.form.get('note') or '').strip()[:300] or None)
    elif act == 'dismiss':
        STORE.set_report_status(h, 'dismissed')
    elif act == 'unlabel':
        STORE.set_label(h, None)
    else:
        abort(400)
    return redirect(url_for('admin', status=request.form.get('status', 'open'), done=act))


def slug(s):
    s = re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
    return 'custom-' + (s[:50] or secrets.token_hex(3))


@app.route('/admin/fake', methods=['POST'])
def admin_fake():
    if not is_admin() or not csrf_ok():
        abort(403)
    if request.form.get('delete'):
        fid = request.form['delete']
        if fid.startswith('custom-'):
            STORE.delete_fake(fid)
            CHECKER.fakes = [f for f in CHECKER.fakes if f['id'] != fid]
            CHECKER.fake_index = [x for x in CHECKER.fake_index if x[0] != fid]
        return redirect(url_for('admin', done='deleted') + '#fakes')
    name = (request.form.get('name') or '').strip()[:120]
    if not name:
        return redirect(url_for('admin') + '#fakes')
    aliases = [a.strip()[:120] for a in re.split(r'[\n,]', request.form.get('aliases') or '') if a.strip()][:20]
    claim = (request.form.get('claim') or '').strip()[:600]
    source = (request.form.get('source') or '').strip()[:400]
    if source and not source.startswith(('http://', 'https://')):
        source = 'https://' + source
    real_id = request.form.get('real_id') if request.form.get('real_id') in BY_ID else None
    f = {'id': slug(name), 'kind': 'scam' if real_id else 'fake', 'name': name, 'aliases': aliases,
         'claim': {'en': claim} if claim else {}, 'checked': datetime.now().strftime('%Y-%m-%d'),
         'source': source or None, 'added_by': 'admin'}
    if real_id:
        # a scam that uses a real scheme's name: it matches when one of the scam phrases appears
        f['real_id'] = real_id
        f['patterns'] = [[re.escape(a) for a in (aliases or [name])]]
    STORE.add_fake(f)
    CHECKER.add_fake(f)
    return redirect(url_for('admin', done='added') + '#fakes')


# ---------------------------------------------------------------- JSON API (for the mobile app)
@app.route('/api/check', methods=['GET', 'POST'])
def api_check():
    """POST {"text": "...", "lang": "hi", "state": "Bihar"} -> verdict, matched scheme, fake details, signals, links"""
    data = request.get_json(silent=True) or request.values
    text = str(data.get('text') or data.get('q') or '')
    lang = data.get('lang') if data.get('lang') in UI else get_lang()
    state = data.get('state') if data.get('state') in STATE_LIST else None
    res, error = run_check(text, lang, state, via='api')
    if error:
        return jsonify({'error': error, 'message': Text(lang).t(error)}), (429 if error == 'err_rate' else 400)
    out = present(res, Text(lang), external=True)
    out['lang'] = lang
    return jsonify(out)


@app.route('/api/report', methods=['POST'])
def api_report():
    """POST {"text": "...", "note": "optional"} -- saves the text so the team can review it"""
    data = request.get_json(silent=True) or request.values
    text = str(data.get('text') or '')[:checker_mod.MAX_LEN]
    lang = data.get('lang') if data.get('lang') in UI else get_lang()
    if not text.strip():
        return jsonify({'error': 'err_empty'}), 400
    if not REPORT_LIMIT.ok(STORE.visitor(client_ip())):
        return jsonify({'error': 'err_rate'}), 429
    res = CHECKER.check(text, labels=STORE.labels())
    new = STORE.add_report(res['hash'], text, str(data.get('note') or '')[:500], res['verdict'], lang, client_ip())
    return jsonify({'ok': True, 'new': new, **STORE.counts(res['hash'])})


@app.route('/api/fakes')
def api_fakes():
    """Every fake scheme and known scam pattern the checker knows about."""
    lang = request.args.get('lang') if request.args.get('lang') in UI else 'en'
    out = []
    for f in CHECKER.fakes:
        claim = f.get('claim') or {}
        out.append({'id': f['id'], 'kind': f.get('kind', 'fake'), 'name': f['name'], 'aliases': f.get('aliases', []),
                    'claim': claim.get(lang) or claim.get('en', ''), 'real_scheme': f.get('real_id'),
                    'checked': f.get('checked'), 'source': f.get('source')})
    return jsonify(out)


@app.route('/api/schemes')
def api_schemes():
    ids = request.args.get('ids')
    items = [BY_ID[i] for i in ids.split(',') if i in BY_ID] if ids else SCHEMES
    return jsonify(items)


@app.route('/api/match', methods=['GET', 'POST'])
def api_match():
    args = request.get_json(silent=True) or request.values
    profile, errors = read_profile({k: str(v) for k, v in dict(args).items()})
    if errors:
        return jsonify({'errors': errors}), 400
    best, also, maybe = match(profile)
    return jsonify({k: [s['id'] for s, _ in v] for k, v in (('best', best), ('also', also), ('maybe', maybe))})


@app.errorhandler(404)
def not_found(e):
    return make_response(render_template('404.html', page=''), 404)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'\n  YogyataSetu is running:  http://127.0.0.1:{port}\n')
    app.run(host='127.0.0.1', port=port, debug=os.environ.get('DEBUG') == '1')
