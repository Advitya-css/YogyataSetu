"""
Scheme & scam checker.

check(text) looks at a scheme name, a link, or a forwarded message and returns a verdict:

  real        matches a real scheme, nothing suspicious
  caution     real scheme, but the message has warning signs
  fake        matches a scheme that PIB Fact Check (or our team) has said does not exist
  scam        known scam pattern, or strong scam signals (asks for fees, OTP, APK, fake website ...)
  official    only an official government link, nothing else suspicious
  unsure      looks a bit like a real scheme; we show "did you mean"
  suspicious  no scheme found and some warning signs
  unknown     no scheme found, no warning signs

Everything is explained with "signals" (rule id, severity 1-3, the words that triggered it) so the page can
show *why*. No network calls: it works offline from data/schemes.json, data/aliases.json and data/fakes.json.
"""
import hashlib
import json
import re
import unicodedata
from pathlib import Path

try:  # fast fuzzy matching if available (pip install rapidfuzz), otherwise difflib
    from rapidfuzz import fuzz as _fuzz
    from rapidfuzz import process as _process

    def ratio(a, b):
        return _fuzz.ratio(a, b)

    def best_ratio(word, choices, cutoff):
        r = _process.extractOne(word, choices, scorer=_fuzz.ratio, score_cutoff=cutoff)
        return r[1] if r else 0
except ImportError:  # pragma: no cover
    import difflib

    def ratio(a, b):
        return difflib.SequenceMatcher(None, a, b).ratio() * 100

    def best_ratio(word, choices, cutoff):
        best = 0
        for c in choices:
            if abs(len(c) - len(word)) > 2:
                continue
            r = ratio(word, c)
            if r > best:
                best = r
        return best if best >= cutoff else 0

BASE = Path(__file__).resolve().parent
MAX_LEN = 4000

# ------------------------------------------------------------------ text normalisation
_SUBS = [
    (r'pradhan\s*mantri|pradhanmantri|प्रधान\s*मंत्री|प्रधानमंत्री|पीएम|प्रधानमन्त्री|প্রধানমন্ত্রী|ప్రధానమంత్రి|பிரதமர்|પ્રધાનમંત્રી|ಪ್ರಧಾನ ಮಂತ್ರಿ|പ്രധാനമന്ത്രി|ପ୍ରଧାନମନ୍ତ୍ରୀ|ਪ੍ਰਧਾਨ ਮੰਤਰੀ', ' pm '),
    (r'mukh(?:ya)?\s*mantri|mukhyamantri|मुख्य\s*मंत्री|मुख्यमंत्री|मुख्यमन्त्री|मुख्यमंत्र्यांचा', ' cm '),
    (r'\byojna\b|\byojona\b|\byojanaa\b|योजना|যোজনা|ਯੋਜਨਾ|યોજના|ଯୋଜନା|ಯೋಜನೆ|యోజన|திட்டம்|പദ്ധതി', ' yojana '),
    (r'\bpm[\s-]+', ' pm '),
]
STOP = {
    'pm', 'cm', 'yojana', 'scheme', 'schemes', 'the', 'of', 'for', 'and', 'a', 'an', 'to', 'in', 'on', 'card', 'mission',
    'programme', 'program', 'abhiyan', 'karyakram', 'india', 'bharat', 'national', 'rashtriya', 'state', 'govt',
    'government', 'sarkar', 'chief', 'minister', 'ministers', 'prime', 'new', 'online', 'apply', 'registration',
    'form', 'status', 'list', 'check', 'kya', 'hai', 'है', 'क्या', 'की', 'का', 'के', 'में', 'और', 'से', 'को', 'free', 'with',
    'all', 'sabhi', 'up', 'by', 'from', 'is', 'are', 'this', 'that', 'it', 'you', 'your', 'kendra', 'centre', 'center',
    '2', '0', '4', '2026', '2025', 'others', 'women', 'girls', 'students', 'youth', 'citizens', 'persons', 'people',
}
PAREN = re.compile(r'\(([^)]*)\)')


def norm(s):
    s = unicodedata.normalize('NFKC', s or '').lower()
    s = re.sub('[​-‍﻿]', '', s).replace('़', '')
    for pat, rep in _SUBS:
        s = re.sub(pat, rep, s)
    s = ''.join(ch if unicodedata.category(ch)[0] in 'LMN' else ' ' for ch in s)
    return ' '.join(s.split())


def tokens(n):
    return [t for t in n.split() if t]


def distinct(toks):
    return [t for t in toks if t not in STOP and not (t.isdigit() and len(t) < 3) and len(t) > 1]


def text_hash(text):
    return hashlib.sha256(norm(text)[:MAX_LEN].encode('utf-8')).hexdigest()[:32]


# ------------------------------------------------------------------ scam signals
# severity: 3 = strong scam sign on its own, 2 = warning, 1 = mild
SIGNALS = [
    ('fee', 3, r'(registration|processing|approval|activation|verification|insurance|delivery|security|file|form|gst|token)\s*(fee|fees|charge|charges|amount)'
               r'|(पंजीकरण|रजिस्ट्रेशन|प्रोसेसिंग|स्वीकृति|बीमा|सत्यापन|फॉर्म|फाइल)\s*(शुल्क|फीस|फ़ीस|चार्ज|राशि)'
               r'|নিবন্ধন ফি|রেজিস্ট্রেশন ফি|नोंदणी शुल्क|నమోదు రుసుము|பதிவு கட்டணம்|નોંધણી ફી|ನೋಂದಣಿ ಶುಲ್ಕ|രജിസ്ട്രേഷൻ ഫീസ്|ପଞ୍ଜୀକରଣ ଫି|ਰਜਿਸਟ੍ਰੇਸ਼ਨ ਫੀਸ'),
    ('pay', 2, r'\b(pay|send|transfer|deposit)\b[^.\n]{0,25}(₹|\brs\b\.?|\binr\b|rupees)'
               r'|(₹|\brs\b\.?)\s?[\d,]+[^.\n]{0,25}\b(pay|send|transfer|deposit)\b'
               r'|पैसे भेजें|पैसे भेजो|राशि जमा करें|भुगतान करें|पेमेंट करें|ट्रांसफर करें|टाका পাঠান|पैसे पाठवा|డబ్బు పంపండి|பணம் அனுப்பவும்|પૈસા મોકલો|ಹಣ ಕಳುಹಿಸಿ|പണം അയയ്ക്കുക|ଟଙ୍କା ପଠାନ୍ତୁ|ਪੈਸੇ ਭੇਜੋ'),
    ('upi', 3, r'\bupi\s*(id|pin)\b|scan (the |this )?qr|qr code|phone ?pe|paytm|google ?pay|\bgpay\b|यूपीआई|क्यूआर|[a-z0-9._-]{3,}@(ybl|oksbi|okhdfcbank|okicici|okaxis|paytm|upi|ibl|axl|apl)\b'),
    ('otp', 3, r'(share|send|tell|give|forward|bhejo|bhejen|batao|batayen|बताएं|बताओ|भेजें|भेजो|शेयर करें|দিন|पाठवा|చెప్పండి|சொல்லுங்கள்|કહો|ತಿಳಿಸಿ|പറയുക|କୁହନ୍ତୁ|ਦੱਸੋ)[^.\n]{0,30}(\botp\b|\bpin\b|\bcvv\b|password|ओटीपी|पिन|পিন|ఓటీపీ|ஓடிபி)'
               r'|(\botp\b|\bpin\b|\bcvv\b|ओटीपी|पिन)[^.\n]{0,30}(share|send|tell|bhejo|batao|बताएं|बताओ|भेजें|भेजो|शेयर करें)'),
    ('apk', 3, r'\.apk\b|\bapk\b|एपीके|(download|install|डाउनलोड|इंस्टॉल)[^.\n]{0,40}(app|ऐप|एप)[^.\n]{0,30}(link|whatsapp|लिंक|व्हाट्सऐप)'),
    ('remote', 3, r'anydesk|any desk|teamviewer|team viewer|quick ?support|airdroid|rustdesk|screen ?share|स्क्रीन शेयर'),
    ('card', 3, r'(atm|debit|credit)\s*card\s*(number|no|details|pin|cvv)|card (number|details) (and|&) cvv|कार्ड नंबर'),
    ('bank', 2, r'(send|share|whatsapp|bhejo|भेजें|भेजो|शेयर)[^.\n]{0,40}(aadhaar|aadhar|\bpan\b|bank|account|passbook|आधार|बैंक|खाता|पासबुक)'
                r'|(aadhaar|aadhar|bank|account|passbook|आधार|बैंक|खाता|पासबुक)[^.\n]{0,40}(send|share|whatsapp|bhejo|भेजें|भेजो)'),
    ('prize', 2, r'congratulations|congrats|you (have been|are|were) selected|you have won|lucky draw|lottery|\bwinner\b|बधाई हो|आपका चयन|आप चुने गए|लॉटरी|इनाम जीत|लकी ड्रॉ'),
    ('invest', 3, r'(invest|investment|निवेश|गुंतवणूक|বিনিয়োগ)[^\n]{0,60}(return|profit|earn|income|double|guaranteed|रिटर्न|मुनाफा|कमाई|कमाएं|आय|दोगुना)'
                  r'|(earn|kamaye|कमाएं|कमाई)[^.\n]{0,30}(₹|rs\.?|रुपये)?\s?[\d,]+\s*(per day|daily|a day|रोज|प्रतिदिन|रोजाना)|trading platform|crypto|क्रिप्टो'),
    ('urgent', 1, r'today only|only today|last date (is )?today|last chance|within \d+ (hours|hrs|minutes|mins)|hurry|expires today|limited (seats|time|period|offer)'
                  r'|आज ही|सिर्फ आज|केवल आज|अंतिम मौका|जल्दी करें|जल्दी करो|24 घंटे'),
    ('forward', 2, r'(forward|share|send)( this| it)?( message)? (to|with|in) \d+|\d+ (groups|people|friends|contacts) (me|में|ko|को)? ?(share|forward|भेजें)'
                   r'|आगे भेजें|फॉरवर्ड करें|फॉरवर्ड करो|\d+ ग्रुप|\d+ लोगों को भेजें'),
    ('free_gift', 1, r'(free|फ्री|मुफ्त|मुफ़्त)\s*(laptop|mobile|smart ?phone|recharge|scooty|\bac\b|tablet|bike|tractor|gold|लैपटॉप|मोबाइल|स्मार्टफोन|रिचार्ज|स्कूटी|एसी|टैबलेट|सोना)'),
    ('everyone', 1, r'(all|every|sabhi|har|सभी|हर)\s+(women|woman|families|family|citizens|students|farmers|indians|महिला|महिलाओं|परिवार|नागरिक|छात्र|किसान|भारतीय)[^.\n]{0,40}(₹|\brs\b|rupees|रुपये|lakh|लाख)'),
]
_SIG = [(sid, sev, re.compile(rx, re.I)) for sid, sev, rx in SIGNALS]
_OTP_SAFE = re.compile(r"do not share|don'?t share|never share|किसी (को|के साथ) (भी )?(न|ना) (बताएं|शेयर|साझा)|साझा न करें|शेयर न करें|share na kare", re.I)
_PAY_OK = re.compile(r'fixed deposit|a month|per month|a year|per year|monthly|yearly|premium|up to|upto|प्रीमियम|हर महीने|प्रति माह|सालाना', re.I)
_MOBILE = re.compile(r'(?<![\d.,])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?![\d,])')

# ------------------------------------------------------------------ links
TLDS = set('''com in org net info xyz top site online live shop club app io co me ly gl gd cc biz us uk ru cn tk ml ga cf gq icu vip link
click buzz store tech website space fun pw ws page dev ai gov nic edu tv cloud email world today news life host win bid loan work
pro one asia mobi name support help digital center services agency sbs cfd lol rest bar art ink''' .split())
URL_RE = re.compile(r'(?i)\b((?:https?://|www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})(?::\d{2,5})?(?:/[^\s<>"\'\)\]]*)?)')
SHORTENERS = {'bit.ly', 'tinyurl.com', 'cutt.ly', 'rb.gy', 'is.gd', 't.ly', 'shorturl.at', 'tiny.cc', 'ow.ly', 'goo.gl', 's.id',
              'rebrand.ly', 'shorte.st', 'v.gd', 'bitly.com', 'tiny.one', 'urlz.fr', 'clck.ru', 'qr.ae', 'lnkd.in', 'surl.li',
              'shrtco.de', 'linktr.ee', 'bl.ink', 'short.gy', 'u.to'}
FREE_HOSTS = ('blogspot.com', 'wordpress.com', 'web.app', 'firebaseapp.com', 'netlify.app', 'vercel.app', 'github.io',
              'weebly.com', 'wixsite.com', '000webhostapp.com', 'sites.google.com', 'pages.dev', 'glitch.me', 'herokuapp.com',
              'ngrok.io', 'ngrok-free.app', 'repl.co', 'carrd.co', 'godaddysites.com', 'mystrikingly.com', 'jimdosite.com')
FORMS = ('forms.gle', 'docs.google.com', 'form.jotform.com', 'jotform.com', 'typeform.com', 'surveymonkey.com', 'forms.office.com')
CHAT = ('wa.me', 'chat.whatsapp.com', 'api.whatsapp.com', 't.me', 'telegram.me', 'telegram.org')
SOCIAL = ('youtube.com', 'youtu.be', 'facebook.com', 'fb.watch', 'instagram.com', 'x.com', 'twitter.com', 'sharechat.com', 'moj.app')
GOVLIKE = re.compile(r'gov|sarkar|yojana|yojna|scheme|pmkisan|kisan|modi|pradhan|ayushman|ujjwala|awas|mudra|kusum|nrega|aadhaar|aadhar|uidai|subsidy|'
                     r'ladli|laptop|recharge|bharat|india-|-india|pm-|pmyojana|sahayata|lakshmi|laxmi|scholarship|ration|epfo|pension|bima|loan')
EXTRA_OFFICIAL = {'india.gov.in', 'myscheme.gov.in', 'pib.gov.in', 'factcheck.pib.gov.in', 'cybercrime.gov.in', 'sancharsaathi.gov.in',
                  'uidai.gov.in', 'npci.org.in', 'rbi.org.in', 'sbi.co.in', 'indiapost.gov.in', 'epfindia.gov.in', 'csc.gov.in'}


def host_of(url):
    u = url if '://' in url else 'http://' + url
    h = re.sub(r'^[a-z]+://', '', u.lower()).split('/')[0].split(':')[0].strip('.')
    return h[4:] if h.startswith('www.') else h


# ------------------------------------------------------------------ the checker
STATE_ABBR = {'Uttar Pradesh': ['UP', 'यूपी'], 'Madhya Pradesh': ['MP', 'एमपी'], 'Andhra Pradesh': ['AP'], 'Tamil Nadu': ['TN'],
              'Himachal Pradesh': ['HP'], 'West Bengal': ['WB'], 'Jammu and Kashmir': ['J&K', 'JK', 'Jammu', 'Kashmir'],
              'Telangana': ['TS', 'TG'], 'Karnataka': ['KA'], 'Maharashtra': ['MH'], 'Rajasthan': ['RJ'], 'Odisha': ['Orissa']}


class Checker:
    def __init__(self, schemes, aliases=None, fakes=None, states=None):
        self.schemes = schemes
        self.state_rx = []
        for st, info in (states or {}).items():
            names = set((info.get('names') or {}).values()) | {st} | set(STATE_ABBR.get(st, []))
            alts = '|'.join(sorted((re.escape(norm(n)) for n in names if norm(n)), key=len, reverse=True))
            self.state_rx.append((st, re.compile(r'(?:^| )(?:' + alts + r')(?: |$)')))
        self.by_id = {s['id']: s for s in schemes}
        self.official = set(EXTRA_OFFICIAL)
        for s in schemes:
            for u in (s.get('link'), s.get('apply_url')):
                if u:
                    self.official.add(host_of(u))
        for s in schemes:
            for k, p in s.get('steps', []):
                if k in ('web', 'checklist') and p.get('url'):
                    self.official.add(host_of(p['url']))
        self.index = []  # (scheme_id, alias_norm, distinct_tokens)
        for s in schemes:
            names = {s['name']}
            names.add(PAREN.sub('', s['name']))
            for inner in PAREN.findall(s['name']):
                if len(inner) >= 3:
                    names.add(inner)
            for part in re.split(r'\s+[–—-]\s+|\s*/\s*', s['name']):
                if len(part) >= 4:
                    names.add(part)
            names.update((aliases or {}).get(s['id'], []))
            self._add(s['id'], names, self.index)
        self.fakes = []
        self.fake_index = []
        for f in fakes or []:
            self.add_fake(f)

    def _add(self, sid, names, index):
        seen = set()
        for n in names:
            nn = norm(n)
            if not nn or nn in seen:
                continue
            seen.add(nn)
            d = distinct(tokens(nn))
            if d:
                index.append((sid, nn, d))

    def add_fake(self, f):
        f = dict(f)
        f['_rx'] = [[re.compile(p, re.I) for p in grp] for grp in f.get('patterns', [])]
        f['_rx2'] = [[re.compile(p, re.I) for p in grp] for grp in f.get('patterns2', [])]
        f['_none'] = [re.compile(p, re.I) for p in f.get('none', [])]
        self.fakes = [x for x in self.fakes if x['id'] != f['id']] + [f]
        self.fake_index = [x for x in self.fake_index if x[0] != f['id']]
        self._add(f['id'], set([f['name']] + f.get('aliases', [])) if f.get('kind', 'fake') == 'fake' else set(f.get('aliases', [])),
                  self.fake_index)

    # -------------------------------------------------- scoring
    @staticmethod
    def _alias_score(a_norm, a_toks, t_norm, t_set, t_list, short):
        if f' {a_norm} ' in f' {t_norm} ':
            return 100.0, f' {t_norm} '.find(f' {a_norm} ')
        if not a_toks:
            return 0.0, None
        hit = 0.0
        for at in a_toks:
            if at in t_set:
                hit += 1
            elif len(at) >= 4:
                r = best_ratio(at, t_list, 84)
                if r:
                    hit += 0.9
        s = hit / len(a_toks) * 100
        if len(a_toks) == 1:
            s *= 0.88
        if short:
            s = max(s, ratio(a_norm, t_norm) * (1.0 if len(a_toks) > 1 else 0.95))
        return s, None

    def states_in(self, t_norm):
        return {st for st, rx in self.state_rx if rx.search(t_norm)}

    def _rank(self, index, t_norm, states=()):
        t_list = tokens(t_norm)[:600]
        t_set = set(t_list)
        cand = list({t for t in t_list if len(t) >= 3})
        short = len(t_list) <= 8
        best = {}
        for sid, a_norm, a_toks in index:
            sc, pos = self._alias_score(a_norm, a_toks, t_norm, t_set, cand, short)
            # ties: the scheme mentioned first wins, then the longer (more specific) name
            st_hit = 1 if states and self.by_id.get(sid, {}).get('state') in states else 0
            key = (round(sc), st_hit, -pos if pos is not None else -10 ** 6, len(a_toks) if sc >= 85 else 0)
            if key > best.get(sid, (0, 0, -10 ** 7, 0)):
                best[sid] = key
        ranked = sorted(best.items(), key=lambda kv: tuple(-x for x in kv[1]))
        return [(sid, k[0]) for sid, k in ranked]

    @staticmethod
    def _all(groups, low):
        return bool(groups) and all(any(rx.search(low) for rx in grp) for grp in groups)

    # -------------------------------------------------- links
    def classify_link(self, url):
        h = host_of(url)
        path = url.lower()
        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', h):
            return h, 'bad', 'ip_link'
        if h.endswith('.gov.in') or h.endswith('.nic.in') or h in ('gov.in', 'nic.in') or h.endswith('.gov') or h in self.official \
                or any(h.endswith('.' + o) for o in self.official if o.count('.') >= 2):
            return h, 'official', None
        if h in SHORTENERS:
            return h, 'bad', 'short_link'
        if h in FORMS or h.endswith(FORMS):
            return h, 'bad', 'form_link'
        if h.endswith(FREE_HOSTS):
            return h, 'bad', 'free_host'
        if h in CHAT or h.endswith(CHAT):
            return h, 'warn', 'chat_link'
        if '.gov.in.' in h or 'gov-in' in h or 'govin' in h.replace('.', '') and not h.endswith('gov.in') or 'nic-in' in h:
            return h, 'bad', 'fake_domain'
        for o in self.official:
            if o.count('.') >= 1 and len(o) >= 8 and h != o and ratio(h, o) >= 82:
                return h, 'bad', 'fake_domain'
        if h in SOCIAL or h.endswith(tuple('.' + s for s in SOCIAL)):
            return h, 'warn', 'social_link'
        if GOVLIKE.search(h):
            return h, 'bad', 'fake_domain'
        return h, 'warn', 'unofficial_link'

    def links(self, text):
        out, seen = [], set()
        for m in URL_RE.finditer(text):
            url, tld = m.group(1), m.group(2).lower()
            if tld not in TLDS and not url.lower().startswith(('http', 'www.')):
                continue
            h, status, sig = self.classify_link(url)
            if h in seen:
                continue
            seen.add(h)
            out.append({'url': url, 'host': h, 'status': status, 'signal': sig, 'span': m.span(1)})
        return out

    # -------------------------------------------------- main entry
    def check(self, text, labels=None, state=None):
        raw = unicodedata.normalize('NFC', (text or '')[:MAX_LEN])
        low = raw.lower()
        t_norm = norm(raw)
        h = text_hash(raw)
        res = {'hash': h, 'verdict': 'unknown', 'matched': None, 'also': [], 'suggest': [], 'fake': None, 'signals': [],
               'links': [], 'spans': []}
        if not t_norm and not raw.strip():
            res['verdict'] = 'empty'
            return res

        # signals
        sigs, spans = [], []
        for sid, sev, rx in _SIG:
            m = None
            for mm in rx.finditer(low):
                if sid == 'pay' and _PAY_OK.search(low[mm.start():mm.end() + 30]):
                    continue
                m = mm
                break
            if not m:
                continue
            if sid == 'otp' and _OTP_SAFE.search(low):
                continue
            ev = raw[m.start():m.end()].strip()
            sigs.append({'id': sid, 'sev': sev, 'ev': ev})
            spans.append(m.span())
        mob = _MOBILE.search(raw)
        if mob:
            sigs.append({'id': 'mobile', 'sev': 1, 'ev': mob.group(0)})
            spans.append(mob.span())
        links = self.links(raw)
        for ln in links:
            if ln['signal']:
                sev = 3 if ln['status'] == 'bad' else (1 if ln['signal'] == 'social_link' else 2)
                if not any(s['id'] == ln['signal'] for s in sigs):
                    sigs.append({'id': ln['signal'], 'sev': sev, 'ev': ln['host']})
                if ln['status'] != 'official':
                    spans.append(ln['span'])
        # "pay" becomes strong when combined with UPI / unofficial links / phone numbers
        ids = {s['id'] for s in sigs}
        for s in sigs:
            if s['id'] == 'pay' and ids & {'upi', 'mobile', 'unofficial_link', 'chat_link', 'fake_domain', 'short_link', 'form_link', 'free_host'}:
                s['sev'] = 3
        res['signals'] = sorted(sigs, key=lambda s: -s['sev'])
        res['links'] = [{k: v for k, v in ln.items() if k != 'span'} for ln in links]

        # real schemes
        states = self.states_in(t_norm)
        if state:
            states.add(state)
        ranked = self._rank(self.index, t_norm, states)
        real_top = ranked[0][1] if ranked else 0

        # known fakes / scam patterns
        fake_hit, fake_score, by_pattern = None, 0.0, False
        for f in self.fakes:
            if any(rx.search(low) for rx in f['_none']):
                continue
            if self._all(f['_rx'], low) or self._all(f['_rx2'], low):
                fake_hit, fake_score, by_pattern = f, 100.0, True
                break
        if fake_hit and by_pattern and fake_hit.get('kind', 'fake') == 'fake' and real_top >= 95:
            fake_hit = None  # the message names a real scheme exactly; judge it by its signals instead
        if not fake_hit and self.fake_index:
            ranked_f = self._rank(self.fake_index, t_norm)
            exact = ranked_f and any(fid == ranked_f[0][0] and f' {an} ' in f' {t_norm} ' for fid, an, _ in self.fake_index)
            if ranked_f and ranked_f[0][1] >= 88 and (exact or real_top < 95):
                f = next(x for x in self.fakes if x['id'] == ranked_f[0][0])
                if not any(rx.search(low) for rx in f['_none']):
                    fake_hit, fake_score = f, ranked_f[0][1]

        top_id, top = (ranked[0] if ranked else (None, 0))
        if top >= 85:
            res['matched'] = {'id': top_id, 'score': round(top)}
            ties = [sid for sid, sc in ranked[1:6] if sc >= max(85, top - 4)]
            res['also'] = ties[:4]
        elif top >= 62:
            res['suggest'] = [sid for sid, sc in ranked[:3] if sc >= 62]

        # labels confirmed by the admin for this exact message
        label = (labels or {}).get(h)

        high = sum(1 for s in sigs if s['sev'] >= 3)
        total = sum(s['sev'] for s in sigs)
        if label == 'scam':
            res['verdict'] = 'scam'
            res['confirmed'] = True
        elif label == 'safe':
            res['verdict'] = 'real' if res['matched'] else 'unknown'
            res['confirmed'] = True
        elif fake_hit and fake_hit.get('kind', 'fake') == 'fake' and fake_score >= top - 2:
            res['verdict'] = 'fake'
            res['fake'] = fake_hit['id']
            res['matched'] = None
            res['also'] = []
        elif fake_hit and fake_hit.get('kind') == 'scam':
            res['verdict'] = 'scam'
            res['fake'] = fake_hit['id']
            rid = fake_hit.get('real_id')
            if rid in self.by_id:
                res['matched'] = {'id': rid, 'score': 100}
        elif high >= 1 or total >= 5:
            res['verdict'] = 'scam'
        elif res['matched']:
            res['verdict'] = 'caution' if total >= 2 else 'real'
        elif links and all(l['status'] == 'official' for l in links) and total == 0:
            res['verdict'] = 'official'
        elif res['suggest']:
            res['verdict'] = 'suspicious' if total >= 2 else 'unsure'
        elif total >= 2:
            res['verdict'] = 'suspicious'
        else:
            res['verdict'] = 'unknown'
        res['score'] = total
        res['spans'] = merge_spans(spans)
        return res

    def fake(self, fid):
        return next((f for f in self.fakes if f['id'] == fid), None)


def merge_spans(spans):
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def segments(text, spans):
    """Split text into [(chunk, marked)] for highlighting evidence."""
    text = unicodedata.normalize('NFC', (text or '')[:MAX_LEN])
    out, pos = [], 0
    for a, b in spans:
        if a > pos:
            out.append((text[pos:a], False))
        out.append((text[a:b], True))
        pos = b
    if pos < len(text):
        out.append((text[pos:], False))
    return out


def load(base=BASE):
    schemes = json.loads((base / 'data' / 'schemes.json').read_text(encoding='utf-8'))
    aliases = json.loads((base / 'data' / 'aliases.json').read_text(encoding='utf-8'))
    aliases.pop('_note', None)
    fakes = json.loads((base / 'data' / 'fakes.json').read_text(encoding='utf-8'))
    states = json.loads((base / 'data' / 'states.json').read_text(encoding='utf-8'))
    return Checker(schemes, aliases, fakes, states)
