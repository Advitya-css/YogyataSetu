"""Run:  python -m pytest tests/   (or: python tests/test_server.py)"""
import os
import re
import sys
import tempfile
from pathlib import Path

os.environ['YS_DB'] = tempfile.mktemp(suffix='.db')  # never touch the real database
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

server.app.testing = True
server.CHECK_LIMIT = server.RateLimit(10 ** 6, 1)
SCAM = 'Your PM Mudra loan of ₹3 lakh is approved. Pay insurance charges ₹36,500 to release the loan.'


def test_pages_in_every_language():
    c = server.app.test_client()
    for lang in server.LANG_CODES:
        for url in ('/', '/check', '/schemes', '/scheme/pm-kisan', '/about'):
            assert c.get(f'{url}?lang={lang}').status_code == 200, (url, lang)
        r = c.get('/check', query_string={'q': 'PM Free Laptop Yojana 2026', 'lang': lang})
        assert r.status_code == 200 and 'v-bad' in r.get_data(as_text=True), lang


def test_check_api_and_report():
    c = server.app.test_client()
    j = c.post('/api/check', json={'text': 'PM Kisan', 'lang': 'hi'}).get_json()
    assert j['verdict'] == 'real' and j['scheme']['id'] == 'pm-kisan'
    assert c.post('/api/check', json={'text': ' '}).status_code == 400
    r = c.post('/check/report?lang=en', data={'q': SCAM, 'note': 'sms'})
    assert r.status_code == 302
    j = c.post('/api/check', json={'text': SCAM}).get_json()
    assert j['verdict'] == 'scam' and j['fake']['id'] == 'mudra-approval-letter' and j['reports'] == 1
    assert len(c.get('/api/fakes').get_json()) >= 19


def test_admin_label_and_custom_fake():
    c = server.app.test_client()
    c.post('/api/report', json={'text': 'Totally normal message about a gift'})
    h = c.get('/admin').get_data(as_text=True)
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', h).group(1)
    hsh = re.search(r'name="hash" value="([0-9a-f]{32})"', h).group(1)
    assert c.post('/admin/action', data={'csrf': 'bad', 'hash': hsh, 'action': 'scam'}).status_code == 403
    assert c.post('/admin/action', data={'csrf': csrf, 'hash': hsh, 'action': 'scam'}).status_code == 302
    c.post('/admin/fake', data={'csrf': csrf, 'name': 'PM Free Bicycle Yojana', 'aliases': 'फ्री साइकिल योजना'})
    assert c.post('/api/check', json={'text': 'pm free bicycle yojna'}).get_json()['verdict'] == 'fake'
    c.post('/admin/fake', data={'csrf': csrf, 'delete': 'custom-pm-free-bicycle-yojana'})
    assert c.post('/api/check', json={'text': 'pm free bicycle yojna'}).get_json()['verdict'] != 'fake'


if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_'):
            fn()
            print('ok', name)
