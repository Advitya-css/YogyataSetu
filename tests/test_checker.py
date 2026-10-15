"""Run:  python -m pytest tests/   (or: python tests/test_checker.py)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import checker  # noqa: E402

C = checker.load()

CASES = [
    # ---- real schemes: names, short forms, typos, Hindi and other scripts
    ('PM Kisan', 'real', 'pm-kisan'),
    ('pm kisaan samman nidhi', 'real', 'pm-kisan'),
    ('प्रधानमंत्री किसान सम्मान निधि', 'real', 'pm-kisan'),
    ('Ayushman card', 'real', 'pm-jay'),
    ('आयुष्मान भारत योजना', 'real', 'pm-jay'),
    ('ujjwala yojna', 'real', 'pmuy'),
    ('Ladli Behna Yojana', 'real', 'madhya-pradesh-ladli-behna-yojana'),
    ('लाडकी बहीण योजना', 'real', 'maharashtra-mukhyamantri-majhi-ladki-bahin-yojana'),
    ('kudumbasree', 'real', 'kerala-kudumbashree'),
    ('Orunodoi scheme Assam', 'real', 'assam-orunodoi'),
    ('মহিলাদের জন্য অন্নপূর্ণা ভাণ্ডার', 'real', 'west-bengal-annapurna-bhandar'),
    ('mudra loan', 'real', 'mudra'),
    ('MGNREGA job card', 'real', 'vb-g-ram-g'),
    ('Sukanya Samriddhi Yojana', 'real', 'ssy'),
    ('PM Surya Ghar Muft Bijli Yojana', 'real', 'pm-surya-ghar'),
    ('Is Kalaignar Magalir Urimai Thogai real?', 'real', 'tamil-nadu-magalir-urimai-thogai'),
    ('Apply for PM Kisan only on https://pmkisan.gov.in. Never share your OTP with anyone.', 'real', 'pm-kisan'),
    # ---- links on their own
    ('https://pmkisan.gov.in', 'official', None),
    ('www.myscheme.gov.in/schemes/kcc', 'real', 'kcc'),
    # ---- known fakes (PIB Fact Check)
    ('PM Free Laptop Yojana 2026', 'fake', 'national-student-laptop-scheme'),
    ('National Student Laptop Scheme 2026 apply now', 'fake', 'national-student-laptop-scheme'),
    ('प्रधानमंत्री फ्री लैपटॉप योजना', 'fake', 'national-student-laptop-scheme'),
    ('PM Modi AC Yojana free 5 star AC', 'fake', 'pm-modi-ac-yojana'),
    ('Pradhan Mantri Berojgari Bhatta Yojana 3500 per month', 'fake', 'pm-berozgari-bhatta'),
    ('Mahila Swarozgar Yojana: ₹1 lakh to all women', 'fake', 'mahila-swarozgar-1-lakh'),
    ('PM Kanya Vivah Yojana 40000', 'fake', 'pm-kanya-vivah'),
    ('Modi ji de rahe hain free recharge, click karo', 'fake', 'free-recharge-yojana'),
    ('प्रधानमंत्री धन लक्ष्मी योजना में महिलाओं को बिना ब्याज लोन', 'fake', 'pm-dhan-laxmi'),
    ('PM free scooty yojana for girls', 'fake', 'pm-free-scooty'),
    ('Invest ₹21,000 and earn ₹3.5 lakh every month - PM Modi new scheme', 'fake', 'investment-deepfake'),
    # ---- scams built on real schemes
    ('PM KUSUM approval letter: pay registration fee ₹8,000 to get solar pump', 'scam', 'kusum-registration-fee'),
    ('Your PM Mudra loan of ₹3 lakh is approved. Pay insurance charges ₹36,500 to release the loan.', 'scam', 'mudra-approval-letter'),
    ('PM Kisan new list. Download PM_Kisan.apk to check your name', 'scam', 'pm-kisan-apk'),
    ('Jan Dhan account holders will get ₹2 lakh cash credited, register now', 'scam', 'jan-dhan-2-lakh-cash'),
    ('Ayushman card banwane ke liye OTP bhejo is number par 9876543210', 'scam', None),
    ('Congratulations! You are selected for PM Awas Yojana. Pay ₹2,500 on UPI id pmawas@ybl to get your house.', 'scam', None),
    ('PM Kisan ki agli kist ke liye yahan register karein: http://pmkisan-gov.in/register', 'scam', None),
    ('Free ration card apply link: bit.ly/ration-free', 'scam', None),
    ('Sarkari yojana form: https://forms.gle/abc123 fill your Aadhaar and bank details', 'scam', None),
    ('Bank KYC update: install AnyDesk and share the code with our officer', 'scam', None),
    # ---- warnings but not certain
    ('PM Ujjwala Yojana free gas. Forward this to 10 groups today only!', 'caution', 'pmuy'),
    # ---- unknown things
    ('Super Sonic Rocket Yojana', None, None),  # unknown / unsure is fine
    ('hello', 'unknown', None),
]


def run():
    fails = []
    for text, want, wid in CASES:
        r = C.check(text)
        v = r['verdict']
        got_id = r['fake'] or (r['matched'] or {}).get('id')
        ok = True
        if want and v != want:
            ok = False
        if want is None and v not in ('unknown', 'unsure', 'suspicious'):
            ok = False
        if wid and got_id != wid:
            ok = False
        if not ok:
            fails.append((text, want, wid, v, got_id, [s['id'] for s in r['signals']], r.get('suggest')))
    return fails


def test_cases():
    fails = run()
    assert not fails, '\n'.join(map(str, fails))


if __name__ == '__main__':
    import time
    t = time.time()
    f = run()
    print(f'{len(CASES) - len(f)}/{len(CASES)} passed in {time.time() - t:.2f}s')
    for x in f:
        print('FAIL', x)
