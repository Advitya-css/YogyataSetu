# YogyataSetu

A website that matches people to Indian government welfare schemes (central and state) using their age, gender, work and state, explains each scheme in plain words in 12 languages, and shows exactly how to apply.

## Run it (VS Code)

1. Open this folder in VS Code.
2. Press **F5** (uses the "Run YogyataSetu website" configuration), or in the terminal:

   ```bash
   source .venv/bin/activate
   python server.py
   ```
3. Open http://127.0.0.1:5000

If Flask is missing: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`

## Folders

| Path | What it is |
|---|---|
| `server.py` | Flask app: pages, eligibility matching, JSON API |
| `data/schemes.json` | Every scheme: eligibility, text in each language, apply steps, documents, links |
| `data/states.json` | State names in all languages, state language, local service-centre name |
| `i18n/<code>.json` | Interface text (buttons, labels, apply-step sentences) for each language |
| `Templates/` | Page templates |
| `public/static/pixels.svg` | Pixel-art icon set used for needs and apply steps |
| `public/static/fonts/` | Self-hosted fonts for every script (each loads only when needed) |
| `data/reports.csv` | Created automatically when visitors report wrong information |
| `checker.py` | "Real or fake?" engine: matches a name, link or message against real schemes and known fakes, and finds scam signs |
| `store.py` | SQLite storage for the checker (checks, scam reports, admin decisions, extra fakes) |
| `data/fakes.json` | Fake schemes and scams found by PIB Fact Check and news fact-checkers, with sources |
| `data/aliases.json` | Short and local-language names people use for real schemes |
| `data/yogyatasetu.db` | Created automatically on first run (do not commit it) |
| `tests/` | `python tests/test_checker.py` and `python tests/test_server.py` |

## Scheme record (data/schemes.json)

- `level`: `central` (shown in every state) or `state` (with `state`)
- `cat`: needs it belongs to: welfare, health, education, farmers, jobs, women, housing, food, business, ids
- `occ`: limited to these kinds of work (empty = anyone)
- `gender`, `age` ([min, max]; 0 and 120 mean no limit)
- `needs`: extra conditions, each entry can be `a|b` for "a or b": bpl, sc, st, obc, minority, disability, widow, pregnant, rural, urban, woman
- `text`: `{lang: {amount, benefit, who}}` — English is required, other languages fall back to English
- `steps`: `[step_key, params]` — sentences come from `s_<step_key>` in `i18n/*.json`, so steps are translated automatically
- `docs`: document keys (`d_<key>` in i18n)
- `link`, `helpline`, `mode` (online / offline / both / auto), `verify` (shows "check before applying"), `note`

## "Real or fake?" checker

Page: `/check`. Paste a scheme name, a link, or a forwarded WhatsApp/SMS message. The answer is one of:
real, caution (real scheme but risky message), fake, scam, official link, not sure (did you mean...), suspicious, not in our list.
It shows why (fees, OTP, UPI, APK, look-alike websites, short links, urgency and more), highlights the risky words, and lists what to do (1930, cybercrime.gov.in, Sanchar Saathi, PIB Fact Check).

- Works offline. Nothing is sent to other websites.
- Privacy: a normal check stores only a fingerprint of the text, not the text itself, plus a salted fingerprint of the visitor. The text is saved only when someone presses "Report as scam".
- Limits: 30 checks per 5 minutes and 10 reports per hour for each visitor.

**Admin page: `/admin`.** It opens without a password only on the computer running the server. To use it from another device, set a key:

```bash
YS_ADMIN_KEY=choose-a-long-secret python server.py
```

There you can see numbers, confirm a reported message as a scam or mark it safe (everyone who checks the same text then gets that answer), and add a new fake scheme. It works right away and is saved in the database.

To add fakes permanently, edit `data/fakes.json` and restart. Each entry has `name`, `aliases` (fuzzy-matched, any language), optional `patterns` (groups of regular expressions that must all match), `claim` (per language) and `source`.

Other settings: `YS_DB` (database path), `YS_SECRET` (session key, made automatically otherwise), `YS_BEHIND_PROXY=1` (trust `X-Forwarded-For` when behind nginx etc.).

## API

- `GET /api/schemes` (or `?ids=pm-kisan,pm-jay`)
- `POST /api/check` with JSON `{"text": "...", "lang": "hi", "state": "Bihar"}` (lang and state optional): verdict, title and explanation in that language, matched scheme, fake details with source, signals, links, how many people checked and reported it
- `POST /api/report` with `{"text": "...", "note": "..."}`
- `GET /api/fakes?lang=hi`: every known fake and scam pattern
- `GET|POST /api/match` with `age`, `gender`, `occupation`, `state`, optional `area`, `caste`, `more=1`, `bpl`, `minority`, `disability`, `widow`, `pregnant`

Information compiled October 2026. Rules change often: keep `verify` flags and report feedback under review.

## Deploy on Vercel

Vercel finds `app` in `server.py` by itself, so `vercel.json` needs no rewrites (a rewrite sends every page to one path and Flask answers 404).
CSS, JS, fonts and icons live in `public/static/`, which Vercel serves from its CDN; locally Flask serves the same folder.

On Vercel the checker database is kept in `/tmp`, which is wiped whenever Vercel starts a new copy of the app, so checks counts, reports and admin decisions are temporary there.
Set `YS_ADMIN_KEY` in the Vercel project's Environment Variables to use `/admin` online.
