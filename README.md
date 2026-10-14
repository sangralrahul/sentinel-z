# Sentinel-Z

**Find attacks in banking security logs without exposing customer data.**

Team Bitverse · IBM Z Datathon 2026 · Challenge 2: *AI Secured – Innovation Without Exposure*

[![CI](https://github.com/sangralrahul/sentinel-z/actions/workflows/ci.yml/badge.svg)](https://github.com/sangralrahul/sentinel-z/actions/workflows/ci.yml)
![Node 18+](https://img.shields.io/badge/node-18%2B-0f62fe)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0-0ca30c)
![Runs on s390x](https://img.shields.io/badge/IBM%20Z-s390x-161616)
![Licence: MIT](https://img.shields.io/badge/licence-MIT-6f6f6f)

| | |
|---|---|
| **Live demo** | https://sentinel-z-eight.vercel.app (press <kbd>D</kbd> to open the console) |
| **Open the console directly** | https://sentinel-z-eight.vercel.app/#console |
| **Source** | https://github.com/sangralrahul/sentinel-z |
| **Explainer** | [docs/EXPLAINER.md](docs/EXPLAINER.md) |

Sentinel-Z learns how each customer normally behaves: when they log in, from where and on which device, how much they transfer, and how much they download. It flags events that break the pattern and gives a plain-English reason for each one.

Before any analysis, every identifier is replaced with a keyed pseudonym, and personal data in free-text notes is masked. The engine is plain JavaScript with no dependencies. The same code runs in a browser tab, on a laptop, or on Linux on IBM Z / LinuxONE, which is where bank data already lives. Nothing is sent to a cloud service.

---

## Contents

- [Why this matters](#why-this-matters)
- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Results](#results)
- [Benchmarks on public datasets](#benchmarks-on-public-datasets)
- [How it works](#how-it-works)
- [The web app](#the-web-app)
- [Privacy design](#privacy-design)
- [Running on IBM Z / LinuxONE](#running-on-ibm-z--linuxone)
- [Use your own logs](#use-your-own-logs)
- [Project structure](#project-structure)
- [Testing and CI](#testing-and-ci)
- [Deploy](#deploy)
- [Limitations and next steps](#limitations-and-next-steps)
- [Licence](#licence)

## Why this matters

Banks hold some of the most sensitive data there is, and the logs needed to catch attacks are full of it: customer IDs, IP addresses, devices, account numbers, and support notes with phone and card numbers in them.

Sending those logs to a third-party AI service to look for anomalies creates the very exposure security teams exist to prevent. Sentinel-Z keeps the AI next to the data and removes identities before the model ever sees a row.

## What it does

| | |
|---|---|
| **Detects** | Account takeover, impossible travel, credential stuffing, brute force, mule / rapid transfers, data exfiltration and insider misuse |
| **Explains** | Every alert lists its reasons, e.g. *"Impossible travel: Bengaluru → São Paulo, 14,045 km in 193 min"* or *"Transfer of ₹1,68,018 is 34× the usual ₹4,962"* |
| **Groups** | Alerts for the same customer within 2 hours become one incident, rated critical, high or medium |
| **Protects** | HMAC-SHA256 pseudonyms; PII redaction (email, phone, Luhn-checked cards, Aadhaar, PAN, IP); differentially private counts for sharing |
| **Investigates** | Triage workflow (New → Investigating → Escalated → Resolved / False positive) with notes, a per-customer risk timeline, a day × hour heat map and copy-ready incident summaries |
| **Speaks SOC** | Signals mapped to MITRE ATT&CK: T1110 Brute Force, T1110.004 Credential Stuffing, T1078 Valid Accounts, T1213 Data from Information Repositories |
| **Red-teams itself** | An attack simulator injects one of seven attacks into the synthetic bank and shows live whether it is caught and why. The deliberately subtle "low-and-slow insider" is sometimes missed, and the app says so |
| **Key-holder lookup** | Type a real customer ID or IP: it is pseudonymised locally with your key and matched, never stored |
| **Proves it** | The page counts its own network requests live, and the site is served with `connect-src 'self'`, so the browser itself blocks any upload to another server |
| **Measures itself** | ROC-AUC, precision, recall, a confusion matrix, recall per attack type, an ablation of model vs. rules vs. hybrid, and a what-if threshold slider |

## Quick start

You need [Node.js 18 or newer](https://nodejs.org) and Git. There is nothing to `npm install`.

```bash
git clone https://github.com/sangralrahul/sentinel-z.git
cd sentinel-z
npm test          # 15 tests, a few seconds
npm run demo      # generate the synthetic bank, then analyse it in the terminal
npm start         # web app at http://localhost:5173
```

Open http://localhost:5173 and click **Open the live console** (or press <kbd>D</kbd>), or upload your own CSV/JSON file in the **Try it** section. Use `npm start -- 8080` if port 5173 is busy.

**Windows:** the same commands work in CMD and PowerShell. To set a fixed privacy key, use `set SENTINEL_KEY=...` in CMD or `$env:SENTINEL_KEY="..."` in PowerShell.

### Command line

```bash
node cli/sentinel-z.js generate --out data/sample-events.csv --seed 7
SENTINEL_KEY="a-long-secret-from-your-vault" \
  node cli/sentinel-z.js analyze data/sample-events.csv --train-days 14 --out report.json
node cli/sentinel-z.js simulate --type account_takeover    # red-team one attack
node cli/sentinel-z.js help
```

| Option (`analyze`) | Meaning |
|---|---|
| `--train-days N` / `--train-until ISO` | The normal-behaviour window (default: first 70% of the time span) |
| `--sensitivity P` | Alert threshold as a percentile of baseline risk (default 99.5) |
| `--tz-offset MIN` | Local time zone for "unusual hour" (default 330 = IST) |
| `--out report.json` | Save the pseudonymised report |
| `--explain` | Analyst summary from a **local** LLM (e.g. IBM Granite via Ollama). Localhost and private addresses only |
| `--llm-url URL`, `--llm-model NAME` | Local LLM endpoint (default `http://127.0.0.1:11434`) and model (default `granite3.3:2b`) |

`simulate` accepts `--type` (`impossible_travel`, `account_takeover`, `brute_force`, `credential_stuffing`, `mule_transfers`, `data_exfiltration`, `low_and_slow`), `--customer N` and `--day N`.

Without `SENTINEL_KEY`, a random key is used for that run only and never written anywhere.

## Results

These results come from the bundled synthetic bank: 80 customers, 21 days, 5,996 events, and 26 injected attacks in the last 7 days. The first 14 days are the baseline. Output of `npm run demo`:

| Metric | Value |
|---|---|
| ROC-AUC | **0.998** |
| Precision | 78.5% (113 of 144 alerts were attacks) |
| Recall | 94.2% (113 of 120 attack events) |
| False-alarm rate | 1.55% of normal events |
| Attacks caught (at least one alert) | **26 / 26** |
| Time | about 0.3 s for 6,000 events |

**Ablation.** Both parts are needed:

| Scorer | ROC-AUC | Precision | Recall | F1 |
|---|---|---|---|---|
| Isolation Forest only | 0.951 | 81.8% | 67.5% | 0.740 |
| Rules only | 0.996 | 87.9% | 85.0% | 0.864 |
| **Hybrid (used)** | **0.998** | 78.5% | **94.2%** | 0.856 |

Insider misuse has **no dedicated rule** on purpose: an off-hours session on the customer's own device with a few mid-size downloads and a larger-than-usual payment. The unsupervised model catches 15 of its 20 events; the rules alone catch 6. Rules are good at known attacks, and the model covers what nobody wrote a rule for.

The results hold across seeds: seeds 7, 11 and 23 give a hybrid AUC of 0.997 to 0.998, with all attacks caught every time.

> **Honest caveat:** the data is synthetic, generated by `core/generator.js` with realistic noise and legitimate surprises (real trips, new phones, one-off big payments) that create false-alarm pressure. These numbers show the method works as designed. They are not a claim about live bank traffic. See [Limitations](#limitations-and-next-steps).

## Benchmarks on public datasets

Synthetic data proves the method; public data proves it travels. Sentinel-Z ships adapters for two widely used fraud datasets, so anyone can reproduce an evaluation on data we did not generate:

| Dataset | What it is | Mapped to Sentinel-Z |
|---|---|---|
| **PaySim** (Lopez-Rojas et al., EMSS 2016) · [Kaggle](https://www.kaggle.com/datasets/ealaxi/paysim1) | 6.3M simulated mobile-money transactions, calibrated on a real African provider's logs, with fraud labels | `nameOrig` → customer, `nameDest` → beneficiary, `oldbalanceOrg` → balance, `step` → hour |
| **IEEE-CIS Fraud Detection** (Vesta, 2019) · [Kaggle](https://www.kaggle.com/competitions/ieee-fraud-detection) | 590k real, anonymised card-not-present e-commerce transactions with fraud labels | `card1 + addr1 + email domain` → customer proxy, `DeviceInfo` → device, `TransactionDT` → time |

The datasets are **not** in this repository: download them from Kaggle (free account) and respect their licences. Then run:

```bash
node cli/sentinel-z.js benchmark paysim path/to/PS_20174392719_1491204439457_log.csv
node cli/sentinel-z.js benchmark ieee   path/to/ieee-fraud-detection/      # folder with train_transaction.csv
```

Files are streamed, so the full datasets work on a laptop. Customers are sampled by a hash of their ID (5% for PaySim, 30% for IEEE-CIS by default, change with `--sample`), which keeps each sampled customer's whole history. The first half of the time span is the baseline (`--train-frac`); everything after is scored. Metrics (no raw data) are written to `benchmarks/<dataset>.json`.

For PaySim, an optional `balance` column enables a banking signal used everywhere: **account drained** (a transfer that empties the account). Your own logs can use it too.

Results from these runs are recorded in `benchmarks/` once produced. We do not publish numbers we have not measured.

## How it works

```
 raw logs ──► 1 Protect ──► 2 Learn normal ──► 3 Score ──► 4 Explain & group ──► 5 Share safely
              pseudonyms     per-customer       Isolation    plain-English         pseudonymised report
              PII masking    baseline           Forest +     reasons, incidents    + DP counts (ε = 1)
                                                rules
```

1. **Protect** (`core/privacy.js`). Users, IPs, devices and accounts become `usr_` / `ip_` / `dev_` / `acc_` + 12 hex characters, computed as HMAC-SHA256(key, kind + value). Notes are scanned for PII. Raw values are dropped.
2. **Learn normal** (`core/features.js`). For each customer, the baseline window gives their usual hour (circular mean), typical transfer and download sizes, known devices, cities and beneficiaries.
3. **Score.** Each event gets 10 behaviour features:

   | Feature | Meaning |
   |---|---|
   | `hour_dev` | Hours from the customer's usual time |
   | `amount_z`, `bytes_z` | How far a transfer or download is above the customer's normal |
   | `new_device`, `new_city`, `new_beneficiary` | Never seen for this customer in the baseline |
   | `travel_speed` | Speed implied by the previous city (haversine distance) |
   | `fails_10m` | Failed logins in the last 10 minutes |
   | `txn_10m` | Transfers in the last 10 minutes |
   | `ip_users_1h` | Distinct customers on the same IP in the last hour |

   An **Isolation Forest** (`core/iforest.js`, written from scratch: 150 trees, sample size 256, seeded) is trained on the baseline only, so no labels are needed. Its score is normalised between the baseline median and the 99.9th percentile. **Rules** turn known attack indicators into weighted evidence. The two are combined as:

   `risk = 1 − (1 − 0.85 × model) × (1 − rules)`

   The alert threshold is a percentile of the *baseline* risk (99.5 by default, never below 0.5), so it adapts to each dataset instead of being a magic number.
4. **Explain and group.** Every alert carries reasons. If the model alone raised it, the reason reads *"Unusual combination of behaviour for this user"*. Alerts for the same customer within 2 hours become one incident.
5. **Share safely.** The report keeps only pseudonyms. Counts for people outside the security team get Laplace noise with ε = 1.

## The web app

**Home page.** A live preview replays the synthetic bank: raw identities scramble into pseudonyms in real time, and every alert sends a ripple across the animated background. Below it are the results, a step-by-step walkthrough that shows a real alert's data at each pipeline stage, and an upload area for your own logs. Analysis runs in a Web Worker, so the page stays responsive.

**Console** (full screen, sidebar navigation):

| Section | What you get |
|---|---|
| **Overview** | KPIs, incidents per day by severity, why alerts fired, a day × hour heat map, ATT&CK techniques, triage progress, highest-risk incidents |
| **Incidents** | Filter by severity and triage status. Search by signal, ATT&CK ID, pseudonym or real ID (key-holder lookup). Expand an incident for triage, notes, the customer timeline and the per-event model/rules split |
| **Simulator** | Pick an attack, a synthetic customer and a day, then launch. Shows the verdict, peak risk against the threshold, reasons and every injected event |
| **Model quality** | What-if threshold slider (live precision, recall and false alarms, with the ROC point moving), ROC curve, confusion matrix, recall by attack type, ablation |
| **Privacy** | Live count of external requests, what was pseudonymised or masked, a playground for the privacy layer, the differentially private summary and JSON exports |
| **How it works** | Pipeline, features, IBM Z commands |

**Keyboard:** <kbd>D</kbd> open the console with the demo bank · <kbd>1</kbd>–<kbd>6</kbd> switch sections · <kbd>/</kbd> search incidents · <kbd>E</kbd> export report · <kbd>P</kbd> print report · <kbd>Esc</kbd> back to the home page · <kbd>?</kbd> shortcuts. **Print report** produces a clean, pseudonymised incident report (use "Save as PDF" to keep a copy).

The console follows your light/dark preference (toggle at the bottom of the sidebar). Animations are switched off automatically for anyone who prefers reduced motion.

## Privacy design

| Threat | Mitigation |
|---|---|
| Model or analyst sees customer identities | Keyed pseudonyms. Re-identification needs the key *and* the bank's own records |
| Dictionary attack on pseudonyms (hashing known emails) | HMAC with a secret key, not a plain hash. Keys must be at least 16 characters |
| PII hidden in free text | Regex redaction with a Luhn check for cards, so ordinary numbers like invoice IDs survive |
| Logs sent to a cloud AI | No cloud calls. The optional LLM is refused unless it is on localhost or a private network |
| A web page quietly uploads data | CSP `connect-src 'self'` (in `vercel.json` and the local server) plus a live request counter in the UI |
| Aggregate statistics leak individuals | Laplace mechanism (ε = 1) on everything shared outside the team |
| Key leakage | The key is never written to disk. It lives in memory, or in `SENTINEL_KEY` from your secret manager. The UI shows only an 8-character fingerprint |
| Notes and real IDs in the browser | Uploaded files are read locally; triage notes and lookups stay in memory and vanish when the tab closes |

The SHA-256/HMAC implementation is pure JS. The tests check it against Node's `crypto` module.

## Running on IBM Z / LinuxONE

Sentinel-Z has no native modules and no dependencies, so it runs unchanged on `s390x`:

```bash
# On a LinuxONE / IBM Z Linux guest (RHEL, SLES or Ubuntu for s390x) with Node 18+
git clone https://github.com/sangralrahul/sentinel-z.git && cd sentinel-z
npm test && npm run demo

# Or as a container (node:20-alpine is published for linux/s390x)
docker build -t sentinel-z .
docker run --rm -p 5173:5173 sentinel-z                 # web app
docker run --rm sentinel-z node cli/sentinel-z.js simulate --type account_takeover
```

The image runs the test suite during the build and runs as a non-root user. CI builds and tests it for `linux/s390x` under QEMU on every push.

**Optional local LLM summary with IBM Granite.** This runs on the same machine, so nothing leaves it:

```bash
ollama pull granite3.3:2b
node cli/sentinel-z.js analyze logs.csv --train-days 14 --explain
```

The LLM sees only pseudonymised incident summaries. If it isn't running, detection still works and the CLI says so.

## Use your own logs

CSV (with a header row) or JSON (an array, or `{ "events": [...] }`). Column names are case-sensitive.

| Column | Required | Example |
|---|---|---|
| `timestamp` (or `ts`, `time`) | yes | `2026-09-28T20:20:00Z` (ISO 8601; epoch milliseconds also work in JSON) |
| `user` (or `user_id`, `username`) | yes | `asha.verma@bank.example` |
| `event` (or `type`) | yes | `login`, `login_failed`, `transfer`, `download` |
| `ip`, `device`, `city` | recommended | `103.21.4.7`, `Pixel-7`, `Mumbai` |
| `amount` | for transfers | `25000` |
| `balance` | optional | account balance before the event; enables the "account drained" signal |
| `bytes` | for downloads | `5242880` |
| `account` | for transfers | beneficiary account number |
| `note` | optional | free text, will be redacted |
| `label`, `case` | optional | `normal` or an attack name, which enables the Model quality section |

You need at least 50 valid events, and the baseline window needs at least 30. In practice use a week or more of history before the period you want to check. Invalid rows are skipped and counted. The web app accepts files up to 50 MB; use the CLI for larger logs. Impossible-travel checks use the city table in `core/geo.js` (major Indian cities plus common foreign ones).

## Project structure

```
core/              detection engine, shared by browser and CLI (zero dependencies)
  privacy.js       pseudonymisation, PII redaction, Laplace noise
  sha256.js        SHA-256 + HMAC in pure JS
  features.js      per-customer baselines, 10 features, plain-English reasons
  iforest.js       Isolation Forest
  pipeline.js      analysis, incidents, evaluation, CSV parsing
  generator.js     synthetic bank with 7 attack types and legitimate surprises
  simulator.js     red-team attack injection
  geo.js, rng.js   city coordinates, seeded random numbers
cli/
  sentinel-z.js    command line: generate, analyze, simulate, benchmark
  datasets.js      streaming adapters for PaySim and IEEE-CIS
  llm.js           optional local LLM client (localhost / private network only)
  serve.js         zero-dependency local web server with the same security headers
web/
  app.js           home page and console logic
  job.js, worker.js  analysis in a Web Worker (with main-thread fallback)
  charts.js        SVG charts with tooltips
  bg.js            animated background
  site.css, app-shell.css, console.css, styles.css
  fonts/           IBM Plex, self-hosted (SIL OFL)
scripts/build.js   copies the static site into dist/ for hosting
benchmarks/        metrics from public-dataset runs (no raw data)
tests/             node:test suite
data/              sample-events.csv (synthetic)
docs/              EXPLAINER.md
index.html         web app entry
vercel.json        static build, CSP and security headers
Dockerfile         multi-arch image, including s390x
.github/workflows/ci.yml   tests on Node 18, 20, 22 and an s390x container build
```

## Testing and CI

`npm test` runs 15 tests with Node's built-in runner. They check:

- SHA-256 and HMAC against Node's `crypto` module.
- That pseudonyms are stable, depend on the key and contain no raw values.
- PII redaction, the Luhn check and Laplace noise.
- The Isolation Forest, distances, ROC-AUC, CSV parsing and rejection of invalid rows.
- End-to-end detection on two seeds: AUC above 0.98, recall above 0.85, precision above 0.7, every attack caught, the hybrid recalling at least as much as either part, a reason on every alert, and no raw email or internal IP anywhere in the output.
- Reproducibility.
- That every simulated attack type except the deliberately subtle one is detected.
- That the CLI works end to end without a key set.
- That the PaySim and IEEE-CIS adapters parse the real column layouts (on tiny fixtures; these are format checks, not results).

GitHub Actions runs the suite and `npm run demo` on Node 18, 20 and 22, then builds and tests the Docker image for `linux/s390x`.

## Deploy

**Vercel:** import the repo at [vercel.com/new](https://vercel.com/new) and deploy. `vercel.json` sets everything: `node scripts/build.js` copies the static site into `dist/` (no bundler, no dependencies), with the CSP and security headers. In the project settings, leave **Framework Preset** on **Other** with no overrides. Or use the CLI:

```bash
npx vercel --prod
```

**Any static host** also works (GitHub Pages, Netlify, an internal web server): run `node scripts/build.js` and serve `dist/`.

## Limitations and next steps

- The evaluation uses synthetic data. Next step: validate on a public or partner dataset (e.g. LANL authentication logs, or anonymised bank logs inside the bank's own environment).
- The baseline is static per run. Next: rolling baselines and analyst feedback, where a dismissed alert becomes a known-good pattern.
- City-level geolocation only. Next: ASN and VPN signals.
- Pseudonyms protect identity, not behaviour. A very distinctive pattern can still hint at who someone is, which is why the shareable output uses differential privacy and the detailed report stays with the security team.
- Scale: about 20,000 events per second in one thread. Larger volumes would move to streaming on z/OS or LinuxONE, with the IBM Z Integrated Accelerator for AI for model inference.

## Licence

MIT © 2026 Team Bitverse. IBM Plex fonts © IBM Corp., SIL Open Font License 1.1 (`web/fonts/OFL.txt`). All demo data is synthetic, and any resemblance of generated names to real people is coincidental.
