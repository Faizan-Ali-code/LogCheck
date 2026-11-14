# LogCheck

LogCheck scans application log files for sensitive data that should never have been logged:

- payment card numbers, track data, PINs and security codes;
- Social Security Numbers, dates of birth and bank account numbers;
- passwords, API keys, tokens, session IDs, connection strings and private keys.

It reads logs without changing them and validates every candidate before reporting it. Its reports show
masked values only.

```
C:\demo> python -m logcheck scan logs --out report --formats csv,json
[1/3] C:\demo\logs\auth.log: scanned, 1 finding(s)
[2/3] C:\demo\logs\batch.log: scanned, 2 finding(s)
[3/3] C:\demo\logs\payments.log: scanned, 5 finding(s)

LogCheck 2.0.0: 3 file(s), 15,490 lines, 1.7 MB in 1.0 s
Findings: 8 (7 high, 1 critical); 8 distinct value(s)
  card-number      4
  card-track-data  1
  password         1
  us-ssn           1
  api-token        1
Report: C:\demo\report\findings.csv
Report: C:\demo\report\findings.json
```

(These demo logs come from the evaluation corpus, so they also hold its traps. Three of the four card
numbers are random 16-digit order IDs that happen to pass the Luhn and card range checks. All four card
findings are *medium* confidence, because no card keyword is on their lines. A BIN list would separate
them.)

## How it decides

- **Validated, not just matched.**
  - Card numbers need a Luhn check, a card scheme's number range and a card length.
  - IBANs and US routing numbers need their checksums, and SSNs need the SSA numbering rules.
  - Tokens and keys need a minimum randomness, so placeholders and words are not reported.
- **Key and value, not "keyword somewhere nearby".** A password is a value after a `password` key, in
  `key=value`, JSON, XML or command-line form. So `setting 123456789` is not an SSN, `spin=1234` is
  not a PIN, and `password: invalid` is not a password.
- **Stand-alone numbers only.** A card number inside a 20-digit reference is not reported. Card numbers
  written with spaces or dashes (`4111 1111 1111 1111`) are.
- **Confidence on every finding.** High, medium or low, with the reason (for example `Visa, 16 digits,
  Luhn valid`, or `published test card number`).

The 18 detectors, their rules and their known gaps are described in [docs/DETECTORS.md](docs/DETECTORS.md).

## Measured, not claimed

On a generated corpus of 6,970 log lines (485 planted values, 485 lines built to cause false
positives), LogCheck finds every planted value with a precision of 0.996. A naive scanner of the usual
kind reaches 0.26–0.66 precision and 0.46–0.78 recall on the same lines.

The corpus is synthetic and written by the same person as the rules, so these are upper bounds.
[docs/EVALUATION.md](docs/EVALUATION.md) gives the method, the full results, throughput and these
limits. The numbers are re-checked by the tests.

## Safe to run on production logs

- **Read-only.** Files are opened for reading and streamed line by line. They are never renamed, split or
  rewritten, so a file of any size works and nothing is lost at a chunk boundary.
- **Nothing silently skipped.**
  - Encoding is detected (BOM, UTF-8, otherwise cp1252), and undecodable bytes are replaced and counted.
  - Binary and unreadable files are listed in the summary.
  - Files that grow while being scanned are flagged.
- **Reports outside the log folders.** They go to `./logcheck-report-<date-time>` or `--out`. That folder
  is never scanned itself.
- **Masked reports.**
  - Values are masked to the same length: cards keep the first 6 and last 4 digits, SSNs and accounts the
    last 4, and passwords and keys nothing.
  - Each value has an HMAC fingerprint, so repeated values can be counted without being shown.
  - `--include-values` adds the raw values when you need them for clean-up.
- **No formula injection.** Log text starting with `=`, `+`, `-` or `@` is written as text in CSV and
  Excel.
- **No network.** Nothing leaves the machine unless you switch on the experimental AI triage (below).

## Quick start

Needs Python 3.11 or newer. The scanner uses the standard library only; `openpyxl` adds Excel reports.

```bat
git clone https://github.com/Faizan-Ali-code/LogCheck.git
cd LogCheck
pip install -r requirements.txt
python -m logcheck scan D:\logs
```

On Windows, `run.bat scan D:\logs` does the same and creates a virtual environment on the first run.

Useful options:

| Option | Meaning |
|---|---|
| `--out DIR` | Report folder |
| `--formats csv,json,xlsx` | Which reports to write |
| `--detectors a,b` / `--disable a,b` | Run only, or skip, some detectors (`python -m logcheck detectors` lists them) |
| `--min-confidence medium` | Hide low-confidence findings |
| `--workers N` | Parallel processes (default: one per CPU; files are scanned in parallel) |
| `--include` / `--exclude` | File name patterns inside folders (default: `*.log`, `*.log.*`, `*.txt`, `*.out`, `*.err`, `*.json`, `*.gz`) |
| `--bin-list FILE` | Your issuer BIN prefixes, to confirm card numbers |
| `--pan-hashes FILE` | HMAC digests of your real card numbers (see below) |
| `--fail-on SEVERITY` | Exit code 1 when a finding of this severity or higher exists (default `low`; `never` to always exit 0). Exit code 2 means nothing could be scanned. |
| `--config FILE` | Settings file; [logcheck.example.toml](logcheck.example.toml) lists every setting with its default |

The exit codes make LogCheck usable as a CI or release gate, for example `--fail-on high`.

## Reports

`findings.csv`, `findings.json` and `findings.xlsx` (Summary, Findings and Files sheets). Each finding has:

- severity and confidence;
- detector;
- file, line and column;
- masked value and fingerprint;
- evidence: the surrounding text, with every detected value masked;
- notes: why it was reported.

The JSON report adds the per-file results (encoding, lines, skipped or changed files) and the run
summary.

## Confirming card numbers without clear card numbers

- **`--bin-list bins.txt`**: your BIN prefixes, 6 to 11 digits, one per line or first CSV column. Card
  numbers starting with one of them become high confidence, including private-label ranges outside the
  card schemes. The lookup costs the same for 10 or 10,000 BINs.
- **`--pan-hashes hashes.txt`**: proves "this is one of our cards" without the scanner ever querying a
  card database. On the issuer side:
  ```
  set LOGCHECK_PAN_HASH_KEY=<a long secret>
  python -m logcheck hash-pans cards.txt > hashes.txt
  ```
  The scanner, given the same key, compares HMAC-SHA256 digests.

## Experimental: AI triage

`--ai` (with `OPENAI_API_KEY` set) asks an OpenAI model for a second opinion on each finding.

- **What is sent:** the detector name, the value's *format* only (`Hunter2!` becomes `Aaaaaa9*`), and the
  evidence text with every value-like part replaced by its format.
- **What is never sent:** card data, in any form.
- **What it changes:** the verdict goes into its own column and never removes or changes a finding.
- **Limits:** calls are capped (`max_calls`, default 50), and AI triage stops after repeated errors.
- **Status:** its accuracy has not been measured (see [docs/EVALUATION.md](docs/EVALUATION.md)), so treat
  it as experimental. Check that your organisation allows log excerpts to be sent to an external
  service.

## Project structure

```
logcheck/
  detectors.py     the 18 detectors: candidate patterns and validation
  checks.py        Luhn, card scheme ranges, IBAN, ABA, SSN rules, entropy, placeholders
  engine.py        per-line scanning, overlap rules, masking, parallel file scanning
  reader.py        read-only streaming with encoding detection
  cards.py         BIN list and PAN hash list
  report.py        CSV / JSON / Excel reports and the console summary
  ai/              optional AI triage and the redaction it relies on
evaluation/        labelled corpus generator, baseline, evaluation and benchmark
docs/              DETECTORS.md, EVALUATION.md
tests/             pytest suite
```

## Development

```
pip install -r requirements-dev.txt
python -m pytest
python -m evaluation.evaluate
```

## Authorship

- **Author:** Faizan Ali. Version 2.0 (November 2026) replaces version 1.x completely.
- **Third-party:** none at runtime; the scanner uses the Python standard library. Optional: openpyxl (MIT) for
  Excel reports, and pytest for the tests.

## License

[MIT](LICENSE) © 2026 Faizan Ali.

> Only scan logs you are authorised to access. Treat reports as sensitive: even masked evidence shows
> where sensitive data is logged.
