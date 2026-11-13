# Evaluation

How well the detectors work was measured on a generated, labelled log corpus. This page gives the
method, the results and their limits. Reproduce them with:

```
python -m evaluation.evaluate      # precision and recall
python -m evaluation.benchmark     # throughput and the BIN-list cost
```

The same numbers are checked by `tests/test_evaluation.py`, so a change that makes them worse fails the
tests.

## Method

`evaluation/corpus.py` generates (seed 2026) 6,970 log lines of three kinds:

- **6,000 ordinary lines**: access logs, SQL, scheduler and cache messages, stack traces, build
  versions with commit hashes, checksums, request IDs, metrics and phone numbers.
- **485 positive lines**, each carrying one sensitive value with a label naming the detector that should
  find it. Card numbers are Luhn-valid and in a scheme range, IBANs and routing numbers have valid
  checksums, SSNs follow the SSA rules, and secrets are random. Values appear in the forms logs use:
  `key=value`, JSON, XML, URLs, headers, command lines, and card numbers with and without spaces or
  dashes.
- **485 trap lines**, built to cause false positives. Examples:
  - card numbers inside 18–20 digit references;
  - masked card numbers;
  - 13-digit epoch milliseconds;
  - random 16-digit order IDs;
  - 9-digit numbers after `setting`, `routing` and `testing`;
  - invalid SSN areas and phone numbers;
  - password placeholders and messages such as `Invalid password for user bob`;
  - `PWD=/opt/app`, `bypass=…`, `spin=…` and `pin_attempts=…`;
  - API-key placeholders, Windows SIDs, JWT `exp` claims and cookie expiry dates;
  - IBANs with a wrong checksum, URLs without credentials, and cache keys made of hex digests.

A finding is a **true positive** when its line is labelled for the same detector. Any other finding is a
**false positive**, and a label without a finding is a **false negative**.

The same corpus is also scanned by `evaluation/baseline.py`, a deliberately simple scanner that
represents the usual first attempt:

- contiguous 13–19 digits with a Luhn check;
- a 9-digit or dashed number within 80 characters of the *substrings* `ssn`, `social`, `tin` and `tax`;
- `password = anything`;
- `token = anything`.

It shows what the validation rules change.

## Results

| Detector | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| private-key | 5 | 0 | 0 | 1.000 | 1.000 |
| card-track-data | 20 | 0 | 0 | 1.000 | 1.000 |
| card-number | 125 | 2 | 0 | 0.984 | 1.000 |
| card-pin | 15 | 0 | 0 | 1.000 | 1.000 |
| card-security-code | 20 | 0 | 0 | 1.000 | 1.000 |
| known-key-format | 20 | 0 | 0 | 1.000 | 1.000 |
| connection-string | 15 | 0 | 0 | 1.000 | 1.000 |
| authorization-header | 20 | 0 | 0 | 1.000 | 1.000 |
| jwt | 10 | 0 | 0 | 1.000 | 1.000 |
| crypto-key | 20 | 0 | 0 | 1.000 | 1.000 |
| api-token | 25 | 0 | 0 | 1.000 | 1.000 |
| password | 65 | 0 | 0 | 1.000 | 1.000 |
| session-id | 15 | 0 | 0 | 1.000 | 1.000 |
| us-ssn | 45 | 0 | 0 | 1.000 | 1.000 |
| iban | 20 | 0 | 0 | 1.000 | 1.000 |
| bank-account | 20 | 0 | 0 | 1.000 | 1.000 |
| date-of-birth | 15 | 0 | 0 | 1.000 | 1.000 |
| card-expiry | 10 | 0 | 0 | 1.000 | 1.000 |
| **all** | **485** | **2** | **0** | **0.996** | **1.000** |

The two false positives are random 16-digit order IDs that happen to pass the Luhn check and fall in a
card scheme's range. About one random 16-digit number in ten passes Luhn. No rule can tell such a number
from a card number without context, so these come out as *medium* confidence, while numbers with a card
keyword on the line come out as *high*. A BIN list removes them.

### Compared with the naive baseline

| Detector | Baseline precision | Baseline recall | LogCheck precision | LogCheck recall |
|---|---:|---:|---:|---:|
| card-number | 0.664 | 0.760 | 0.984 | 1.000 |
| us-ssn | 0.350 | 0.778 | 1.000 | 1.000 |
| password | 0.259 | 0.462 | 1.000 | 1.000 |
| api-token | 0.536 | 0.600 | 1.000 | 1.000 |

Where the baseline goes wrong:

- **Card numbers.** It misses every card number written with spaces or dashes (recall 0.76). It reports
  Luhn-valid substrings of longer references and epoch timestamps.
- **SSNs.** 40 of its false positives are 9-digit numbers after `setting`, `routing` and `testing`, which
  contain `tin`. It also accepts invalid SSN areas such as 000, 666 and 9xx.
- **Passwords and tokens.** It reports placeholders (`********`, `${DB_PASSWORD}`), messages, `PWD=/opt/app`
  and `bypass=`. It misses JSON, XML and command-line forms.

## Performance

Measured on an Intel Core i5-10310U (1.7 GHz, 4 cores), Python 3.12, Windows 11, one process:

- **Throughput:** 20 MB (189,943 lines, 13,279 findings) in 12.5–13.4 s across runs, about **1.5 MB/s per
  process**. The
  corpus is dense: about 7% of its lines hold sensitive data. Files are scanned in parallel processes, one
  per CPU by default, so a folder of logs scales with the number of cores. A single file is scanned by
  one process.
- **BIN list cost.** Matching card numbers against an issuer's BIN list can be done with one regular-expression
  pass per BIN and card length, or with one pass for stand-alone digit runs followed by a set lookup.
  The table compares them on 1 MB of the same log:

| BINs | Regex passes needed | One pass per BIN and length | One pass + set lookup |
|---:|---:|---:|---:|
| 10 | 70 | 1.67 s | 0.27 s |
| 100 | 700 | 16.82 s | 0.27 s |
| 997 | 6,979 | 167.59 s | 0.27 s |

The first approach grows linearly with the BIN list. LogCheck's approach does not depend on its size.

## Limits of this evaluation

- **The corpus is synthetic, and the same person wrote it and the rules.** The traps are the false
  positives I knew to look for, so the precision and recall above are an upper bound. On real logs,
  formats the corpus does not contain will lower recall (see "What the detectors miss" in
  [DETECTORS.md](DETECTORS.md)), and messages it does not imitate will lower precision. A fair next step
  is a corpus written by someone else, or labelled samples of real, sanitised logs.
- **Each positive line holds one value**, and lines are independent. Multi-line records and lines with
  several values are only covered by the unit tests.
- **Confidence is not calibrated.** "High" means "passed every check and has supporting context", not a
  measured probability.
- **The optional AI triage has not been evaluated** and is therefore marked experimental. To measure it,
  scan the corpus with AI triage on and compare the `ai_verdict` column with the labels (a key and
  budget are needed). Until then it is a second opinion shown next to a finding; it never removes a
  finding or changes its confidence.
