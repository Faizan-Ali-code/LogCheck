# Detectors

LogCheck runs 18 detectors. Each one finds *candidates* with a pattern and then *validates* them;
only validated candidates become findings. This page explains what each detector accepts, why, and
what it misses. `logcheck detectors` lists them.

## Shared rules

| Rule | Why |
|---|---|
| A digit candidate must stand alone: no digit, letter or underscore directly before or after it. | A card number or SSN inside a longer ID, timestamp or hash is not a card number or SSN. |
| Keyword detectors look for a **key followed by `=`, `:`, `=>` or `->` and a value** (`password=…`, `"pin": "…"`), not for a keyword anywhere near a number. | Proximity rules ("a 9-digit number within 80 characters of `tin`") fire on `setting`, `routing` and `testing`. A key/value pair is how logs actually record a field. |
| A key must start at a word boundary. It may carry a prefix that ends in `.`, `_` or `-` (`db.password`, `card_pin`). Long, distinctive keys such as `password` and `secret` may also have a camelCase prefix (`userPassword`). | `spin=1234` is not a PIN, and `bypass=…` and `compass=…` are not passwords. |
| Placeholders are not values: `****`, `xxxx`, `${DB_PASSWORD}`, `$DB_PASS`, `%s`, `{0}`, `{{ … }}`, `<…>`, `[REDACTED]`, `null`, `true`/`false`. | Masked or templated values in logs are the *correct* behaviour and must not be reported. |
| When findings overlap on a line, the more specific detector wins, in the order of the table below. | Track data contains a card number, and a bearer header contains a JWT. One finding per value. |
| Every finding has a confidence: **high**, **medium** or **low**. `--min-confidence` filters by it. | Lets a team start with the findings that are almost certainly real. |

## Detectors

Severity: **critical** for data that may never be stored at all (PCI DSS sensitive authentication
data) or that gives complete control (private keys); **high** for data that identifies a person or
grants access; **medium** where the risk depends on context; **low** for data that only matters in
combination with other data.

| # | Id | Finds | Validation | Severity |
|---|---|---|---|---|
| 1 | `private-key` | `-----BEGIN … PRIVATE KEY-----` headers, PuTTY key files | Header text; `ENCRYPTED` keys get medium confidence | critical |
| 2 | `card-track-data` | Magnetic-stripe track 1/2 and EMV track 2 equivalent (`PAN=YYMM…`, `%B…^NAME^…`, tag 57 with `D` separator) | Luhn-valid PAN, month 01–12 | critical |
| 3 | `card-number` | 13–19 digit card numbers, contiguous or in card layouts with one separator: `4111 1111 1111 1111`, `4111-1111-1111-1111`, `3782 822463 10005` | Luhn check, issuer range and length of a card scheme (Visa, Mastercard incl. 2-series, Amex, Discover, Diners, JCB, UnionPay, Maestro, Mir) **or** a prefix from your BIN list | high |
| 4 | `card-pin` | `pin=1234`, `atm_pin`, `new_pin`, clear `pin_block=<16 hex>` | Key/value; 4–12 digits | critical |
| 5 | `card-security-code` | `cvv`, `cvc`, `cvn`, `csc`, `cav2`, `card_verification_value`, `security_code` with 3–4 digits | Key/value | critical |
| 6 | `known-key-format` | AWS access key IDs and secret keys, GitHub, GitLab, Slack (tokens and webhooks), Google API, Stripe, OpenAI, Anthropic, npm and SendGrid keys, Azure storage account keys | Each provider's published prefix and length; Stripe test keys get low confidence | high |
| 7 | `connection-string` | `scheme://user:password@host` (database URLs, HTTP basic auth in URLs) | Password part is not a placeholder | high |
| 8 | `authorization-header` | `Authorization:` with Basic, Bearer, Token, ApiKey, SharedKey, AWS4, Digest, NTLM, Negotiate; a bare `Bearer <token>` | Basic credentials are decoded and must contain `user:password` for high confidence | high |
| 9 | `jwt` | JSON Web Tokens (`eyJ….eyJ….…`) | The header decodes to JSON with an `alg` claim; expired tokens (`exp` in the past) get medium confidence | high |
| 10 | `crypto-key` | Symmetric and HSM keys by key name: `aes_key`, `encryption_key`, `hmac_key`, `signing_key`, `master_key`, `zmk`, `zpk`, `tmk`, `tpk`, `kek`, `dek`, `bdk`, `ipek`, `lmk`, `key_component`… | Hex of 32–128 digits (optionally with a U/T/X/Y key-scheme letter) or base64 of 24+ characters; entropy at least 2.8 (hex) or 3.5 (base64) bits/character, so `0000…` is ignored | high |
| 11 | `api-token` | `api_key`, `apikey`, `api_secret`, `access_token`, `refresh_token`, `client_secret`, `x-api-key`, `subscription_key`, `webhook_secret`… | 16+ token characters, entropy at least 3.0 bits/character, and a digit unless 32+ characters long (so `YOUR_API_KEY_HERE` is ignored) | high |
| 12 | `password` | `password`, `passwd`, `passphrase`, `pwd`, `pass`, `pw`, `secret` as key/value, JSON, XML elements and `--password` command-line options | Not a placeholder, at least 4 characters, not message text (`password: invalid`, `Password: required`), not a path (`PWD=/opt/app`), not another `key=value`. Password hashes (bcrypt, argon2, hex digests) get low confidence | high |
| 13 | `session-id` | `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`, `session_id`, `sid`, `connect.sid`, `laravel_session`… | 16+ characters, entropy at least 3.0; Windows SIDs (`S-1-5-…`) excluded | high |
| 14 | `us-ssn` | `ssn=…`, `social_security_number`, `tin`, `itin`, `tax_id` keys; dashed `219-09-9998` anywhere; spaced `219 09 9998` only with an SSN keyword on the line | SSA rules: area 001–899 except 666, group 01–99, serial 0001–9999. Known example and invalidated numbers get low confidence | high |
| 15 | `iban` | IBANs, compact or in groups of four | Country code, the country's IBAN length, ISO 7064 mod-97 check | high |
| 16 | `bank-account` | `account_number`, `acct`, `dda` with 6–17 digits; `routing_number`, `aba`, `rtn` with 9 digits | Routing numbers: Federal Reserve prefix and the ABA 3-7-1 checksum | medium |
| 17 | `date-of-birth` | `dob`, `date_of_birth`, `birth_date`, `birthday` with a date | A real calendar date between 1900 and today | medium |
| 18 | `card-expiry` | `exp`, `expiry`, `expiration_date`, `valid_thru` with MM/YY, MMYY or MM/YYYY | Month 01–12; JWT `exp` epochs and cookie `expires=` dates do not match | low |

## Card numbers in detail

1. **One pass.** A single expression finds runs of digits joined by single spaces or dashes. Candidates
   are cut from each run: a contiguous group of 13–19 digits, or consecutive groups in a known card
   layout (4-4-4-4, 4-4-4-4-1…3, 4-6-5, 4-6-4, 4-4-4-1…3) with one consistent separator. A layout that
   continues with another 4-digit group (`… 1486 9999`) belongs to a longer number and is rejected.
2. **Validation.** Luhn check, then the issuer range of a card scheme. A Luhn-valid number outside every
   scheme range is reported only when your BIN list contains its prefix.
3. **Issuer data, without clear card numbers.** A BIN list is a set of prefixes: each candidate costs one
   lookup per distinct prefix length, however long the list (see the benchmark in
   [EVALUATION.md](EVALUATION.md)). To confirm "this is one of our cards", the issuer creates
   HMAC-SHA256 digests of its card numbers with `logcheck hash-pans`; the scanner compares digests. No
   database query with clear card numbers is ever built.
4. **Confidence.** High with a card keyword on the line (`card`, `pan`, `cc`, `credit`, `visa`…), a BIN
   list match or a PAN hash match; medium otherwise; low for published test numbers (`4111 1111 1111
   1111` and others) and numbers whose middle digits are all the same.

## What the detectors miss

- Values split across lines, values in binary or compressed formats other than gzip, and values that
  are themselves encoded (base64 of a JSON body containing a card number).
- Keys without a separator before a short key name (`dbpwd=…`, `atmpin=…`).
- Card numbers written with dots or other separators, with mixed separators, or directly after letters
  (`PAN4111…`).
- National identifiers other than US SSNs, phone numbers, e-mail and postal addresses, and names. These
  are personal data too, but each needs its own rules to avoid flooding reports with false positives.
- Secrets with formats that are not listed and keys that are not in the key lists. The key lists are in
  `logcheck/detectors.py`.
