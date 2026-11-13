# Changelog

## 2.0.0 (2026-11-13)

A new implementation. Version 1.x is replaced completely; its configuration (`Default.xls`), reports and
database integration are not compatible.

- **Detectors.** 18 detectors with their own validation: Luhn and card scheme ranges, IBAN mod 97, ABA
  checksum, SSA rules, entropy and placeholder filtering. Card numbers with spaces or dashes are found,
  and digit runs inside longer numbers are not. Keywords are matched as whole-word keys with values, not
  as nearby substrings. See docs/DETECTORS.md.
- **Card checks.** One pass for card candidates, then an in-memory BIN-list lookup. Card numbers are
  confirmed against HMAC digests (`logcheck hash-pans`) instead of database queries that contain clear
  card numbers. The card database connection and its encrypted password are gone.
- **Reading.** Read-only streaming with encoding detection. Files are no longer split or renamed,
  undecodable bytes are replaced and counted, and binary, unreadable and changing files are reported.
- **Reports.** CSV, JSON and Excel in a separate report folder, with masked values and HMAC
  fingerprints by default, protected against formula injection.
- **Interface.** A command-line interface with exit codes for CI use, and a TOML settings file. The
  desktop GUI and the registry change made by the launcher are gone.
- **AI triage.** Optional, experimental and off by default. It sends masked formats only and never card
  data, and it no longer changes findings.
- **Evidence.** A pytest suite, a labelled evaluation corpus with a baseline comparison and a benchmark
  (docs/EVALUATION.md), and GitHub Actions on Windows and Linux.
