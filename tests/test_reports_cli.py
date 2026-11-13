"""Report files, card lists, configuration and the command line."""

import csv
import io
import json
import os

import pytest

from logcheck import cli
from logcheck.cards import BinList, PanHashList, hash_pans_cli, pan_digest
from logcheck.config import Config, ConfigError, load_config
from logcheck.engine import run_scan
from logcheck.report import safe_cell, write_reports

PAN = "4539578763621486"


@pytest.fixture
def logs(tmp_path):
    folder = tmp_path / "logs"
    folder.mkdir()
    (folder / "app.log").write_text(f"=HYPERLINK(\"http://x\") card={PAN}\n2026 INFO password=Hunter2Secret!\n")
    (folder / "quiet.log").write_text("nothing here\n")
    return folder


# ------------------------------------------------------------------------------------------ reports

def test_formula_cells_are_neutralised():
    assert safe_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert safe_cell("+1") == "'+1" and safe_cell("@SUM(A1)") == "'@SUM(A1)" and safe_cell("ok") == "ok"


def test_csv_and_json_contain_no_raw_values(tmp_path, logs):
    result = run_scan([str(logs)], Config(workers=1))
    paths = write_reports(result, str(tmp_path / "out"), ["csv", "json"], include_values=False)
    for path in paths:
        text = open(path, encoding="utf-8-sig").read()
        assert PAN not in text and "Hunter2Secret!" not in text
    rows = list(csv.DictReader(open(paths[0], encoding="utf-8-sig")))
    assert {r["detector"] for r in rows} == {"card-number", "password"}
    assert rows[0]["evidence"].startswith("'=")  # evidence began with '=' and is stored as text
    doc = json.load(open(paths[1], encoding="utf-8"))
    assert doc["summary"]["total_findings"] == 2 and doc["summary"]["files_scanned"] == 2
    assert all("value" not in f and "ai_input" not in f for f in doc["findings"])


def test_include_values_writes_raw_values(tmp_path, logs):
    result = run_scan([str(logs)], Config(workers=1, include_values=True))
    [path] = write_reports(result, str(tmp_path / "out"), ["json"], include_values=True)
    values = {f["value"] for f in json.load(open(path, encoding="utf-8"))["findings"]}
    assert values == {PAN, "Hunter2Secret!"}


def test_excel_cells_are_strings_not_formulas(tmp_path, logs):
    openpyxl = pytest.importorskip("openpyxl")
    result = run_scan([str(logs)], Config(workers=1))
    [path] = write_reports(result, str(tmp_path / "out"), ["xlsx"], include_values=False)
    ws = openpyxl.load_workbook(path)["Findings"]
    evidence = [row[9] for row in ws.iter_rows(min_row=2)]
    assert any(c.value.startswith("=HYPERLINK") for c in evidence)
    assert all(c.data_type == "s" for c in evidence)


# ------------------------------------------------------------------------------------------ card lists

def test_bin_list(tmp_path):
    path = tmp_path / "bins.csv"
    path.write_text("bin,issuer\n453957,Example\n45395787,Example premium\n12345,too short\n")
    bins = BinList.load(str(path))
    assert len(bins) == 2 and bins.match(PAN) == "45395787" and bins.match("5555555555554444") is None


def test_pan_hash_list_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("LOGCHECK_PAN_HASH_KEY", "a-long-enough-test-key")
    out = io.StringIO()
    assert hash_pans_cli(["4539 5787 6362 1486\n", "not a card\n"], out) == 1
    path = tmp_path / "hashes.txt"
    path.write_text(out.getvalue())
    hashes = PanHashList.load(str(path))
    assert hashes.contains(PAN) and not hashes.contains("5555555555554444")
    assert PAN not in out.getvalue()
    assert pan_digest(PAN, b"a-long-enough-test-key") in out.getvalue()


def test_pan_hash_key_is_required(monkeypatch):
    monkeypatch.delenv("LOGCHECK_PAN_HASH_KEY", raising=False)
    with pytest.raises(ValueError, match="LOGCHECK_PAN_HASH_KEY"):
        hash_pans_cli([PAN], io.StringIO())


# ------------------------------------------------------------------------------------------ config

def test_config_file(tmp_path):
    path = tmp_path / "logcheck.toml"
    path.write_text('[scan]\nworkers = 2\nmin_confidence = "medium"\n[detectors]\ndisable = ["card-expiry"]\n'
                    '[report]\nformats = ["json"]\n')
    cfg = load_config(str(path))
    assert (cfg.workers, cfg.min_confidence, cfg.disable, cfg.formats) == (2, "medium", ["card-expiry"], ["json"])
    for bad in ('[scan]\nworkerz = 2\n', '[scan]\nworkers = "2"\n', '[nope]\nx = 1\n', '[report]\nformats = ["pdf"]\n',
                "not toml ["):
        path.write_text(bad)
        with pytest.raises(ConfigError):
            load_config(str(path))


def test_example_config_is_valid():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = load_config(os.path.join(root, "logcheck.example.toml"))
    assert cfg == Config()  # the example documents the defaults


# ------------------------------------------------------------------------------------------ command line

def test_cli_exit_codes(tmp_path, logs, capsys):
    out = tmp_path / "out"
    assert cli.main(["scan", str(logs), "-o", str(out), "-q", "--workers", "1", "--formats", "json"]) == 1
    assert os.listdir(out) == ["findings.json"]
    assert cli.main([str(logs), "-o", str(out), "-q", "--workers", "1", "--fail-on", "never"]) == 0
    assert cli.main([str(logs), "-o", str(out), "-q", "--workers", "1", "--fail-on", "critical"]) == 0
    assert cli.main([str(logs), "-o", str(out), "-q", "--workers", "1", "--disable", "card-number,password"]) == 0
    assert cli.main([str(tmp_path / "nothing-here")]) == 2
    assert cli.main([str(logs), "--detectors", "nope", "-q"]) == 2
    printed = capsys.readouterr().out
    assert "Findings: 2" in printed and PAN not in printed


def test_cli_detectors_and_hash_pans(tmp_path, capsys, monkeypatch):
    assert cli.main(["detectors"]) == 0
    assert "card-number" in capsys.readouterr().out
    monkeypatch.setenv("LOGCHECK_PAN_HASH_KEY", "a-long-enough-test-key")
    cards = tmp_path / "cards.txt"
    cards.write_text(PAN + "\n")
    assert cli.main(["hash-pans", str(cards)]) == 0
    assert pan_digest(PAN, b"a-long-enough-test-key") in capsys.readouterr().out
