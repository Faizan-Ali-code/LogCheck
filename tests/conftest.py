import pytest

from logcheck.engine import FileScanner, WorkerSettings


def make_settings(**overrides) -> WorkerSettings:
    values = dict(enable=(), disable=(), bin_list="", pan_hashes="", pan_key=None, fingerprint_key=b"test-key",
                  context_chars=60, min_confidence="low", include_values=True, ai_input=False)
    values.update(overrides)
    return WorkerSettings(**values)


@pytest.fixture
def scan():
    """scan(line) -> [(detector, raw value, confidence)] using every detector and the engine's overlap rules."""
    scanner = FileScanner(make_settings())

    def run(line: str):
        return [(f.detector, f.value, f.confidence) for f in scanner.scan_line("test.log", 1, line)]
    return run


@pytest.fixture
def detectors_found(scan):
    def run(line: str) -> set[str]:
        return {d for d, _v, _c in scan(line)}
    return run
