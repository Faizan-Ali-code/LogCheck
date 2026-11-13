"""Behaviour of each detector on positive and negative log lines.

Values that look like real credentials are assembled at run time, so the repository itself contains no
secret-like literals for secret scanners to flag.
"""

import base64
import json

import pytest

from logcheck.cards import BinList, PanHashList, pan_digest
from logcheck.detectors import CardNumber, all_detectors, card_candidates, select

PAN = "4539578763621486"  # Luhn-valid Visa number, not a published test card


# ------------------------------------------------------------------------------------------ card numbers

@pytest.mark.parametrize("text", [f"card={PAN}", "card=4539 5787 6362 1486", "card=4539-5787-6362-1486",
                                  "paid with 3714 496353 98431 ok", f'{{"pan":"{PAN}"}}', f"GET /pay?cc={PAN}&x=1",
                                  f"2026-11-13 10:15:32 {PAN} approved", "at 32 4539 5787 6362 1486 done"])
def test_card_numbers_in_common_layouts(scan, text):  # review item L3: separators are accepted
    found = [(d, v) for d, v, _c in scan(text) if d == "card-number"]
    assert len(found) == 1
    assert found[0][1].replace(" ", "").replace("-", "") in (PAN, "371449635398431")


@pytest.mark.parametrize("text", [f"txn_ref={PAN}1234", f"ref=987{PAN} ok", f"id {PAN}.75", f"x{PAN}",
                                  "4539 5787-6362 1486", "2026 4539 5787 6362 1486 9999"])
def test_no_card_inside_longer_numbers_or_mixed_layouts(detectors_found, text):  # review item L4
    assert "card-number" not in detectors_found(text)


def test_card_needs_luhn_and_a_scheme_range(detectors_found):
    assert "card-number" not in detectors_found("card=4539578763621487")  # Luhn fails
    assert "card-number" not in detectors_found("card=9539578763621485")  # Luhn ok, no scheme starts with 9


def test_card_confidence():
    det = CardNumber()
    assert [h.confidence for h in det.find(f"card={PAN}")] == ["high"]  # card keyword on the line
    assert [h.confidence for h in det.find(f"value {PAN}")] == ["medium"]
    assert [h.confidence for h in det.find("value 4111111111111111")] == ["low"]  # published test number


def test_bin_list_and_pan_hashes_raise_confidence():
    private_label = "9539578763621485"  # outside every scheme range: only reported with the issuer's BIN list
    det = CardNumber(bin_list=BinList(["953957"]))
    hits = list(det.find(f"value {private_label}"))
    assert hits and hits[0].confidence == "high" and "BIN 953957" in hits[0].notes[1]
    key = b"k" * 32
    det = CardNumber(pan_hashes=PanHashList([pan_digest(PAN, key)], key))
    hit = next(det.find(f"value {PAN}"))
    assert hit.confidence == "high" and "PAN hash list" in " ".join(hit.notes)


def test_card_candidates_is_one_pass_with_positions():
    line = "a 4539 5787 6362 1486 b 4539578763621486 c"
    spans = [(s, e) for s, e, _d in card_candidates(line)]
    assert [line[s:e] for s, e in spans] == ["4539 5787 6362 1486", PAN]


def test_track_data_reported_once(scan):
    for text in (f"swipe ;{PAN}=25121011234567890?", f"%B{PAN}^DOE/JOHN^2512101000000000000?",
                 f"tag57={PAN}D25122011758928889"):
        assert [d for d, _v, _c in scan(text)] == ["card-track-data"]  # the PAN inside is not reported again


def test_track_data_needs_valid_pan_and_month(detectors_found):
    assert "card-track-data" not in detectors_found(f";{PAN[:-1]}7=25121011234567890?")
    assert "card-track-data" not in detectors_found(f";{PAN}=25131011234567890?")


@pytest.mark.parametrize("text,detector", [("cvv=123", "card-security-code"), ('{"cvc": "4567"}', "card-security-code"),
                                           ("card_verification_value: 321", "card-security-code"),
                                           ("pin=1234", "card-pin"), ("atm_pin: 987654", "card-pin"),
                                           ("pin_block=0412AC89FFFFFFFF", "card-pin"), ("exp=12/27", "card-expiry"),
                                           ("expiry_date: 0128", "card-expiry")])
def test_card_codes(detectors_found, text, detector):
    assert detector in detectors_found(text)


@pytest.mark.parametrize("text", ["spin=1234", "pin_attempts=3", "pinned=12345", "mapping=4321",
                                  '"exp": 1735689600', "Set-Cookie: a=b; expires=Thu, 01 Jan 2027"])
def test_card_code_lookalikes(scan, text):
    assert scan(text) == []


# ------------------------------------------------------------------------------------------ identity

@pytest.mark.parametrize("text,confidence", [("ssn=219-09-9998", "high"), ('{"social_security_number":"219-09-9998"}', "high"),
                                             ("tin=219099998", "high"), ("SSN 219 09 9998 matched", "high"),
                                             ("customer 219-09-9998 ok", "medium"), ("ssn=123-45-6789", "low")])
def test_ssn(scan, text, confidence):
    assert [(d, c) for d, _v, c in scan(text)] == [("us-ssn", confidence)]


@pytest.mark.parametrize("text", ["setting 219099998 done", "routing id 219099998", "testing 219099998",
                                  "waiting for 219-099-998", "ssn=000-12-3456", "ssn=666-12-3456", "ssn=912-12-3456",
                                  "customer 219 09 9998 ok", "call 555-123-4567"])
def test_ssn_lookalikes(detectors_found, text):  # review item L7: 'tin' only counts as a whole word key
    assert "us-ssn" not in detectors_found(text)


def test_date_of_birth(detectors_found):
    assert "date-of-birth" in detectors_found("dob=1987-04-12")
    assert "date-of-birth" in detectors_found('"date_of_birth":"12/04/1987"')
    assert "date-of-birth" not in detectors_found("dob=2999-01-01")


# ------------------------------------------------------------------------------------------ banking

def test_iban(scan):
    assert scan("payout to GB82 WEST 1234 5698 7654 32 queued") == [("iban", "GB82 WEST 1234 5698 7654 32", "high")]
    assert scan("IBAN DE89370400440532013000.") == [("iban", "DE89370400440532013000", "high")]
    assert scan("IBAN DE89370400440532013001") == []
    assert scan("payout to GB82 WEST 1234 5698 7654 32 ABC") == [("iban", "GB82 WEST 1234 5698 7654 32", "high")]


def test_bank_account(detectors_found):
    assert "bank-account" in detectors_found("account_number=12345678901")
    assert "bank-account" in detectors_found("routing_number=021000021")
    assert "bank-account" not in detectors_found("routing_number=021000022")  # checksum fails
    assert "bank-account" not in detectors_found("account=alice")


# ------------------------------------------------------------------------------------------ credentials

@pytest.mark.parametrize("text,value", [("user=alice password=Hunter2Secret! from x", "Hunter2Secret!"),
                                        ('{"username":"bob","password":"s3cr3t-pw"}', "s3cr3t-pw"),
                                        ("spring.datasource.password=Winter2026", "Winter2026"),
                                        ("userPassword: Orange77x", "Orange77x"), ("db_pwd='abcd1234'", "abcd1234"),
                                        ("exec --password Tr0ub4dor --user x", "Tr0ub4dor"),
                                        ("<db><password>OpenSesame9</password></db>", "OpenSesame9"),
                                        ("password=changeme", "changeme")])
def test_passwords(scan, text, value):
    assert [(d, v) for d, v, _c in scan(text)] == [("password", value)]


@pytest.mark.parametrize("text", ["password=********", "db.password=${DB_PASSWORD}", "password: <redacted>",
                                  "password=[FILTERED]", '"password": null', "password=%s", "Invalid password for bob",
                                  "password: expired for user chen", "Password: required", "password=true",
                                  "PWD=/opt/app/current", "bypass=12345", "compass=north", "passwordless=true",
                                  "password=user=bob", "pass: 3/5"])
def test_password_lookalikes(scan, text):
    assert scan(text) == []


def test_unquoted_password_is_masked_to_the_end_of_the_token():
    from logcheck.engine import FileScanner
    from conftest import make_settings
    scanner = FileScanner(make_settings(include_values=False))
    [finding] = scanner.scan_line("x", 1, "login user=alice password=Summer2026&7x;ok next")
    assert "&7x" not in finding.evidence and "Summer" not in finding.evidence
    assert finding.evidence.endswith("password=" + "*" * len("Summer2026&7x;ok") + " next")


def test_password_hash_is_low_confidence(scan):
    assert scan("password=5f4dcc3b5aa765d61d8327deb882cf99") == [
        ("password", "5f4dcc3b5aa765d61d8327deb882cf99", "low")]


def test_connection_strings(scan, detectors_found):
    assert scan("connect postgresql://app:P4ssw0rd@db01:5432/cards") == [("connection-string", "P4ssw0rd", "high")]
    assert "connection-string" not in detectors_found("connect postgresql://app:****@db01:5432/cards")
    assert "connection-string" not in detectors_found("proxy https://api.example.com:8443/v1/items?id=4")


def test_authorization_header(scan):
    basic = base64.b64encode(b"svc_user:Winter2026!").decode()
    [(det, value, confidence)] = scan(f"Authorization: Basic {basic}")
    assert (det, value, confidence) == ("authorization-header", basic, "high")
    assert scan("Authorization: Bearer ********") == []


def _jwt(payload: dict) -> str:
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{part({'alg': 'HS256'})}.{part(payload)}.c2lnbmF0dXJlX3ZhbHVlX3g"


def test_bearer_jwt_reported_once_as_authorization(scan):
    token = _jwt({"sub": "alice", "exp": 4_000_000_000})
    assert [d for d, _v, _c in scan(f"Authorization: Bearer {token}")] == ["authorization-header"]
    assert scan(f"id token {token}") == [("jwt", token, "high")]
    expired = _jwt({"sub": "alice", "exp": 1_000_000_000})
    assert scan(f"id token {expired}")[0][2] == "medium"
    assert scan("not a token eyJub3RhbGciOiJ4In0.eyJzdWIiOiJ4In0.sig") == []


def test_api_tokens(detectors_found):
    assert "api-token" in detectors_found("api_key=9f8e7d6c5b4a39281706f5e4d3c2b1a0Zx")
    assert "api-token" in detectors_found('{"access_token":"Zk3mQ9xWv2Lp8Rt5Yn7Bc4Hd6Fg1Js0K"}')
    for text in ("api_key=YOUR_API_KEY_HERE", "access_token=null", "token_type=bearer", "x-api-key: ${PARTNER_KEY}"):
        assert "api-token" not in detectors_found(text)


def test_known_key_formats(scan):
    aws = "AK" + "IA" + "Z7Q2LMNOPQRS3TUV"
    github = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    google = "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
    for token in (aws, github, google):
        assert scan(f"using {token} now") == [("known-key-format", token, "high")]
    assert scan("using AKIA1234 now") == []


def test_session_ids(detectors_found):
    assert "session-id" in detectors_found("Cookie: JSESSIONID=8F3A9C2B7D1E4F6A0B5C9D8E7F6A5B4C; lang=en")
    assert "session-id" not in detectors_found("sid=S-1-5-21-3623811015-3361044348-30300820-1013")
    assert "session-id" not in detectors_found("session_id=1234")


def test_private_keys(scan):
    assert scan("-----BEGIN OPENSSH PRIVATE KEY-----") == [("private-key", "-----BEGIN OPENSSH PRIVATE KEY-----", "high")]
    assert scan("-----BEGIN ENCRYPTED PRIVATE KEY-----")[0][2] == "medium"
    assert scan("-----BEGIN PUBLIC KEY-----") == []


def test_crypto_keys(detectors_found):
    assert "crypto-key" in detectors_found("aes_key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    assert "crypto-key" in detectors_found("import zmk=U1A2B3C4D5E6F708192A3B4C5D6E7F8091 kcv=1A2B3C")
    assert "crypto-key" in detectors_found("signing_key: q3J7mK9pX2vL5nB8wR4tY6uI1oP0aS3dF7gH2jK5lZ8=")
    assert "crypto-key" not in detectors_found("aes_key=00000000000000000000000000000000")
    assert "crypto-key" not in detectors_found("cache_key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")


# ------------------------------------------------------------------------------------------ registry

def test_registry():
    ids = [d.id for d in all_detectors()]
    assert len(ids) == len(set(ids)) == 18
    assert [d.id for d in select(all_detectors(), enable=["iban", "jwt"])] == ["jwt", "iban"]
    assert "iban" not in [d.id for d in select(all_detectors(), disable=["iban"])]
    with pytest.raises(ValueError, match="nope"):
        select(all_detectors(), disable=["nope"])
