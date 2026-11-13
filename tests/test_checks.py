import datetime as dt

import pytest

from logcheck import checks


@pytest.mark.parametrize("number,ok", [("4539578763621486", True), ("4539578763621487", False), ("79927398713", True),
                                       ("", False), ("4539 5787", False), ("٤٥٣٩", False)])
def test_luhn(number, ok):
    assert checks.luhn_valid(number) is ok


@pytest.mark.parametrize("number,brand", [("4539578763621486", "Visa"), ("2221000000000009", "Mastercard"),
                                          ("378282246310005", "American Express"), ("6011000990139424", "Discover"),
                                          ("3530111333300000", "JCB"), ("9539578763621486", None),
                                          ("37828224631000", None)])  # Amex prefix, wrong length
def test_card_brand(number, brand):
    assert checks.card_brand(number) == brand


def test_test_and_trivial_cards():
    assert checks.is_test_or_trivial_card("4111111111111111")
    assert checks.is_test_or_trivial_card("4444444444444448")
    assert not checks.is_test_or_trivial_card("4539578763621486")


@pytest.mark.parametrize("ssn,ok", [("219099998", True), ("000123456", False), ("666123456", False),
                                    ("912123456", False), ("219009998", False), ("219090000", False)])
def test_ssn_rules(ssn, ok):
    assert checks.ssn_valid(ssn[:3], ssn[3:5], ssn[5:]) is ok


@pytest.mark.parametrize("iban,ok", [("GB82WEST12345698765432", True), ("GB82 WEST 1234 5698 7654 32", True),
                                     ("DE89370400440532013000", True), ("DE89370400440532013001", False),
                                     ("GB82WEST1234569876543", False), ("XX82WEST12345698765432", False)])
def test_iban(iban, ok):
    assert checks.iban_valid(iban) is ok


def test_aba_routing():
    assert checks.aba_routing_valid("021000021")
    assert not checks.aba_routing_valid("021000022")
    assert not checks.aba_routing_valid("991000021")  # prefix outside the Federal Reserve ranges


def test_entropy_orders_values():
    assert checks.shannon_entropy("aaaaaaaa") == 0
    assert checks.shannon_entropy("Zx9Qw2Lm8Rt5Yp3K") > checks.shannon_entropy("passwordpassword")


@pytest.mark.parametrize("value", ["********", "xxxxxx", "${DB_PASSWORD}", "<redacted>", "[FILTERED]", "null", "%s",
                                   "{0}", "{{ vault.pw }}", "$DB_PASS", "ab****yz", "N/A", ""])
def test_placeholders(value):
    assert checks.is_placeholder(value)


@pytest.mark.parametrize("value", ["Hunter2!", "$ecret1", "correct horse", "S3cr3tPw"])
def test_real_values_are_not_placeholders(value):
    assert not checks.is_placeholder(value)


def test_hash_formats():
    assert checks.looks_like_hash("$2b$12$" + "a" * 53)
    assert checks.looks_like_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    assert not checks.looks_like_hash("Hunter2Secret!")


def test_jwt_header():
    assert checks.jwt_header("eyJhbGciOiJIUzI1NiJ9.e30.x") == {"alg": "HS256"}
    assert checks.jwt_header("eyJmb28iOiJiYXIifQ.e30.x") is None  # JSON, but no "alg"
    assert checks.jwt_header("not-base64!.e30.x") is None


def test_birth_dates():
    assert checks.plausible_birth_date("1987-04-12")
    assert checks.plausible_birth_date("12/04/1987")
    assert not checks.plausible_birth_date("2999-01-01")
    assert not checks.plausible_birth_date("1850-01-01")
    assert not checks.plausible_birth_date("1987-13-45")
    assert checks.parse_date("19870412") == dt.date(1987, 4, 12)
