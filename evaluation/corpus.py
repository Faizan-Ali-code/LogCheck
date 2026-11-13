"""A generated, labelled log corpus: ordinary log lines, lines that carry sensitive data (positives) and
lines built to trigger false positives (traps).

Every positive line carries exactly one labelled value; noise and trap lines carry none. Values are
generated at run time (valid checksums, random secrets), so the repository holds no secret-looking strings.
The corpus is synthetic: it measures the rules against the cases it contains, not against real logs.
"""

from __future__ import annotations

import base64
import json
import random
import string
import uuid
from dataclasses import dataclass

from logcheck.checks import IBAN_LENGTHS, aba_routing_valid, card_brand, is_test_or_trivial_card, luhn_valid


@dataclass(frozen=True)
class Line:
    text: str
    detector: str | None = None  # the labelled detector for a positive line
    trap: str | None = None  # the false-positive trap a line was built for


class Gen:
    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)

    # ---------------------------------------------------------------- primitives
    def digits(self, n: int, first: str | None = None) -> str:
        s = "".join(self.r.choice(string.digits) for _ in range(n))
        return (first + s[1:]) if first else s

    def chars(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def ts(self) -> str:
        return (f"2026-{self.r.randint(1, 12):02d}-{self.r.randint(1, 28):02d} "
                f"{self.r.randint(0, 23):02d}:{self.r.randint(0, 59):02d}:{self.r.randint(0, 59):02d}.{self.r.randint(0, 999):03d}")

    def level(self) -> str:
        return self.r.choice(["INFO ", "DEBUG", "WARN ", "ERROR", "TRACE"])

    def head(self, component: str) -> str:
        return f"{self.ts()} {self.level()} [{self.r.choice(['main', 'http-nio-8443-exec-3', 'worker-7', 'pool-2-thread-1'])}] {component} -"

    def ip(self) -> str:
        return ".".join(str(self.r.randint(1, 254)) for _ in range(4))

    def secret(self, n: int = 14) -> str:
        word = self.r.choice(["Summer", "Falcon", "Orange", "Winter", "Rocket", "Silver", "Monkey", "Dragon"])
        tail = self.chars(string.ascii_letters + string.digits, max(2, n - len(word) - 2))
        return word + tail + self.r.choice("!@#$%^&*") + str(self.r.randint(0, 9))

    def token(self, n: int) -> str:
        return self.chars(string.ascii_letters + string.digits, n - 2) + str(self.r.randint(0, 9)) + self.r.choice("AbZx")

    # ---------------------------------------------------------------- valid sensitive values
    def pan(self) -> str:
        prefix, length = self.r.choice([("4", 16), ("4", 16), ("51", 16), ("55", 16), ("2221", 16), ("2720", 16),
                                        ("34", 15), ("37", 15), ("6011", 16), ("3530", 16), ("62", 16), ("36", 14)])
        while True:
            body = prefix + self.digits(length - len(prefix) - 1)
            for d in string.digits:
                if luhn_valid(body + d) and not is_test_or_trivial_card(body + d) and card_brand(body + d):
                    return body + d

    def formatted_pan(self) -> str:
        pan = self.pan()
        sep = self.r.choice([" ", "-"])
        if len(pan) == 15:
            return sep.join((pan[:4], pan[4:10], pan[10:]))
        if len(pan) == 14:
            return sep.join((pan[:4], pan[4:10], pan[10:]))
        return sep.join(pan[i:i + 4] for i in range(0, 16, 4))

    def ssn(self, sep: str = "-") -> str:
        while True:
            area = self.r.randint(1, 899)
            if area != 666:
                break
        return f"{area:03d}{sep}{self.r.randint(1, 99):02d}{sep}{self.r.randint(1, 9999):04d}"

    def iban(self) -> str:
        country = self.r.choice(["DE", "GB", "FR", "NL", "PK", "IT", "ES"])
        n = IBAN_LENGTHS[country]
        if country in ("GB", "NL"):
            bban = self.chars(string.ascii_uppercase, 4) + self.digits(n - 8)
        elif country == "PK":
            bban = self.chars(string.ascii_uppercase, 4) + self.digits(n - 8)
        else:
            bban = self.digits(n - 4)
        numeric = "".join(str(int(c, 36)) for c in bban + country + "00")
        iban = f"{country}{98 - int(numeric) % 97:02d}{bban}"
        return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4)) if self.r.random() < 0.5 else iban

    def bad_iban(self) -> str:
        """A valid IBAN with its last digit changed: the mod-97 remainder moves by 1-9, so it never validates."""
        iban = self.iban().replace(" ", "")
        return iban[:-1] + str((int(iban[-1]) + self.r.randint(1, 9)) % 10)

    def routing(self) -> str:
        while True:
            candidate = self.r.choice(["02", "03", "11", "21", "26", "31", "06"]) + self.digits(7)
            if aba_routing_valid(candidate):
                return candidate

    def jwt(self) -> str:
        def b64(obj: dict) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
        payload = {"sub": f"user{self.r.randint(1, 9999)}", "exp": 2_000_000_000 + self.r.randint(0, 10**6)}
        return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(payload)}.{self.token(43)}"

    # ---------------------------------------------------------------- lines
    def noise(self) -> str:
        r = self.r
        choice = r.randrange(11)
        if choice == 0:
            return (f'{self.head("access")} {self.ip()} "GET /api/v1/items/{r.randint(1, 99999)} HTTP/1.1" 200 '
                    f'{r.randint(100, 99999)} {r.randint(1, 900)}ms')
        if choice == 1:
            return f"{self.head('sql')} SELECT * FROM orders WHERE id = {r.randint(1, 10**9)} -- {r.randint(1, 500)} ms"
        if choice == 2:
            return f"{self.head('scheduler')} job nightly-export finished in {r.randint(1, 10**6)} ms, {r.randint(0, 10**5)} records"
        if choice == 3:
            return f"{self.head('cache')} miss key=user:{r.randint(1, 10**6)} ttl={r.randint(1, 3600)}"
        if choice == 4:
            return f"{self.head('auth')} user {r.choice(['alice', 'bob', 'chen', 'dana'])} logged in from {self.ip()}"
        if choice == 5:
            return f"{self.head('build')} version 2.{r.randint(0, 40)}.{r.randint(0, 9)} commit {self.chars('0123456789abcdef', 40)}"
        if choice == 6:
            return f"{self.head('storage')} uploaded checksum sha256={self.chars('0123456789abcdef', 64)} size={r.randint(1, 10**8)}"
        if choice == 7:
            return f"{self.head('trace')} request_id={uuid.UUID(int=r.getrandbits(128))} duration={r.randint(1, 5000)}ms"
        if choice == 8:
            return f"{self.head('app')} java.lang.IllegalStateException: queue full at com.example.Queue.put(Queue.java:{r.randint(10, 999)})"
        if choice == 9:
            return f"{self.head('metrics')} heap_used={r.randint(10**8, 10**10)} gc_pause_ms={r.randint(0, 900)} threads={r.randint(5, 400)}"
        return f"{self.head('notify')} sent sms to +1-{self.digits(3)}-{self.digits(3)}-{self.digits(4)} at {self.ts()}"

    def positives(self) -> list[Line]:
        r, out = self.r, []

        def add(detector: str, n: int, make) -> None:
            out.extend(Line(make(), detector) for _ in range(n))

        add("card-number", 40, lambda: f"{self.head('payments')} authorising card={self.pan()} amount={r.randint(1, 9999)}.00")
        add("card-number", 25, lambda: f'{self.head("http")} request body {{"pan":"{self.pan()}","currency":"USD"}}')
        add("card-number", 30, lambda: f"{self.head('checkout')} customer paid with {self.formatted_pan()} order {r.randint(1, 10**6)}")
        add("card-number", 15, lambda: f"{self.head('gateway')} GET /v1/charge?cc={self.pan()}&cur=EUR -> 402")
        add("card-number", 15, lambda: f"{self.head('gateway')} declined {self.pan()} reason=05")

        def track() -> str:
            pan, yymm = self.pan(), f"{r.randint(26, 35)}{r.randint(1, 12):02d}"
            if r.random() < 0.5:
                return f"{self.head('pos')} swipe data ;{pan}={yymm}101{self.digits(12)}?"
            return f"{self.head('pos')} raw track %B{pan}^DOE/JOHN^{yymm}101{self.digits(10)}?"
        add("card-track-data", 20, track)
        add("card-security-code", 20, lambda: r.choice([f"{self.head('payments')} cvv={self.digits(3)} accepted",
                                                         f'{self.head("http")} {{"cvc": "{self.digits(3)}", "save": true}}',
                                                         f"{self.head('ivr')} card_verification_value: {self.digits(4)}"]))
        add("card-pin", 15, lambda: r.choice([f"{self.head('atm')} pin={self.digits(4)} entered",
                                              f"{self.head('hsm')} clear pin_block={self.chars('0123456789ABCDEF', 16)}"]))
        add("card-expiry", 10, lambda: f"{self.head('payments')} exp={r.randint(1, 12):02d}/{r.randint(26, 33)} brand=visa")
        add("us-ssn", 15, lambda: f"{self.head('kyc')} applicant ssn={self.ssn()} verified")
        add("us-ssn", 10, lambda: f'{self.head("kyc")} {{"social_security_number":"{self.ssn()}"}}')
        add("us-ssn", 10, lambda: f"{self.head('tax')} tin={self.ssn('')} accepted")
        add("us-ssn", 10, lambda: f"{self.head('kyc')} SSN {self.ssn(' ')} matched")
        add("date-of-birth", 15, lambda: f"{self.head('kyc')} dob={r.randint(1940, 2005)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}")
        add("iban", 20, lambda: f"{self.head('sepa')} payout to IBAN {self.iban()} queued")
        add("bank-account", 10, lambda: f"{self.head('ach')} account_number={self.digits(10)} type=checking")
        add("bank-account", 10, lambda: f"{self.head('ach')} routing_number={self.routing()} bank=FIRST")
        add("password", 20, lambda: f"{self.head('auth')} login user=alice password={self.secret()}")
        add("password", 15, lambda: f'{self.head("http")} body {{"username":"bob","password":"{self.secret()}"}}')
        add("password", 10, lambda: f"{self.head('config')} <datasource><password>{self.secret()}</password></datasource>")
        add("password", 10, lambda: f"{self.head('ops')} exec backup.sh --password {self.secret()} --target s3")
        add("password", 10, lambda: f"{self.head('config')} spring.datasource.password={self.secret()}")
        add("connection-string", 15, lambda: f"{self.head('db')} connecting to postgresql://app:{self.token(16)}@db01:5432/cards")
        add("authorization-header", 10, lambda: f"{self.head('http')} Authorization: Basic "
            f"{base64.b64encode(f'svc_user:{self.secret()}'.encode()).decode()}")
        add("authorization-header", 10, lambda: f"{self.head('http')} header Authorization: Bearer {self.token(40)}")
        add("api-token", 15, lambda: f"{self.head('client')} calling partner api_key={self.token(32)}")
        add("api-token", 10, lambda: f'{self.head("oauth")} response {{"access_token":"{self.token(48)}","expires_in":3600}}')
        add("known-key-format", 10, lambda: f"{self.head('aws')} using key " + "AK" + "IA" + self.chars(string.ascii_uppercase + string.digits, 16))
        add("known-key-format", 5, lambda: f"{self.head('ci')} token " + "gh" + "p_" + self.chars(string.ascii_letters + string.digits, 36))
        add("known-key-format", 5, lambda: f"{self.head('maps')} key=" + "AI" + "za" + self.chars(string.ascii_letters + string.digits + "_-", 35))
        add("jwt", 10, lambda: f"{self.head('sso')} id token issued {self.jwt()}")
        add("session-id", 15, lambda: f"{self.head('http')} Cookie: JSESSIONID={self.chars('0123456789ABCDEF', 32)}; lang=en")
        add("private-key", 5, lambda: f"{self.head('tls')} -----BEGIN RSA PRIVATE KEY-----")
        add("crypto-key", 10, lambda: f"{self.head('crypto')} aes_key={self.chars('0123456789abcdef', 64)} loaded")
        add("crypto-key", 10, lambda: f"{self.head('hsm')} import zmk=U{self.chars('0123456789ABCDEF', 32)} kcv=1A2B3C")
        return out

    def traps(self) -> list[Line]:
        r, out = self.r, []

        def add(trap: str, n: int, make) -> None:
            out.extend(Line(make(), None, trap) for _ in range(n))

        # numbers that contain or resemble card numbers
        add("card number inside a longer ID", 40, lambda: f"{self.head('ledger')} txn_ref={self.pan()}{self.digits(4)} posted")
        add("card number inside a longer ID", 20, lambda: f"{self.head('ledger')} ref={self.digits(3)}{self.pan()} ok")
        add("masked card number", 20, lambda: (lambda p: f"{self.head('payments')} card={p[:6]}{'*' * (len(p) - 10)}{p[-4:]}")(self.pan()))
        add("epoch milliseconds", 30, lambda: f"{self.head('events')} ts_ms=17{self.digits(11)} seq={r.randint(1, 999)}")
        add("random 16-digit order ID", 60, lambda: f"{self.head('orders')} order_id={self.digits(16, r.choice('123456789'))} created")
        # SSN-like numbers near words that contain 'tin' or 'ssn' as substrings
        add("9 digits after 'setting', 'routing', 'testing'", 40, lambda: f"{self.head(r.choice(['config', 'router', 'qa']))} "
            f"{r.choice(['setting', 'routing', 'testing', 'starting', 'waiting'])} id {self.digits(9)} done")
        add("phone number", 20, lambda: f"{self.head('crm')} callback {self.digits(3)}-{self.digits(3)}-{self.digits(4)}")
        add("invalid SSN area", 15, lambda: f"{self.head('kyc')} ssn={r.choice(['000', '666', '9' + self.digits(2)])}-{self.digits(2)}-{self.digits(4)}")
        # password-like text that is not a password
        add("password placeholder", 40, lambda: f"{self.head('config')} " + r.choice([
            "password=********", "db.password=${DB_PASSWORD}", "password: <redacted>", "password=[FILTERED]",
            '"password": null', "password=%s", "smtp_password={{ vault.smtp }}", "password=xxxxxx"]))
        add("password in a message", 40, lambda: f"{self.head('auth')} " + r.choice([
            "Invalid password for user bob", "password: expired for user chen", "password reset requested",
            "password=true remember=false", "Password: required", "password policy: min length 12"]))
        add("working directory variable", 15, lambda: f"{self.head('env')} PWD=/opt/app/release-{r.randint(1, 99)} HOME=/home/app")
        add("words ending in 'pass' or 'pin'", 30, lambda: f"{self.head('misc')} " + r.choice([
            f"bypass={r.randint(1000, 9999)}", f"spin={r.randint(1000, 9999)}", f"pin_attempts={r.randint(1, 3)}",
            f"compass=north{r.randint(1000, 9999)}", f"pinned={r.randint(10000, 99999)}"]))
        # tokens and keys that are not credentials
        add("API key placeholder", 20, lambda: f"{self.head('client')} " + r.choice([
            "api_key=YOUR_API_KEY_HERE", "access_token=null", "token_type=bearer", "api_key=<your key>",
            "x-api-key: ${PARTNER_KEY}"]))
        add("Windows SID", 10, lambda: f"{self.head('ad')} sid=S-1-5-21-{self.digits(10)}-{self.digits(10)}-{self.digits(4)}")
        add("JWT claim or cookie expiry", 20, lambda: r.choice([
            f'{self.head("sso")} claims {{"exp": 17{self.digits(8)}, "iat": 17{self.digits(8)}}}',
            f"{self.head('http')} Set-Cookie: lang=en; expires=Thu, 01 Jan 2027 00:00:00 GMT"]))
        add("invalid IBAN checksum", 15, lambda: f"{self.head('sepa')} rejected IBAN {self.bad_iban()}")
        add("URL without credentials", 20, lambda: f"{self.head('http')} proxy to https://api.example.com:8443/v1/items?id={r.randint(1, 999)}")
        add("hash or checksum", 20, lambda: f"{self.head('storage')} cache_key={self.chars('0123456789abcdef', 64)} hit")
        add("bearer placeholder", 10, lambda: f"{self.head('http')} Authorization: Bearer ********")
        return out


def generate(seed: int = 2026, noise_lines: int = 6000) -> list[Line]:
    g = Gen(seed)
    lines = [Line(g.noise()) for _ in range(noise_lines)] + g.positives() + g.traps()
    g.r.shuffle(lines)
    return lines
