"""The AI verifier must never send a detected value (or other values in the evidence) off the machine."""

import json
import unittest

from autologger import constants as C
from autologger.ai.openai_verifier import OpenAIVerifier, build_payload
from autologger.ai.redaction import redact_evidence, shape
from autologger.config.openai_config import OpenAIConfig

SECRETS = {
    C.PASSWORD: ("Hunter2Secret!", "2026-11-12 INFO login user=alice password=Hunter2Secret! from 10.1.2.3"),
    C.SSN: ("123-45-6789", "INFO customer ssn: 123-45-6789 verified"),
    C.DB_STRING: ("jdbc:informix-sqli://db01:1526/cards;user=app;password=S3cr3tPw",
                  "ERROR connect jdbc:informix-sqli://db01:1526/cards;user=app;password=S3cr3tPw failed"),
    C.CRYPTO_KEYS: ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                    "WARN key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 loaded"),
    C.SESSION_TOKENS: ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlX3ZhbHVl",
                       "INFO Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlX3ZhbHVl"),
}

CONFIG = OpenAIConfig(True, "test-key", "gpt-4.1-mini", "https://example.invalid/v1/responses",
                      1000, 1, 0, 1, 0, 0, 0, 0)


class ShapeTest(unittest.TestCase):
    def test_shape_keeps_format_not_content(self):
        self.assertEqual(shape("Hunter2!"), "Aaaaaa9*")
        self.assertEqual(shape("123-45-6789"), "999-99-9999")
        self.assertEqual(shape(""), "")

    def test_redact_evidence_masks_match_and_assigned_values(self):
        text = redact_evidence("Hunter2Secret!", "user=alice password=Hunter2Secret! pin: 4321")
        self.assertNotIn("Hunter2Secret", text)
        self.assertNotIn("alice", text)
        self.assertNotIn("4321", text)
        self.assertIn("password=", text)  # key names stay, so the model can still classify
        self.assertIn("pin:", text)


class PayloadTest(unittest.TestCase):
    def test_no_secret_in_any_payload(self):
        for type_name, (match, evidence) in SECRETS.items():
            body = build_payload("gpt-4.1-mini", type_name, match, evidence, True)
            json.loads(body)  # still valid JSON
            for fragment in (match, match[:8], match[-8:]):
                self.assertNotIn(fragment, body, f"{type_name}: '{fragment}' leaked into the request")

    def test_verifier_sends_only_masked_values(self):
        sent = []

        def fake_post(url, headers, body, timeout):
            sent.append(body.decode("utf-8"))
            return 200, '{"output":[{"content":[{"type":"output_text","text":"CONFIRMED"}]}]}'

        verifier = OpenAIVerifier(http_post=fake_post, sleep=lambda _s: None)
        verifier.initialize_for_new_run(CONFIG)
        for type_name, (match, evidence) in SECRETS.items():
            self.assertEqual(verifier.verify(type_name, match, evidence), C.AI_CONFIRMED)
        self.assertEqual(len(sent), len(SECRETS))
        for body, (match, _evidence) in zip(sent, SECRETS.values()):
            self.assertNotIn(match, body)


if __name__ == "__main__":
    unittest.main()
