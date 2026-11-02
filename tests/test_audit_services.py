import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
import yaml

from audit_services import audit_file, audit_one, load_services, substitute


class ServiceAuditTests(unittest.TestCase):
    def setUp(self):
        # Any accidental use of a real socket must fail, even with cached DNS.
        for target in ("socket.socket.connect", "socket.socket.connect_ex",
                       "socket.getaddrinfo", "httpx.HTTPTransport.handle_request"):
            blocker = patch(target, side_effect=AssertionError("Network access in offline test"))
            blocker.start()
            self.addCleanup(blocker.stop)

    def test_malformed_fields_reported_without_crashing(self):
        cases = [
            ({"url": "https://["}, "NOT_HTTPS_OR_INVALID_URL"),
            ({"url": "https://example.invalid:bad/mock"}, "NOT_HTTPS_OR_INVALID_URL"),
            ({"headers": [1]}, "INVALID_HEADERS"),
            ({"headers": {1: "value"}}, "INVALID_HEADERS"),
            ({"headers": {"X-Test": 1}}, "INVALID_HEADERS"),
            ({1: "value", 2: "value"}, "INVALID_FIELD_NAME"),
            ({"data_type": "xml"}, "UNKNOWN_DATA_TYPE"),
        ]
        for fields, expected in cases:
            with self.subTest(fields=fields):
                result = audit_one({"name": "fixture", "method": "POST",
                                    "url": "https://example.invalid/mock",
                                    "identifier": "accepted", **fields}, "multi")
                self.assertFalse(result["request_built"])
                self.assertIn(expected, result["findings"])

    def test_invalid_entry_does_not_stop_audit(self):
        sample = """providers:
  multi:
    - name: bad
      method: GET
      url: 'https://['
    - name: good
      method: GET
      url: https://example.invalid/mock
      identifier: accepted
"""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "services.yaml"
            path.write_text(sample, encoding="utf-8")
            report = audit_file(path)
            self.assertEqual(report["total_services"], 2)
            self.assertEqual(report["mock_requests_constructed"], 1)

    def test_malformed_yaml_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "services.yaml"
            path.write_text("providers: [", encoding="utf-8")
            with self.assertRaises(yaml.YAMLError):
                load_services(path)

    def test_template_replacement(self):
        self.assertEqual(substitute("+{cc}{target}", country="33", target="000000000"), "+33000000000")

    def test_mock_transport_no_delivery(self):
        result = audit_one({
            "name": "fixture", "method": "POST", "url": "https://example.invalid/mock",
            "data_type": "json", "data": {"phone": "+{cc}{target}"},
            "identifier": "accepted",
        }, "multi")
        self.assertTrue(result["request_built"])
        self.assertEqual(result["findings"], [])

    def test_weak_identifier_warning(self):
        result = audit_one({
            "name": "fixture", "method": "GET", "url": "https://example.invalid/mock",
            "identifier": "true",
        }, "multi")
        self.assertTrue(result["request_built"])
        self.assertIn("WEAK_RESPONSE_IDENTIFIER_NOT_DELIVERY_PROOF", result["findings"])

    def test_invalid_url_never_attempted(self):
        result = audit_one({"name": "invalid", "method": "POST", "url": "http://example.invalid/sms"}, "multi")
        self.assertFalse(result["request_built"])
        self.assertIn("NOT_HTTPS_OR_INVALID_URL", result["findings"])

    def test_safe_loading_and_summary(self):
        sample = """providers:\n  '91':\n    - name: test\n      url: https://example.invalid/mock\n      method: GET\n      identifier: done\n  multi: []\n"""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "services.yaml"
            path.write_text(sample, encoding="utf-8")
            result = audit_file(path)
            self.assertEqual(result["total_services"], 1)
            self.assertEqual(result["messages_sent"], 0)
            self.assertEqual(result["network_requests"], 0)
            self.assertEqual(result["mock_requests_constructed"], 1)

    def test_unsafe_yaml_tag_rejected(self):
        sample = "providers: !!python/object/apply:os.system ['echo should-not-run']\n"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "services.yaml"
            path.write_text(sample, encoding="utf-8")
            with self.assertRaises(yaml.constructor.ConstructorError):
                load_services(path)


if __name__ == "__main__":
    unittest.main()
