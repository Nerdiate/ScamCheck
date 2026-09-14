"""Unit tests for the EMCC domain-configuration checks.

Uses an injected fake DNS resolver rather than live lookups, so results are
deterministic and don't depend on any particular domain's records staying
the same over time (or on network access being available at all).

Run with: python3 tests/test_emcc.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dns.resolver

from scamcheck.emcc import analyze_domain_config


class FakeAnswer:
    def __init__(self, text: str):
        self.strings = [text.encode()]


class FakeMXRecord:
    def __init__(self, exchange: str):
        self.exchange = exchange


class FakeResolver:
    """records: {(name, record_type): [FakeAnswer,...] | Exception}
    A missing key raises NXDOMAIN, matching real resolver behavior for an
    absent record.
    """

    def __init__(self, records):
        self.records = records

    def resolve(self, name, rtype):
        result = self.records.get((name.rstrip("."), rtype))
        if result is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(result, Exception):
            raise result
        return result


class TestEMCC(unittest.TestCase):
    def test_weak_domain_flags_permissive_spf_and_missing_dmarc(self):
        resolver = FakeResolver({
            ("weakcorp.com", "TXT"): [FakeAnswer("v=spf1 include:somehost.com +all")],
            ("weakcorp.com", "MX"): dns.resolver.NoAnswer(),
        })
        report = analyze_domain_config("weakcorp.com", resolver=resolver)

        finding_ids = {f.id for f in report.findings}
        self.assertIn("spf_plus_all", finding_ids)
        self.assertIn("dmarc_missing", finding_ids)
        self.assertIn("mx_missing", finding_ids)
        self.assertGreaterEqual(report.score, 60)
        self.assertIn("High exposure", report.risk_level)

    def test_strong_domain_scores_well(self):
        resolver = FakeResolver({
            ("strongcorp.com", "TXT"): [FakeAnswer("v=spf1 include:_spf.google.com -all")],
            ("_dmarc.strongcorp.com", "TXT"): [FakeAnswer("v=DMARC1; p=reject; rua=mailto:dmarc@strongcorp.com")],
            ("google._domainkey.strongcorp.com", "TXT"): [FakeAnswer("v=DKIM1; k=rsa; p=ABC")],
            ("strongcorp.com", "MX"): [FakeMXRecord("mail.strongcorp.com.")],
        })
        report = analyze_domain_config("strongcorp.com", resolver=resolver)

        self.assertEqual(report.score, 0)
        self.assertIn("Well configured", report.risk_level)
        concerning = [f for f in report.findings if f.weight > 0]
        self.assertEqual(concerning, [])

    def test_nonexistent_domain_short_circuits_to_one_finding(self):
        resolver = FakeResolver({})
        report = analyze_domain_config("totally-fake-domain-xyz-99.com", resolver=resolver)

        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].id, "domain_not_found")
        self.assertGreaterEqual(report.score, 50)

    def test_dmarc_policy_none_is_flagged_but_less_severely_than_missing(self):
        base_records = {
            ("midcorp.com", "TXT"): [FakeAnswer("v=spf1 include:_spf.google.com -all")],
            ("midcorp.com", "MX"): [FakeMXRecord("mail.midcorp.com.")],
        }
        none_records = dict(base_records)
        none_records[("_dmarc.midcorp.com", "TXT")] = [FakeAnswer("v=DMARC1; p=none")]
        report_none = analyze_domain_config("midcorp.com", resolver=FakeResolver(none_records))

        missing_records = dict(base_records)
        report_missing = analyze_domain_config("midcorp.com", resolver=FakeResolver(missing_records))

        self.assertLess(report_none.score, report_missing.score)
        self.assertIn("dmarc_policy_none", {f.id for f in report_none.findings})
        self.assertIn("dmarc_missing", {f.id for f in report_missing.findings})

    def test_spf_multiple_records_flagged(self):
        resolver = FakeResolver({
            ("dupspf.com", "TXT"): [
                FakeAnswer("v=spf1 include:_spf.google.com -all"),
                FakeAnswer("v=spf1 include:sendgrid.net -all"),
            ],
            ("_dmarc.dupspf.com", "TXT"): [FakeAnswer("v=DMARC1; p=reject; rua=mailto:d@dupspf.com")],
            ("dupspf.com", "MX"): [FakeMXRecord("mail.dupspf.com.")],
        })
        report = analyze_domain_config("dupspf.com", resolver=resolver)
        self.assertIn("spf_multiple_records", {f.id for f in report.findings})


if __name__ == "__main__":
    unittest.main()
