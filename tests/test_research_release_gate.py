from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest

from scripts.research_release_gate import decision_for, validate_public_bundle
from scripts.build_public_bundle import build_public_bundle


ROOT = Path(__file__).resolve().parents[1]


class ReleaseGateTests(unittest.TestCase):
    def test_local_public_bundle_and_manifest_validate(self):
        result = validate_public_bundle(ROOT)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["research_usable_n"], 100)
        self.assertEqual(result["contexts"], {"D1": 100, "D2": 100, "D5": 100})
        self.assertEqual(result["manifest_entries_verified"], 605)

    def test_official_holiday_is_no_op(self):
        result = decision_for(
            ROOT,
            datetime.fromisoformat("2026-10-05T19:00:00+08:00"),
            "refresh",
            "300",
            False,
            False,
        )
        self.assertEqual(result["decision"], "NO_OP_NON_TRADING_DAY")
        self.assertFalse(result["publish"])

    def test_static_packager_emits_release_manifest_without_changing_api_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "site" / "docs"
            result = build_public_bundle(ROOT, output, "2026-09-30")
            release = json.loads((output / "PUBLIC_RELEASE_MANIFEST.json").read_text("utf-8"))
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(release["source_status"], "PUBLIC_STATIC_SNAPSHOT_NO_PROVIDER_FETCH")
            self.assertIsNone(release["eligible_universe_n"])
            self.assertEqual(release["eligible_universe_status"], "NOT_ESTABLISHED")
            self.assertEqual(release["context_count"], 300)
            self.assertEqual(validate_public_bundle(output.parent)["status"], "PASS")

    def test_static_packager_rejects_wrong_expected_session(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "ABORT_DATA_AS_OF_NOT_EXPECTED_SESSION"):
                build_public_bundle(ROOT, Path(temp) / "docs", "2026-10-08")

    def test_market_session_fails_closed_without_provider_authority(self):
        result = decision_for(
            ROOT,
            datetime.fromisoformat("2026-10-08T19:00:00+08:00"),
            "expand",
            "300",
            True,
            True,
        )
        self.assertEqual(result["decision"], "BLOCKED_PROVIDER_AUTHORIZATION")
        self.assertEqual(result["expected_session"], "2026-10-08")
        self.assertFalse(result["publish"])

    def test_refresh_waits_for_publication_lag_window(self):
        result = decision_for(
            ROOT,
            datetime.fromisoformat("2026-10-08T18:59:59+08:00"),
            "refresh",
            "300",
            False,
            False,
        )
        self.assertEqual(result["decision"], "NO_OP_PUBLICATION_LAG_WINDOW")

    def test_calendar_outside_versioned_range_is_blocked(self):
        result = decision_for(
            ROOT,
            datetime.fromisoformat("2026-11-02T19:00:00+08:00"),
            "refresh",
            "300",
            False,
            False,
        )
        self.assertEqual(result["decision"], "BLOCKED_CALENDAR_UNVERIFIED")
        self.assertFalse(result["publish"])


if __name__ == "__main__":
    unittest.main()
