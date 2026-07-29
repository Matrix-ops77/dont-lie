"""Tests for the CRM lead pipeline."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dontlie-crm-test-")
os.environ["DONTLIE_CRM_PATH"] = str(Path(_TMP) / "leads.jsonl")

from dontlie.crm import CRMPipeline, CRMPipelineError, load, save


class CRMPipelineTest(unittest.TestCase):
    def test_add_lead_returns_id_and_grade(self) -> None:
        crm = CRMPipeline()
        lead = crm.add("alice@example.com", "Acme", score=80, notes="hot")
        self.assertEqual(lead.grade(), "hot")
        self.assertEqual(lead.status, "new")

    def test_duplicate_email_updates_existing(self) -> None:
        crm = CRMPipeline()
        a = crm.add("alice@example.com", "Acme", score=20)
        b = crm.add("alice@example.com", "Acme Inc", score=40, notes="called")
        self.assertEqual(a.lead_id, b.lead_id)
        self.assertEqual(b.score, 40)
        self.assertEqual(b.company, "Acme Inc")
        self.assertIn("called", b.notes)

    def test_invalid_email_raises(self) -> None:
        crm = CRMPipeline()
        with self.assertRaises(CRMPipelineError):
            crm.add("not-an-email")

    def test_invalid_status_raises(self) -> None:
        crm = CRMPipeline()
        with self.assertRaises(CRMPipelineError):
            crm.add("a@example.com", status="dreaming")

    def test_update_status_and_score(self) -> None:
        crm = CRMPipeline()
        lead = crm.add("a@example.com")
        crm.update(lead.lead_id, status="qualified", score=50)
        self.assertEqual(crm.leads[lead.lead_id].status, "qualified")
        self.assertEqual(crm.leads[lead.lead_id].score, 50)

    def test_hot_warm_cold_split(self) -> None:
        crm = CRMPipeline()
        crm.add("a@example.com", score=10)
        crm.add("b@example.com", score=50)
        crm.add("c@example.com", score=90)
        hot = crm.hot()
        self.assertEqual(len(hot), 1)
        self.assertEqual(hot[0].email, "c@example.com")

    def test_count_by_status(self) -> None:
        crm = CRMPipeline()
        crm.add("a@example.com", status="new")
        crm.add("b@example.com", status="qualified")
        crm.add("c@example.com", status="qualified")
        counts = crm.count()
        self.assertEqual(counts["new"], 1)
        self.assertEqual(counts["qualified"], 2)
        self.assertEqual(counts["piloting"], 0)

    def test_save_and_load(self) -> None:
        crm = CRMPipeline()
        crm.add("a@example.com", "Acme", score=80)
        crm.add("b@example.com", "Beta", score=30)
        save(crm)
        loaded = load()
        self.assertEqual(len(loaded.leads), 2)
        emails = {lead.email for lead in loaded.leads.values()}
        self.assertEqual(emails, {"a@example.com", "b@example.com"})


if __name__ == "__main__":
    unittest.main()
