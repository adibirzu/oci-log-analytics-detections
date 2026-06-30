#!/usr/bin/env python3
"""Regression checks for fail-safe deployment workflow preflights."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class TestDeploymentWorkflows(unittest.TestCase):
    def test_pages_workflow_skips_deployment_when_pages_is_disabled(self):
        workflow = (ROOT / ".github/workflows/forge-github-pages.yml").read_text(encoding="utf-8")

        self.assertIn("pages-preflight:", workflow)
        self.assertIn("github.rest.repos.getPages", workflow)
        self.assertIn("pages_enabled", workflow)
        self.assertIn("if: needs.pages-preflight.outputs.pages_enabled == 'true'", workflow)

    def test_sentinel_live_lane_requires_a_non_failing_secret_preflight(self):
        workflow = (ROOT / ".github/workflows/sentinel-converter.yml").read_text(encoding="utf-8")

        self.assertIn("live-preflight:", workflow)
        self.assertIn("credentials_available", workflow)
        self.assertIn("if: needs.live-preflight.outputs.credentials_available == 'true'", workflow)
        self.assertIn("OCI_CONFIG and OCI_API_KEY_PEM are not configured", workflow)


if __name__ == "__main__":
    unittest.main()
