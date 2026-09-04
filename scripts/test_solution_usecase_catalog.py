"""Contract tests for customer-oriented solution documentation links."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SolutionUseCaseCatalogTests(unittest.TestCase):
    def test_documentation_hub_maps_customer_needs_to_answers(self) -> None:
        text = (ROOT / "docs/README.md").read_text(encoding="utf-8")
        required = (
            "## Use cases: customer needs and answers",
            "Parallel SIEM",
            "Oracle Database Security Analytics",
            "Windows Access Monitoring",
            "OKE Observability",
            "Cost and Retention",
            "How the solution answers it",
            "Technical implementation",
        )
        for value in required:
            self.assertIn(value, text)

    def test_public_hub_and_durable_splunk_documents_are_linked(self) -> None:
        root_readme = (ROOT / "README.md").read_text(encoding="utf-8")
        docs_readme = (ROOT / "docs/README.md").read_text(encoding="utf-8")
        self.assertIn("https://github.com/adibirzu/oci-sd-observability", root_readme)
        self.assertIn("SPLUNK_PARALLEL_DESIGN.md", docs_readme)
        self.assertIn("SPLUNK_PARALLEL_IMPLEMENTATION_PLAN.md", docs_readme)
        self.assertNotIn("docs/superpowers/plans", root_readme + docs_readme)


if __name__ == "__main__":
    unittest.main()
