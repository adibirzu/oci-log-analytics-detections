import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_PATH = PROJECT_ROOT / "queries" / "logan_ql_reference_catalog.json"
PATTERNS_PATH = PROJECT_ROOT / "queries" / "cross_ql_mapping_patterns.json"
EXAMPLES_PATH = PROJECT_ROOT / "queries" / "conversion_examples.json"


class LoganWorkbenchArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        missing = [path for path in (REFERENCE_PATH, PATTERNS_PATH, EXAMPLES_PATH) if not path.exists()]
        if missing:
            subprocess.run(
                [sys.executable, "scripts/generate_logan_workbench_artifacts.py"],
                cwd=PROJECT_ROOT,
                check=True,
            )
        cls.reference = json.loads(REFERENCE_PATH.read_text())
        cls.patterns = json.loads(PATTERNS_PATH.read_text())
        cls.examples = json.loads(EXAMPLES_PATH.read_text())

    def test_reference_catalog_has_required_official_provenance(self):
        self.assertEqual(self.reference["schema_version"], "1.0.0")
        self.assertIn("https://docs.oracle.com/en-us/iaas/log-analytics/doc/query-search.html", self.reference["sources"])
        self.assertIn(
            "https://docs.oracle.com/en-us/iaas/log-analytics/doc/command-reference.html",
            self.reference["sources"],
        )
        by_name = {entry["name"]: entry for entry in self.reference["commands"]}
        for command in self.reference["required_commands"]:
            self.assertIn(command, by_name)
            self.assertTrue(by_name[command]["summary"])
            self.assertTrue(by_name[command]["syntax"])
            self.assertTrue(by_name[command]["source_url"].startswith("https://docs.oracle.com/"))
            self.assertIn("official_command_reference", by_name[command]["provenance"])

    def test_mapping_patterns_cover_supported_source_families(self):
        languages = {pattern["source_language"] for pattern in self.patterns["patterns"]}
        self.assertIn("splunk_spl", languages)
        self.assertIn("sentinel_kql", languages)
        self.assertIn("sigma_yaml", languages)
        self.assertIn("elastic_lucene", languages)
        self.assertIn("cross_ql", languages)
        self.assertTrue(any(pattern["support_level"] == "unsupported" for pattern in self.patterns["patterns"]))
        for pattern in self.patterns["patterns"]:
            self.assertTrue(pattern["logan_commands"])
            self.assertTrue(pattern["warning_behavior"])

    def test_examples_are_bounded_and_cover_languages(self):
        examples = self.examples["examples"]
        self.assertGreaterEqual(len(examples), 10)
        self.assertLessEqual(len(examples), 20)
        languages = {example["source_language"] for example in examples}
        self.assertTrue({"sigma_yaml", "sentinel_kql", "splunk_spl", "elastic_lucene", "oci_logan"}.issubset(languages))
        self.assertTrue(any(example["support_level"] == "unsupported" for example in examples))
        pattern_ids = {pattern["id"] for pattern in self.patterns["patterns"]}
        for example in examples:
            self.assertTrue(example["source_query"])
            self.assertTrue(example["explanation"])
            self.assertTrue(set(example["pattern_ids"]).issubset(pattern_ids))


class LoganWorkbenchConverterTests(unittest.TestCase):
    def run_converter(self, payload):
        result = subprocess.run(
            [sys.executable, "scripts/logan_workbench_convert.py"],
            cwd=PROJECT_ROOT,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertIn(result.returncode, {0, 2}, result.stderr)
        return json.loads(result.stdout)

    def test_sigma_conversion_uses_backend_script(self):
        payload = {
            "source_language": "sigma_yaml",
            "source_query": "\n".join(
                [
                    "title: Test Encoded PowerShell",
                    "id: test-encoded-powershell",
                    "logsource:",
                    "  product: windows",
                    "  category: process_creation",
                    "detection:",
                    "  selection:",
                    "    Image|endswith: '\\\\powershell.exe'",
                    "    CommandLine|contains: ' -enc '",
                    "  condition: selection",
                    "level: high",
                ]
            ),
        }
        response = self.run_converter(payload)
        self.assertEqual(response["support_level"], "supported")
        self.assertIn("'Log Source'", response["logan_query"])
        self.assertIn("'Command Line'", response["logan_query"])
        self.assertIn("convert_sigma.py", response["explanation"])

    def test_kql_conversion_uses_sentinel_converter(self):
        response = self.run_converter(
            {
                "source_language": "sentinel_kql",
                "source_query": "SecurityEvent\n| where EventID == 4688\n| where CommandLine has \" -enc \"",
            }
        )
        self.assertEqual(response["support_level"], "supported")
        self.assertIn("Windows Security Events", response["logan_query"])
        self.assertIn("convert_sentinel_kql.py", response["explanation"])

    def test_unsafe_yaml_is_blocked(self):
        response = self.run_converter(
            {
                "source_language": "sigma_yaml",
                "source_query": "!!python/object/apply:os.system ['id']",
            }
        )
        self.assertEqual(response["support_level"], "unsupported")
        self.assertEqual(response["warnings"][0]["code"], "unsafe_yaml_tag")

    def test_all_published_examples_exercise_conversion_boundary(self):
        examples = json.loads(EXAMPLES_PATH.read_text())["examples"]
        self.assertGreaterEqual(len(examples), 10)
        for example in examples:
            with self.subTest(example=example["id"]):
                response = self.run_converter(
                    {
                        "source_language": example["source_language"],
                        "source_query": example["source_query"],
                    }
                )
                if example["support_level"] == "unsupported":
                    self.assertEqual(response["support_level"], "unsupported")
                    self.assertEqual(response["logan_query"], "")
                else:
                    self.assertIn(response["support_level"], {"supported", "partial", "lossy"})
                    self.assertIn("'Log Source'", response["logan_query"])


if __name__ == "__main__":
    unittest.main()
