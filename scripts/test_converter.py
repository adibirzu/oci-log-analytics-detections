#!/usr/bin/env python3
"""Unit tests for the Sigma-to-OCL converter (convert_sigma.py).

Covers:
  - Wildcard selection expansion (1 of sel*, all of filter*)
  - Chained modifier |contains|all
  - Negation (not filter_*)
  - Unknown logsource stderr warning
  - count()/timeframe graceful degradation

No external dependencies — stdlib unittest only.
"""

import io
import json
import os
import sys
import tempfile
import unittest

# Ensure project scripts are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from convert_sigma import (
    parse_selection,
    parse_condition,
    _expand_wildcard_selections,
    convert_rule,
    build_log_source_filter,
    load_existing_query_index,
    load_config,
    merge_preserved_fields,
    resolve_output_relative_path,
)


class TestWildcardSelectionExpansion(unittest.TestCase):
    """Test ``1 of sel*`` and ``all of filter*`` expansion."""

    def test_1_of_selection_star(self):
        detection = {
            'selection1': {'CommandLine|contains': 'foo'},
            'selection2': {'CommandLine|contains': 'bar'},
            'filter': {'User': 'SYSTEM'},
            'condition': '1 of selection* and not filter',
        }
        result = _expand_wildcard_selections(detection['condition'], detection)
        self.assertIn('selection1', result)
        self.assertIn('selection2', result)
        self.assertIn(' or ', result)
        self.assertIn('not filter', result)

    def test_all_of_filter_star(self):
        detection = {
            'selection': {'Image|endswith': 'cmd.exe'},
            'filter_admin': {'User': 'admin'},
            'filter_system': {'User': 'SYSTEM'},
            'condition': 'selection and not all of filter*',
        }
        result = _expand_wildcard_selections(detection['condition'], detection)
        self.assertIn('filter_admin', result)
        self.assertIn('filter_system', result)
        self.assertIn(' and ', result)

    def test_no_match_leaves_unchanged(self):
        detection = {
            'selection': {'Image': 'cmd.exe'},
            'condition': '1 of nonexistent*',
        }
        result = _expand_wildcard_selections(detection['condition'], detection)
        self.assertEqual(result, '1 of nonexistent*')


class TestParseConditionWithWildcards(unittest.TestCase):
    """Integration test: parse_condition with wildcard selections."""

    def test_1_of_selection_star_produces_or(self):
        detection = {
            'sel_cmd': {'CommandLine|contains': 'whoami'},
            'sel_proc': {'Image|endswith': 'cmd.exe'},
            'condition': '1 of sel*',
        }
        field_map = {
            'CommandLine': "'Command Line'",
            'Image': "'Process Name'",
        }
        result = parse_condition(detection['condition'], detection, field_map)
        self.assertIn("'Command Line' like '*whoami*'", result)
        self.assertIn("'Process Name' like '*cmd.exe'", result)
        self.assertIn(' or ', result)

    def test_all_of_filter_star_produces_and(self):
        detection = {
            'selection': {'CommandLine|contains': 'net'},
            'filter_user': {'User': 'admin'},
            'filter_path': {'Image': 'C:\\Windows\\system32\\net.exe'},
            'condition': 'selection and not all of filter*',
        }
        field_map = {'CommandLine': "'Command Line'", 'User': 'User', 'Image': "'Process Name'"}
        result = parse_condition(detection['condition'], detection, field_map)
        self.assertIn('not', result)
        self.assertIn("User = 'admin'", result)


class TestContainsAll(unittest.TestCase):
    """Test the |contains|all chained modifier."""

    def test_contains_all_produces_and(self):
        selection = {
            'CommandLine|contains|all': ['net', 'user', '/add'],
        }
        field_map = {'CommandLine': "'Command Line'"}
        result = parse_selection(selection, field_map)
        self.assertIn("'Command Line' like '*net*'", result)
        self.assertIn("'Command Line' like '*user*'", result)
        self.assertIn("'Command Line' like '*/add*'", result)
        # Must be AND, not OR
        self.assertIn(' and ', result)
        self.assertNotIn(' or ', result)

    def test_contains_all_single_value(self):
        selection = {'CommandLine|contains|all': 'single'}
        field_map = {'CommandLine': "'Command Line'"}
        result = parse_selection(selection, field_map)
        self.assertIn("'Command Line' like '*single*'", result)

    def test_plain_contains_still_uses_or(self):
        selection = {'CommandLine|contains': ['net', 'user']}
        field_map = {'CommandLine': "'Command Line'"}
        result = parse_selection(selection, field_map)
        self.assertIn(' or ', result)


class TestUnknownLogsourceWarning(unittest.TestCase):
    """Test that unknown logsources emit a stderr warning."""

    def test_unknown_logsource_warns_on_stderr(self):
        rule_content = {
            'title': 'Test Unknown Logsource',
            'id': 'test-unknown-ls',
            'logsource': {'product': 'zscaler', 'service': 'proxy'},
            'detection': {
                'selection': {'action': 'blocked'},
                'condition': 'selection',
            },
            'level': 'medium',
        }
        # Write temp YAML
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(rule_content, f)
            tmp_path = f.name

        try:
            field_map, logsource_map = load_config()
            # Capture stderr
            old_stderr = sys.stderr
            sys.stderr = captured = io.StringIO()
            result = convert_rule(tmp_path, field_map, logsource_map)
            sys.stderr = old_stderr

            warning_output = captured.getvalue()
            self.assertIn('WARN', warning_output)
            self.assertIn('zscaler_proxy', warning_output)
            # Should still produce a result (graceful fallback)
            self.assertIsNotNone(result)
            self.assertTrue(result.get('logsource_fallback', False))
        finally:
            os.unlink(tmp_path)


class TestCategorySpecificLogsourceMapping(unittest.TestCase):
    """Ensure category mappings override generic service mappings when available."""

    def test_category_mapping_takes_precedence_over_service_mapping(self):
        rule_content = {
            'title': 'Network Connection Rule',
            'id': 'test-network-ls',
            'logsource': {'product': 'windows', 'service': 'sysmon', 'category': 'network_connection'},
            'detection': {
                'selection': {'DestinationPort': 445},
                'condition': 'selection',
            },
            'level': 'high',
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(rule_content, f)
            tmp_path = f.name

        try:
            field_map, logsource_map = load_config()
            result = convert_rule(tmp_path, field_map, logsource_map)

            self.assertIsNotNone(result)
            self.assertIn("SOC Sysmon Network Logs", result["query"])
            self.assertLess(
                result["query"].index("SOC Sysmon Network Logs"),
                result["query"].index("SOC Windows Sysmon Logs"),
            )
        finally:
            os.unlink(tmp_path)


class TestCountGracefulDegradation(unittest.TestCase):
    """Test that count()/timeframe conditions degrade gracefully."""

    def test_count_condition_emits_base_filter(self):
        rule_content = {
            'title': 'Test Count Rule',
            'id': 'test-count',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {
                'selection': {'EventID': 4625},
                'condition': 'selection | count(TargetUserName) by SourceIp > 5',
                'timeframe': '5m',
            },
            'level': 'high',
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(rule_content, f)
            tmp_path = f.name

        try:
            field_map, logsource_map = load_config()
            old_stderr = sys.stderr
            sys.stderr = io.StringIO()
            result = convert_rule(tmp_path, field_map, logsource_map)
            sys.stderr = old_stderr

            self.assertIsNotNone(result)
            self.assertTrue(result.get('requires_aggregation', False))
            # Base filter should still be present
            self.assertIn("'Event ID' = 4625", result['query'])
        finally:
            os.unlink(tmp_path)


class TestNotFilter(unittest.TestCase):
    """Test negation of filter selections."""

    def test_not_filter(self):
        detection = {
            'selection': {'CommandLine|contains': 'whoami'},
            'filter': {'User': 'SYSTEM'},
            'condition': 'selection and not filter',
        }
        field_map = {'CommandLine': "'Command Line'", 'User': 'User'}
        result = parse_condition(detection['condition'], detection, field_map)
        self.assertIn("'Command Line' like '*whoami*'", result)
        self.assertIn('not', result)
        self.assertIn("User = 'SYSTEM'", result)

    def test_null_selection_maps_to_missing_field_check(self):
        selection = {'Referer': None}
        field_map = {'Referer': "'Referrer'"}
        result = parse_selection(selection, field_map)
        self.assertEqual(result, "not ('Referrer' like '*')")


class TestOutputPathResolution(unittest.TestCase):
    """Test stable output path routing for generated queries."""

    def test_reuses_existing_sigma_id_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_root = os.path.join(tmpdir, 'queries')
            rules_root = os.path.join(tmpdir, 'rules')
            os.makedirs(output_root, exist_ok=True)
            os.makedirs(os.path.join(rules_root, 'windows'), exist_ok=True)

            existing_path = os.path.join(output_root, 'legacy_name.json')
            with open(existing_path, 'w') as f:
                json.dump({'sigma_id': 'same-id', 'query': build_log_source_filter(['OCI Audit Logs'])}, f)

            index = load_existing_query_index(output_root)
            result = {'title': 'A Brand New Title', 'sigma_id': 'same-id'}
            rule_path = os.path.join(rules_root, 'windows', 'sample.yaml')

            rel_path = resolve_output_relative_path(
                rule_path=rule_path,
                result=result,
                output_root=output_root,
                rules_root=rules_root,
                existing_index=index,
            )
            self.assertEqual(rel_path, 'legacy_name.json')

    def test_routes_browser_attack_rules_to_apps(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_root = os.path.join(tmpdir, 'queries')
            rules_root = os.path.join(tmpdir, 'rules')
            rule_dir = os.path.join(rules_root, 'web', 'browser_attacks')
            os.makedirs(rule_dir, exist_ok=True)

            result = {'title': 'APM: XSS', 'sigma_id': 'apm-browser-xss-001'}
            rule_path = os.path.join(rule_dir, 'apm_xss_attack_detection.yaml')

            rel_path = resolve_output_relative_path(
                rule_path=rule_path,
                result=result,
                output_root=output_root,
                rules_root=rules_root,
                existing_index={},
            )
            self.assertEqual(rel_path, 'apps/apm_xss_attack_detection.json')


class TestPreservedMetadata(unittest.TestCase):
    """Test preservation of curated JSON metadata during regeneration."""

    def test_preserves_pipeline_and_custom_fields(self):
        result = {
            'title': 'Sample Rule',
            'query': "'Log Source' = 'OCI Audit Logs' and (Status = 'Failure')",
            'tags': ['attack.initial_access'],
            'mitre_attack': {'tactics': ['initial_access'], 'techniques': ['T1078']},
        }
        existing = {
            'query': "'Log Source' = 'OCI Audit Logs' and (Status = 'Failure') | stats count as Hits by User",
            'tags': ['browser_attack'],
            'mitre_attack': {'tactics': ['execution'], 'techniques': ['T1059.007']},
            'threat_intel': {'family': 'example'},
        }

        merged = merge_preserved_fields(result, existing)
        self.assertIn('| stats count as Hits by User', merged['query'])
        self.assertIn('browser_attack', merged['tags'])
        self.assertIn('execution', merged['mitre_attack']['tactics'])
        self.assertEqual(merged['threat_intel']['family'], 'example')

    def test_does_not_preserve_ephemeral_generation_flags(self):
        result = {
            'title': 'Sample Rule',
            'query': "'Log Source' = 'OCI Audit Logs'",
            'sigma_id': 'sample-001',
        }
        existing = {
            'title': 'Sample Rule',
            'query': "'Log Source' = 'OCI Audit Logs'",
            'sigma_id': 'sample-001',
            'logsource_fallback': True,
            'requires_aggregation': True,
            'threat_intel': {'family': 'example'},
        }

        merged = merge_preserved_fields(result, existing)
        self.assertNotIn('logsource_fallback', merged)
        self.assertNotIn('requires_aggregation', merged)
        self.assertEqual(merged['threat_intel']['family'], 'example')


if __name__ == '__main__':
    unittest.main()
