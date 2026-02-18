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
    load_config,
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


if __name__ == '__main__':
    unittest.main()
