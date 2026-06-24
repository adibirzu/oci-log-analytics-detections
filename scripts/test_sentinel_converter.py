#!/usr/bin/env python3
"""Compatibility collector for Microsoft Sentinel converter tests."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinel_converter_tests.yaml_normalization import TestSentinelYamlNormalization
from sentinel_converter_tests.kql_conversion import (
    TestSentinelKqlConversionAdvanced,
    TestSentinelKqlConversionCore,
)
from sentinel_converter_tests.artifacts_dashboards import TestSentinelArtifactsAndDashboards

__all__ = [
    "TestSentinelYamlNormalization",
    "TestSentinelKqlConversionAdvanced",
    "TestSentinelKqlConversionCore",
    "TestSentinelArtifactsAndDashboards",
]
