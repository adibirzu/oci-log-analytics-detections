#!/usr/bin/env python3
"""Compatibility entrypoint for Sentinel conversion workflow tests."""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel_workflow_tests.backlog_status import (  # noqa: F401
    TestSentinelConversionWorkflowBacklogStatus,
)
from sentinel_workflow_tests.commands import TestSentinelConversionWorkflowCommands  # noqa: F401


if __name__ == "__main__":
    unittest.main()
