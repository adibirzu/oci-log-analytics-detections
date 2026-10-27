#!/usr/bin/env python3
"""Stable unittest entrypoint for dashboard contract cases."""

import os
import sys
import unittest

if __package__:
    from scripts.dashboard_contract_cases_a import DashboardContractCasesA
    from scripts.dashboard_contract_cases_b import DashboardContractCasesB
    from scripts.dashboard_contract_cases_c import DashboardContractCasesC
else:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from dashboard_contract_cases_a import DashboardContractCasesA
    from dashboard_contract_cases_b import DashboardContractCasesB
    from dashboard_contract_cases_c import DashboardContractCasesC


class TestDashboardContract(
    DashboardContractCasesA, DashboardContractCasesB, DashboardContractCasesC, unittest.TestCase
):
    """Validate dashboard widgets and saved-search visualization metadata."""

    synthetic_validation_error = (
        "opc-request-id: abc123 ocid1.tenancy.oc1..secret "
        "203.0.113.44 profile DEFAULT namespace captenancy"
    )


if __name__ == "__main__":
    unittest.main()
