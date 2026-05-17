# Plan 07-02 Summary — Field Role Tags and Role Mismatch

**Status:** Complete (executed inline)
**Date:** 2026-05-17
**Requirements covered:** MAP-04

## What shipped

- Every sharded field mapping now carries `target` and `role`.
- Loader validates roles against `subject`, `target`, `initiator`, `resource`, `time`, `hash`, and `network`.
- Loader exposes legacy `mapping["fields"]` plus `mapping["field_roles"]` and `mapping["field_specs"]`.
- Predicate conversion now detects simple field-to-field role mismatches and skips with `role_mismatch:<left>:<right>`.
- Added a Sentinel converter regression for `SubjectUserName == TargetUserName`.

## Verification

| Gate | Result |
|------|--------|
| `python3 -m pytest scripts/test_mapping_loader.py scripts/test_sentinel_converter.py scripts/test_kql/test_operators.py -q` | 70 passed |

## Notes

- Existing literal predicate conversion remains behavior-preserving.
- Role mismatch handling is intentionally conservative and only applies when both sides are known mapped fields.

