# Plan 08-02 Summary — Release Advisory and Artifact Contract

**Status:** Complete (executed inline)
**Date:** 2026-05-17
**Requirements covered:** PRI-03

## What shipped

- `scripts/release_checklist.py` now reads the priority artifact and prints a non-blocking advisory.
- `queries/sentinel_backlog_priority.json` is classified as a generated query artifact in `scripts/query_artifacts.py`.
- Added a regression test for advisory rendering.

## Verification

| Gate | Result |
|------|--------|
| `python3 scripts/release_checklist.py --skip-tests` | passed |
| Release advisory | `Sentinel backlog: 4443 ranked; top blocker: field_mapping:SubjectDomainName` |

## Notes

- The advisory is included in release evidence JSON under `advisories.sentinel_backlog`.

