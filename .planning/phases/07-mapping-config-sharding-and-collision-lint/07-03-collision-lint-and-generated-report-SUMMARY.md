# Plan 07-03 Summary — Collision Lint and Generated Report

**Status:** Complete (executed inline)
**Date:** 2026-05-17
**Requirements covered:** MAP-03

## What shipped

- Added deterministic collision report generation via `build_collision_report()`.
- Added `scripts/lint_mapping_collisions.py` with write and `--check` modes.
- Added generated `queries/mapping_collisions.json`.
- Marked `mapping_collisions.json` as a generated query artifact.

## Verification

| Gate | Result |
|------|--------|
| `python3 scripts/lint_mapping_collisions.py --check` | passed |
| `python3 -m pytest scripts/test_mapping_loader.py -q` | passed |

## Notes

- Known many-to-one reasons are present, including `lossy_mapping_collision:Computer+DeviceId→Entity`.
- The user-name fan-out to `User Name` is represented with pairwise structured reasons.

