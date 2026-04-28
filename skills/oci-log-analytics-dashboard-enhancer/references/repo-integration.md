# Repo integration

Use this file when the task needs concrete edits in this repository.

## Canonical content surfaces

- `rules/**`: source-of-truth Sigma or YAML detections
- `queries/*.json`: generated top-level OCI detections
- `queries/apps/*.json`: mixed source-derived browser detections and curated app analytics
- `queries/hunting/*.json`: curated hunting and advanced analytics
- `scripts/deploy_dashboard.py`: dashboard inventory, widget placement, embedded saved searches

Do not add new workflow logic under `logandetectionqueries/` or `logandetectionrules/`; those directories are legacy and empty.

## Query artifact shape

Curated query JSON files in this repo typically contain:

- `title`
- `description`
- `query`
- `level`
- `tags`
- `logsource`
- `falsepositives`

Keep naming and metadata aligned with adjacent files in the same folder.

## Dashboard deployment shape

`scripts/deploy_dashboard.py` currently:

- Defines dashboard inventory in `DASHBOARDS`
- Embeds saved searches directly into dashboard import JSON
- Uses two-column placement with `width=6`, `height=4`
- Applies common dashboard parameters for log-group compartment, entity, and time
- Builds saved searches with `visualizationType: "table"` and empty `visualizationOptions`

Implications:

- Query-only changes are enough if the widget can stay a table.
- Real chart upgrades usually require extending `build_saved_search_json()` and the widget schema so each widget can declare a visualization type and options.
- If you change the saved-search payload shape, keep `scopeFilters`, `parametersMap`, and the embedded saved-search references intact.

## Geographic dashboard note

The current geographic-health content uses explicit latitude and longitude fields in checked-in query JSON. Inspect those existing files before replacing them with `geostats`; the repo may already depend on a specific output shape.

## Validation path

Use the normal contributor loop after changes:

- `python3 scripts/deploy_dashboard.py --dry-run`
- `python3 -m unittest discover -s scripts -p 'test_*.py'`
- `python3 -m compileall scripts`

If the task touched `rules/**` or generated outputs, also run:

- `python3 scripts/convert_sigma.py`
- `python3 scripts/generate_catalog.py`
- `python3 scripts/export_for_multicloud.py --manifest-only`
