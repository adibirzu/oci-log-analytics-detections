# OCI Log Analytics Detections Webapp

`webapp/` contains the long-term Forge frontend for this repository. It is a Next.js App Router application that converts Sigma/YAML, Microsoft Sentinel KQL, Splunk SPL, Elastic/Lucene/KQL, and OCI Log Analytics QL passthrough examples into OCI Log Analytics QL by using this repo's generated artifacts and backend conversion script.

## Scope

- **Only exposed product surface:** `/forge`
- **API surface:** `/api/forge/session`, `/api/forge/convert`, and `/api/health`
- **Artifact source:** parent repository root by default, or `LOGAN_DETECTIONS_REPO` when explicitly set
- **Public repository link:** `https://github.com/adibirzu/oci-log-analytics-detections`
- **Production host target:** `https://convert.octodemo.cloud`

The app does not duplicate query generation. It reads:

- `queries/logan_ql_reference_catalog.json`
- `queries/cross_ql_mapping_patterns.json`
- `queries/conversion_examples.json`
- `queries/catalog.json`
- `queries/dashboard_inventory.json`
- `test_data/manifest.json`
- `scripts/logan_workbench_convert.py`

## Local Development

```bash
cd webapp
pnpm install --frozen-lockfile
pnpm dev
```

The local app reads artifacts from `..` when `LOGAN_DETECTIONS_REPO` is unset. Set `LOGAN_DETECTIONS_REPO=/absolute/path/to/oci-log-analytics-detections` only when running from a different working directory.

Verification:

```bash
cd webapp
pnpm typecheck
pnpm lint
pnpm build
```

## Security Posture

- Middleware redirects HTML requests to `/forge` and returns `404` for non-allowed routes.
- The conversion API uses strict Zod request/response validation, CSRF tokens, origin checks, request size limits, rate limiting, and production-safe error messages.
- Production backend writes must go through `LOGAN_FORGE_BACKEND_URL`, intended to be an API Gateway endpoint protected by WAF. Without that secret, the app uses the bundled read-only converter script.
- No tenancy names, OCIDs, IP addresses, or secret values are rendered in the UI. Deployment scripts read environment variables and local OCI profiles at execution time only.

## Deployment

OKE deployment material lives in `deploy/oke/`. Build from `webapp/` after staging a minimal runtime artifact bundle:

```bash
cd webapp
./deploy/oke/stage-detections-runtime.sh
docker build -t "$FORGE_IMAGE" .
docker push "$FORGE_IMAGE"
envsubst < deploy/oke/forge-frontend.yaml | kubectl apply -f -
```

See `deploy/oke/README.md` for the existing Octo APM load-balancer and DNS wiring flow.
