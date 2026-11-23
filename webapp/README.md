# OCI Log Analytics Detections Webapp

`webapp/` contains the long-term Forge frontend for this repository. It is a Next.js App Router application that converts Sigma/YAML, Microsoft Sentinel KQL, Splunk SPL, Elastic/Lucene/KQL, and OCI Log Analytics QL passthrough examples into OCI Log Analytics QL by using this repo's generated artifacts and backend conversion script.

## Scope

- **Only exposed product surface:** `/forge`
- **API surface:** `/api/forge/session`, `/api/forge/convert`, `/api/forge/artifacts`, `/api/forge/deployment-package`, and `/api/health`
- **Deployment package:** `/api/forge/deployment-package` builds a read-only Resource Manager zip under the [deployment package contract](../docs/DEPLOYMENT.md#package-source-inventory-and-executable-closure); it never accepts OCI credentials or tenancy inputs.
- **Artifact source:** parent repository root by default, or `LOGAN_DETECTIONS_REPO` when explicitly set
- **Public repository link:** `https://github.com/adibirzu/oci-log-analytics-detections`
- **Production host target:** supplied at deployment time; no customer hostname is committed
- **Static host target:** GitHub Pages can serve a limited read-only build when `NEXT_PUBLIC_FORGE_STATIC_EXPORT=1`

The app does not duplicate query generation. It reads:

- `queries/logan_ql_reference_catalog.json`
- `queries/cross_ql_mapping_patterns.json`
- `queries/conversion_examples.json`
- `queries/ql_conversion_capability_matrix.json`
- `queries/catalog.json`
- `queries/dashboard_inventory.json`
- `queries/siem_log_examples.json`
- `test_data/manifest.json`
- `scripts/logan_workbench_convert.py`

## Local Development

```bash
cd webapp
pnpm install --frozen-lockfile
pnpm dev
```

The local app reads artifacts from `..` when `LOGAN_DETECTIONS_REPO` is unset. Set `LOGAN_DETECTIONS_REPO=/absolute/path/to/oci-log-analytics-detections` only when running from a different working directory.

## OCI Resource Manager Deployment

The **Deploy to OCI** workspace keeps privileged operations in the OCI Console. It explains the package scope, requires an acknowledgement before opening Resource Manager, and lets a dynamic Forge deployment download `oci-log-analytics-deployment.zip`. Package source selection and exclusions follow the deployment package contract linked above.

GitHub Pages is read-only and has no API route, so static Forge exports link to the reviewed `stack/` source instead. See [../stack/README.md](../stack/README.md) for the customer deployment sequence.

For customer migration sequencing, security use cases, source onboarding, and the Log-Analytics-first SIEM-forwarding model, see the repository [Migration and Security Guide](../docs/MIGRATION_AND_SECURITY_GUIDE.md). The [documentation hub](../docs/README.md) indexes the companion deployment, threat-hunting, Sentinel-conversion, and operating guides.

Verification:

```bash
cd webapp
pnpm typecheck
pnpm lint
pnpm test:unit:coverage
pnpm build
pnpm e2e
```

## GitHub Pages Static Build

GitHub Pages hosts read-only builds of Forge and the Detection Rules Explorer. Static mode does not include the Next.js API routes, CSRF session endpoint, Python converter, or backend deployment actions. It supports bundled example conversions, raw OCI Logan QL passthrough, and the read-only Log Samples parser workspace in the browser.

```bash
cd webapp
NEXT_PUBLIC_FORGE_BASE_PATH=/oci-log-analytics-detections pnpm build:pages
```

The static export is written to `webapp/out`. The Forge GitHub Pages workflow uploads that directory. At a repository subpath, the Explorer is at `/oci-log-analytics-detections/explorer/`. Pages activation and deployment require the repository owner's approval.

### Detection Rules Explorer preview

Run these commands from the repository root with Python 3.11 or newer.

```bash
preview="$(mktemp -d)"
python3 scripts/build_detection_explorer.py --output "$preview"
python3 -m http.server 8000 --bind 127.0.0.1 --directory "$preview"
```

Open `http://localhost:8000/`. The same Explorer files work under a repository subpath. The browser fetches one generated catalog and runs all search and filtering locally. The Pages build also derives a public Forge catalog that omits companion telemetry examples containing private address literals.

The build indexes base detections, promoted Sentinel conversions, app analytics, and the companion hunts listed in the [cross-SIEM catalog](../config/cross_siem_detection_catalog.json). Each entry copies its OCL string from the original query JSON after checking that file against the content manifest. The six cross-SIEM detection families remain visible in the relevant hunts.

The [mapping ledger](../config/detection_explorer_mappings.json) links each vendor rule to its official file at a pinned revision. Exact links match the core detection condition. Related links share documented behavior and can differ in telemetry, thresholds, or filters. OCI-specific entries use OCI-native telemetry. Unmapped entries have no verified link for that vendor. Repository SPL examples appear separately with their own label. Coverage measures the ATT&CK tags recorded in the catalog.

For offline mapping audits, unpack the official source archives for the two revisions in the ledger into one directory. Run the builder with `--upstream-root` pointing there to verify each upstream path, ID, title, and SHA-256 against its source. Use the repository Python requirements for the audit.

```bash
python3 -m pytest -q scripts/test_detection_explorer.py
PLAYWRIGHT_BASE_URL=http://127.0.0.1:1 pnpm --dir webapp e2e detection-explorer.spec.ts
```

The browser spec starts a static server on an ephemeral port for both the root and repository-subpath cases. Set `EXPLORER_SCREENSHOTS` to a directory outside the checkout to capture desktop and mobile images.

## Security Posture

- Middleware redirects HTML requests to `/forge` and returns `404` for non-allowed routes.
- The conversion API uses strict Zod request/response validation, CSRF tokens, origin checks, request size limits, rate limiting, and production-safe error messages.
- `FORGE_TRUSTED_INTERNAL_HOSTS` can list OKE service DNS names that are allowed as internal origins while still requiring a valid `X-Logan-Forge-CSRF` token.
- `FORGE_TRUSTED_PROXY_HOPS` makes `X-Forwarded-For` trust **opt-in**. It is the number of trusted reverse-proxy hops (e.g. OCI LB + ingress) that sit in front of the app and append to `X-Forwarded-For`; the rate limiter then keys on the entry that many positions from the **right** (the address your proxy inserted), so a client cannot bypass the limit by spoofing leftmost values. **When unset (or `0`) the app does NOT trust `X-Forwarded-For` at all and every request shares one rate-limit bucket (fail-closed).** Set it to the real proxy depth of the deployment — and ensure the app is only reachable through those proxies — to get per-client limiting.
- Production backend writes must go through `LOGAN_FORGE_BACKEND_URL`, intended to be an API Gateway endpoint protected by WAF. Without that secret, the app uses the bundled read-only converter script.
- No tenancy names, OCIDs, IP addresses, or secret values are rendered in the UI. Deployment scripts read environment variables and local OCI profiles at execution time only.
- Log Samples exports contain explicit `<PLACEHOLDER>` values and reserved documentation addresses; they are not copied from a live tenancy.

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
