# Stack Research

**Domain:** SIEM query conversion web workbench for OCI Log Analytics QL
**Researched:** 2026-05-17
**Confidence:** HIGH for repo boundary and OCI docs; MEDIUM for final frontend target until Phase 12 selects the sibling app explicitly

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Python | Existing repo runtime | Generate converter artifacts, docs-derived reference catalogs, schemas, and examples | This repository already owns Sentinel/Sigma conversion and generated query artifacts. Keep conversion logic here instead of rewriting it in the browser. |
| JSON Schema | Draft selected in Phase 12 | Contract between this repo and the sibling frontend | A versioned schema prevents UI drift when conversion patterns, examples, or command metadata change. |
| Next.js | 15.2.4 in `../LoganSecurityDashboardv0` | Sibling frontend route or app shell | The existing sibling security dashboard already has Next.js, React, Tailwind, Radix, and Lucide available. Prefer extending that surface unless Phase 12 documents a stronger reason for a new sibling app. |
| React | 19 in `../LoganSecurityDashboardv0` | Interactive editor, output, menu, and explanation panels | Fits the current sibling frontend stack and supports a dense operator workbench UI. |
| TypeScript | 5 in `../LoganSecurityDashboardv0` | Typed artifact consumption and UI state | Required for reliable schema-driven frontend integration. |
| Tailwind CSS | 3.4.17 in `../LoganSecurityDashboardv0` | Responsive workbench layout | Matches the sibling UI conventions and keeps styling local to the frontend app. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| Zod | 3.24.1 in sibling app | Runtime validation of imported artifact JSON | Use at the frontend boundary to fail clearly when generated artifacts drift. |
| Radix UI | Existing sibling dependency set | Menus, tabs, dialogs, scroll areas, tooltips | Use for command reference menu, source-language selector, warnings, and copy/export controls. |
| Lucide React | 0.454.0 in sibling app | Workbench action icons | Use for copy, download, search, warning, split-view, and validation controls. |
| Code editor component | Decide in Phase 15 | Source and Logan QL editors | Use CodeMirror 6 or Monaco only after assessing bundle size and syntax-highlighting needs. |
| Playwright | Add to sibling app if absent | Browser acceptance tests | Use for desktop/mobile layout, copy/export flow, command menu, and example conversion checks. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `scripts/generate_logan_reference_catalog.py` | Proposed producer for OCI command menu metadata | Should read official OCI Log Analytics pages and write a generated JSON artifact with source URLs and `retrieved_at`. |
| `scripts/generate_cross_ql_patterns.py` | Proposed producer for source-language mapping patterns | Should emit support level, mapping explanation, examples, and unsupported/lossy warnings. |
| `python3 -m pytest` | Producer-side schema and example validation | Tests stay in this repo for generated artifacts. |
| `pnpm build`, `pnpm lint`, `pnpm typecheck` | Sibling frontend gates | Run in the selected sibling app during implementation phases. |

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Extend `../LoganSecurityDashboardv0` | Create a new sibling app such as `logan-ql-workbench` | Use a new app only if the existing dashboard navigation or deployment contract would make a dense converter UI awkward. |
| Generated static JSON artifacts | Live docs scraping in the browser | Use browser-side fetching only for a non-production demo. Production should avoid depending on docs availability at runtime. |
| Reuse Python converters | Reimplement conversion logic in TypeScript | Only reimplement small UI-only formatting helpers. Actual Sigma/Sentinel conversion semantics belong in this repo. |
| Schema-driven examples | Freeform prompt/LLM conversion | Use LLM assistance only as future optional explanation, never as the source of committed detections without deterministic validation. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| Hand-coded OCI command menu | It will drift from Oracle documentation and creates false confidence. | Generated catalog with source URL, retrieval timestamp, and tests. |
| Browser-stored OCI credentials | A public converter UI should not need tenancy credentials. | Static examples and offline conversion artifacts; live OCI validation remains explicit and profile-driven. |
| Silent lossy rewrites | Security detections become misleading if unsupported semantics disappear. | Structured warnings with support levels and alternatives. |
| Duplicated Sentinel/Sigma converters in the UI | Divergence from live-validated artifacts would be inevitable. | Shared artifact/API contract backed by this repo's converters. |

## Sources

- Oracle OCI Log Analytics query search documentation - search syntax, pipe model, and saved-search/dashboard context.
- Oracle OCI Log Analytics command reference - command menu source of truth.
- `../LoganSecurityDashboardv0/package.json` - existing sibling frontend stack.
- User-provided comparable tools: sigconverter.io and Uncoder.io.

---
*Stack research for: v3.0 Logan QL Conversion Workbench*
*Researched: 2026-05-17*
