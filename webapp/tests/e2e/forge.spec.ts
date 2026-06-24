import { expect, test } from "@playwright/test"

type SourceLanguage =
  | "sigma_yaml"
  | "sentinel_kql"
  | "splunk_spl"
  | "elastic_lucene"
  | "elastic_kuery"
  | "elastic_eql"
  | "elastic_esql"
  | "elastic_toml"
  | "osquery_sql"
  | "yara"
  | "oci_logan"

interface ConversionResponse {
  backend: string
  logan_query: string
  metadata: Record<string, unknown>
  support_level: "supported" | "partial" | "lossy" | "unsupported"
}

interface ConversionScenario {
  name: string
  language: SourceLanguage
  sourceQuery: string
  supportLevel: ConversionResponse["support_level"]
  apiFragments: string[]
  uiFragments: string[]
}

const backendScript = "scripts/logan_workbench_convert.py"
const apiPayload = {
  sourceLanguage: "sentinel_kql",
  sourceQuery: 'search in (Perf, Event, Alert) "Contoso" | take 10',
  readOnly: true,
}

const scenarios: ConversionScenario[] = [
  {
    name: "Kusto common operators",
    language: "sentinel_kql",
    sourceQuery: `SecurityEvent
| where TimeGenerated between (ago(1d) .. now())
| where EventID in (4624, 4625)
| extend Outcome = case(EventID == 4625, 'failed', EventID == 4624, 'success', 'other')
| summarize by Computer, Outcome
| sort by Count
| take 20`,
    supportLevel: "supported",
    apiFragments: [
      "Windows Security Events",
      "'Event ID' in ('4624', '4625')",
      "eval Outcome = if('Event ID' = '4625'",
      "stats count as Count by Entity, Outcome",
      "sort -Count",
      "head 20",
    ],
    uiFragments: ["Windows Security Events", "Outcome", "head 20"],
  },
  {
    name: "Kusto search across tables",
    language: "sentinel_kql",
    sourceQuery: 'search in (Perf, Event, Alert) "Contoso" | take 10',
    supportLevel: "supported",
    apiFragments: ["SOC Application Logs", "Windows Event System Logs", "Original Log Content", "head 10"],
    uiFragments: ["SOC Application Logs", "Original Log Content", "head 10"],
  },
  {
    name: "Sigma encoded PowerShell",
    language: "sigma_yaml",
    sourceQuery: String.raw`title: PowerShell Encoded Command
id: demo-sigma-ps-001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001`,
    supportLevel: "supported",
    apiFragments: ["Windows Sysmon Events", "Process Name", "Command Line", "EncodedCommand"],
    uiFragments: ["Windows Sysmon Events", "Process Name", "Command Line"],
  },
  {
    name: "Splunk SPL encoded PowerShell",
    language: "splunk_spl",
    sourceQuery: String.raw`index=windows sourcetype=WinEventLog:Sysmon EventCode=1 Image="*\powershell.exe" CommandLine="* -enc *" | stats count by host User CommandLine | sort -count`,
    supportLevel: "partial",
    apiFragments: ["Windows Sysmon Events", "stats count as count", "Command Line", "sort -count"],
    uiFragments: ["Windows Sysmon Events", "stats count as count", "Command Line"],
  },
  {
    name: "Elastic Lucene encoded PowerShell",
    language: "elastic_lucene",
    sourceQuery: "event.code:1 AND process.name:powershell.exe AND process.command_line:(*enc* OR *EncodedCommand*)",
    supportLevel: "partial",
    apiFragments: ["Windows Sysmon Events", "Process Name", "Command Line", "head 100"],
    uiFragments: ["Windows Sysmon Events", "Process Name", "Command Line"],
  },
  {
    name: "Elastic ES|QL HTTP error rollup",
    language: "elastic_esql",
    sourceQuery:
      "FROM logs-apm*\n| WHERE http.response.status_code >= 500 and service.name is not null\n| STATS errors = count(*) BY service.name\n| SORT errors DESC\n| LIMIT 20",
    supportLevel: "partial",
    apiFragments: ["SOC Application Logs", "'Response Code' >= 500", "stats count as errors", "head 20"],
    uiFragments: ["SOC Application Logs", "Response Code", "head 20"],
  },
  {
    name: "Elastic TOML synthetic threshold",
    language: "elastic_toml",
    sourceQuery:
      '[rule]\ntype = "threshold"\nlanguage = "kuery"\nquery = \'\'\'event.category:authentication and event.outcome:failure\'\'\'\n\n[rule.threshold]\nfield = ["source.ip", "user.name"]\nvalue = 5',
    supportLevel: "lossy",
    apiFragments: ["OCI Audit Logs", "stats count as event_count", "where event_count >= 5"],
    uiFragments: ["OCI Audit Logs", "event_count", "head 100"],
  },
]

test.describe("Forge conversion workbench", () => {
  test("converts multiple ad hoc detections through the backend Python script", async ({ page }) => {
    await page.goto("/forge")

    await expect(page.getByTestId("forge-workbench")).toBeVisible()
    await expect(page.getByTestId("convert-button")).toBeEnabled({ timeout: 15_000 })

    for (const scenario of scenarios) {
      await test.step(scenario.name, async () => {
        await page.getByTestId(`language-${scenario.language}`).click()
        await page.getByTestId("source-query-editor").fill(scenario.sourceQuery)

        const conversionResponse = page.waitForResponse(
          (response) => response.url().includes("/api/forge/convert") && response.request().method() === "POST",
        )
        await page.getByTestId("convert-button").click()

        const response = await conversionResponse
        expect(response.ok()).toBe(true)
        expect(response.headers()["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/)
        const payload = (await response.json()) as ConversionResponse

        expect(payload.backend).toBe("Bundled read-only converter")
        expect(payload.metadata.execution_mode).toBe("bundled_python_script")
        expect(payload.metadata.backend_script).toBe(backendScript)
        expect(payload.support_level).toBe(scenario.supportLevel)
        for (const fragment of scenario.apiFragments) {
          expect(payload.logan_query).toContain(fragment)
        }

        await expect(page.getByTestId("forge-backend")).toContainText("Bundled read-only converter")
        await expect(page.getByTestId("support-level")).toContainText(scenario.supportLevel)
        const outputText = await page.getByTestId("logan-query-output").innerText()
        for (const fragment of scenario.uiFragments) {
          expect(outputText).toContain(fragment)
        }
      })
    }
  })
})

test.describe("Forge conversion API CSRF", () => {
  test("rejects conversion requests without a CSRF token", async ({ request }) => {
    const response = await request.post("/api/forge/convert", { data: apiPayload })

    expect(response.status()).toBe(403)
    expect(response.headers()["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/)
    expect(await response.json()).toEqual({ error: "csrf token is missing or invalid" })
  })

  test("accepts trusted OKE service origins with a valid token", async ({ request }) => {
    const session = await request.get("/api/forge/session")
    expect(session.ok()).toBe(true)
    const { csrfToken } = (await session.json()) as { csrfToken: string }

    const response = await request.post("/api/forge/convert", {
      headers: {
        Origin: "http://logan-forge-lb.logan-forge.svc",
        "X-Logan-Forge-CSRF": csrfToken,
      },
      data: apiPayload,
    })
    const payload = (await response.json()) as ConversionResponse

    expect(response.ok()).toBe(true)
    expect(response.headers()["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/)
    expect(payload.metadata.backend_script).toBe(backendScript)
    expect(payload.logan_query).toContain("SOC Application Logs")
  })

  test("allows same-origin token fallback when an edge proxy drops the CSRF cookie", async ({ baseURL, playwright, request }) => {
    const session = await request.get("/api/forge/session")
    expect(session.ok()).toBe(true)
    const { csrfToken } = (await session.json()) as { csrfToken: string }
    const cookieFreeContext = await playwright.request.newContext({ baseURL })

    try {
      const response = await cookieFreeContext.post("/api/forge/convert", {
        headers: {
          "Sec-Fetch-Site": "same-origin",
          "X-Logan-Forge-CSRF": csrfToken,
        },
        data: apiPayload,
      })
      const payload = (await response.json()) as ConversionResponse

      expect(response.ok()).toBe(true)
      expect(response.headers()["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/)
      expect(payload.metadata.execution_mode).toBe("bundled_python_script")
      expect(payload.logan_query).toContain("Original Log Content")
    } finally {
      await cookieFreeContext.dispose()
    }
  })
})

test.describe("Forge conversion API rate limiting", () => {
  test("cannot be bypassed by spoofing X-Forwarded-For", async ({ request }) => {
    const session = await request.get("/api/forge/session")
    expect(session.ok()).toBe(true)
    const { csrfToken } = (await session.json()) as { csrfToken: string }

    // Simulate one trusted reverse-proxy hop: the proxy appends the real client
    // IP as the RIGHTMOST X-Forwarded-For entry, so it stays constant while the
    // attacker varies the spoofable leftmost entry on every request.
    const trustedClientIp = "198.51.100.77"
    const attempts = 34 // RATE_LIMIT (30) + margin within the 60s window
    const statuses: number[] = []
    for (let index = 0; index < attempts; index += 1) {
      const response = await request.post("/api/forge/convert", {
        headers: {
          "X-Logan-Forge-CSRF": csrfToken,
          "Sec-Fetch-Site": "same-origin",
          "X-Forwarded-For": `203.0.113.${index % 250}, ${trustedClientIp}`,
        },
        // Empty sourceQuery fails schema validation (400) AFTER the rate-limit
        // check increments, so we exercise the limiter without spawning Python.
        data: { sourceLanguage: "sentinel_kql", sourceQuery: "" },
      })
      statuses.push(response.status())
    }

    // With the spoofable leftmost entry varying every request, a naive limiter
    // would never trip; keying on the constant trusted rightmost entry must.
    expect(statuses.filter((status) => status === 429).length).toBeGreaterThan(0)
    // Sanity: the limiter is not trivially always-on — early requests pass.
    expect(statuses[0]).not.toBe(429)
  })
})
