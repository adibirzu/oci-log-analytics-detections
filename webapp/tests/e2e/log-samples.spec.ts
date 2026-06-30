import { expect, test } from "@playwright/test"

test.describe("OCI Log Samples workspace", () => {
  test("browses ten canonical service formats and keeps shareable URL state", async ({ page }) => {
    await page.goto("/forge?view=log-samples")

    await expect(page.getByTestId("log-samples-workspace")).toBeVisible()
    await expect(page.getByRole("heading", { name: "OCI Log Sample Library" })).toBeVisible()
    await expect(page.getByTestId("raw-sample-row")).toHaveCount(10)
    await expect(page.getByTestId("json-output")).toContainText("<TENANCY_OCID>")
    await expect(page.getByTestId("json-output")).toContainText("cloudEventsVersion")

    await page.getByRole("button", { name: /WAF Web application firewall log/ }).click()
    await expect(page).toHaveURL(/sample=waf/)
    await expect(page.getByTestId("json-output")).toContainText("com.oraclecloud.loadbalancer.waf")
    await expect(page.getByRole("link", { name: "Official source" })).toHaveAttribute("href", /docs\.oracle\.com/)
  })

  test("compares normalized detections with native OCI alarm notifications", async ({ page }) => {
    await page.goto("/forge?view=log-samples&tab=detections")

    await expect(page.getByTestId("detection-sample-row")).toHaveCount(10)
    await expect(page.getByTestId("json-output")).toContainText("oci.logan.detection")
    await expect(page.getByTestId("raw-evidence-output")).toContainText("cloudEventsVersion")

    await page.getByRole("button", { name: "Native OCI alarm" }).click()
    await expect(page).toHaveURL(/output=native/)
    await expect(page.getByTestId("json-output")).toContainText("oci_logging_analytics")
    await expect(page.getByTestId("json-output")).toContainText("OK_TO_FIRING")

    await page.getByRole("button", { name: "Web-to-Cloud Correlated Attack Timeline" }).click()
    await expect(page).toHaveURL(/sample=web_to_cloud_attack_timeline/)
    await expect(page.getByTestId("forwarding-paths")).toContainText("Third-party SIEM")
  })

  test("filters samples and downloads JSON and JSONL parser fixtures", async ({ page }) => {
    await page.goto("/forge?view=log-samples")

    await page.getByPlaceholder("Search formats").fill("function")
    await expect(page.getByTestId("raw-sample-row")).toHaveCount(1)
    await expect(page.getByTestId("raw-sample-row").first()).toContainText("Functions")

    const jsonDownload = page.waitForEvent("download")
    await page.getByRole("button", { name: "Download JSON", exact: true }).click()
    await expect((await jsonDownload).suggestedFilename()).toMatch(/^oci-log-raw-.*\.json$/)

    const jsonlDownload = page.waitForEvent("download")
    await page.getByRole("button", { name: "Download JSONL", exact: true }).click()
    await expect((await jsonlDownload).suggestedFilename()).toBe("oci-log-raw-all-services.jsonl")
  })

  test("explains pre-analysis benefits and preserves the forensic caution", async ({ page }) => {
    await page.goto("/forge?view=log-samples&tab=benefits")

    await expect(page.getByRole("heading", { name: "Why analyze in Logan first" })).toBeVisible()
    await expect(page.getByText("Keep raw logs available for forensics, compliance, and detection retuning.")).toBeVisible()
    await expect(page.getByText("No universal native SIEM event")).toBeVisible()
  })

  test("keeps parser controls usable on a mobile viewport", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto("/forge?view=log-samples&tab=detections")

    await expect(page.getByRole("button", { name: "Native OCI alarm" })).toBeVisible()
    await expect(page.getByRole("button", { name: "Normalized SIEM JSON" })).toBeVisible()

    const hasHorizontalPageOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
    )
    expect(hasHorizontalPageOverflow).toBe(false)
  })
})
