import { execFileSync } from "node:child_process"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { createServer } from "node:http"
import type { Server } from "node:http"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { expect, test } from "@playwright/test"

const root = fileURLToPath(new URL("../../../", import.meta.url))
const mount = "/oci-log-analytics-detections/explorer/"
const types = new Map([
  ["", "text/html; charset=utf-8"],
  ["explorer.css", "text/css; charset=utf-8"],
  ["explorer.js", "text/javascript; charset=utf-8"],
  ["catalog.json", "application/json; charset=utf-8"],
])
let directory: string
let server: Server | undefined
let origin: string

test.beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), "detection-explorer-"))
  execFileSync("python3", ["scripts/build_detection_explorer.py", "--output", directory], { cwd: root })
  server = createServer(async (request, response) => {
    const path = new URL(request.url ?? "/", "http://localhost").pathname
    const asset = path.startsWith(mount) ? path.slice(mount.length) : path.slice(1)
    const contentType = types.get(asset)
    if (!contentType) {
      response.writeHead(404).end()
      return
    }
    response.writeHead(200, { "content-type": contentType }).end(await readFile(join(directory, asset || "index.html")))
  })
  await new Promise<void>((resolve, reject) => server?.once("error", reject).listen(0, "127.0.0.1", resolve))
  const address = server.address()
  if (!address || typeof address === "string") throw new Error("No preview address")
  origin = `http://127.0.0.1:${address.port}`
})

test.afterAll(async () => {
  if (server) await new Promise<void>((resolve, reject) => server?.close((error) => error ? reject(error) : resolve()))
  if (directory) await rm(directory, { recursive: true, force: true })
})

for (const [label, viewport, path] of [
  ["desktop", { width: 1440, height: 1000 }, mount],
  ["mobile", { width: 390, height: 844 }, "/"],
] as const) {
  test(`${label} catalog, filter state, mappings and exact clipboard text`, async ({ page, context, request }) => {
    await page.setViewportSize(viewport)
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin })
    const errors: string[] = []
    page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()) })
    page.on("pageerror", (error) => errors.push(error.message))
    page.on("requestfailed", (req) => errors.push(req.url()))
    page.on("response", (response) => { if (response.status() >= 400) errors.push(response.url()) })
    await page.goto(origin + path)
    await expect(page.getByRole("heading", { name: "Detection Rules Explorer" })).toBeVisible()
    await expect(page.getByText(/1,197 OCI rules/)).toBeVisible()
    await expect(page.getByRole("status").filter({ hasText: "1,216" })).toBeVisible()
    const screenshots = process.env.EXPLORER_SCREENSHOTS
    if (screenshots) await page.screenshot({ path: join(screenshots, `${label}-catalog.png`) })
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width)

    if (label === "mobile") await page.getByRole("button", { name: "Filters" }).click()
    await page.getByLabel("Filter by severity").selectOption("high")
    await page.getByLabel("Filter by tactic").selectOption({ label: "Execution" })
    await page.getByLabel("Filter by technique").selectOption("T1059.001")
    await page.getByLabel("Filter by platform").selectOption("windows")
    await expect(page).toHaveURL(/severity=high/)
    await expect(page.getByRole("status").filter({ hasText: /[1-9].*results/ })).toBeVisible()
    await page.reload()
    if (label === "mobile") await page.getByRole("button", { name: "Filters" }).click()
    await expect(page.getByLabel("Filter by technique")).toHaveValue("T1059.001")
    await expect(page.getByLabel("Filter by platform")).toHaveValue("windows")
    await page.getByRole("button", { name: "Clear filters" }).click()

    await page.keyboard.press("/")
    const search = page.getByRole("searchbox")
    await expect(search).toBeFocused()
    await search.fill("clickfix clipboard powershell")
    await page.getByLabel("Filter by Elastic mapping").selectOption("related")
    await page.getByLabel("Filter by Splunk mapping").selectOption("related")
    await page.getByRole("button", { name: "ClickFix: Clipboard PowerShell Execution", exact: true }).click()
    const trigger = page.getByRole("button", { name: "ClickFix: Clipboard PowerShell Execution", exact: true })
    await page.keyboard.press("Escape")
    await expect(trigger).toBeFocused()
    await page.getByLabel("Filter by log source").selectOption("Windows Sysmon Events")
    await page.getByLabel("Filter by category").selectOption("hunting")
    await expect(page.getByRole("status").filter({ hasText: /^1 result$/ })).toBeVisible()
    await trigger.click()
    const dialog = page.getByRole("dialog")
    await expect(dialog.getByRole("heading", { name: "OCI Log Analytics query" })).toBeVisible()
    await expect(dialog.getByRole("heading", { name: "Elastic Detection Rules" })).toBeVisible()
    await expect(dialog.getByRole("heading", { name: "Splunk Security Content" })).toBeVisible()
    await expect(dialog.getByRole("heading", { name: "Provenance" })).toBeVisible()
    await expect(dialog.getByRole("link", { name: /official source/i })).toHaveCount(2)
    if (screenshots) {
      if (label === "mobile") await page.setViewportSize({ ...viewport, height: 1130 })
      await page.screenshot({ path: join(screenshots, `${label}-detail.png`) })
      if (label === "mobile") await page.setViewportSize(viewport)
    }
    const baseRepoResponse = await request.get(origin + path + "catalog.json")
    const data: { rules: Array<{ id: string, query: string }> } = await baseRepoResponse.json()
    const expected = data.rules.find(({ id }) => id === "queries/hunting/clickfix_clipboard_powershell_execution.json")
    expect(expected).toBeDefined()
    await dialog.getByRole("button", { name: "Copy query" }).click()
    await expect(dialog.getByRole("button", { name: "Copied" })).toBeVisible()
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(expected?.query)
    const detailURL = page.url()
    await page.reload()
    await expect(dialog).toBeVisible()
    await page.keyboard.press("Escape")
    await expect(dialog).toBeHidden()
    if (label === "mobile") await page.getByRole("button", { name: "Filters" }).click()
    await page.getByRole("button", { name: "Clear filters" }).click()
    await page.getByRole("button", { name: "Elastic", exact: true }).click()
    await expect(page.getByRole("button", { name: /view .*mapped OCI/i }).first()).toBeVisible()
    await page.getByRole("button", { name: "Splunk", exact: true }).click()
    await expect(page.getByRole("button", { name: /view .*mapped OCI/i }).first()).toBeVisible()
    await page.goto(detailURL)
    await expect(dialog).toBeVisible()
    await page.keyboard.press("Escape")
    await page.getByRole("button", { name: "Switch to dark theme" }).click()
    await expect(page.getByRole("button", { name: "Switch to light theme" })).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width)
    expect(errors).toEqual([])
  })
}
