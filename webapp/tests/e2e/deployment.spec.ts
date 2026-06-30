import { expect, test } from "@playwright/test"

test.describe("OCI Resource Manager deployment workspace", () => {
  test("explains scope, gates the console handoff, and offers the package", async ({ page }) => {
    await page.goto("/forge?view=deployment")

    await expect(page.getByTestId("deployment-workspace")).toBeVisible()
    await expect(page.getByRole("heading", { name: "Deploy detection content to OCI Log Analytics" })).toBeVisible()
    await expect(page.getByText("Forge never receives your OCI credentials.")).toBeVisible()
    await expect(page.getByText("Detection query artifacts")).toBeVisible()

    const openResourceManager = page.getByRole("link", { name: "Open OCI Resource Manager" })
    await expect(openResourceManager).toHaveAttribute("href", "https://cloud.oracle.com/resourcemanager/stacks")
    await expect(openResourceManager).toHaveAttribute("aria-disabled", "true")

    await page.getByRole("checkbox").check()
    await expect(openResourceManager).not.toHaveAttribute("aria-disabled", "true")

    const packageDownload = page.waitForEvent("download")
    await page.getByRole("link", { name: "Download ORM package" }).click()
    await expect((await packageDownload).suggestedFilename()).toBe("oci-log-analytics-deployment.zip")
  })
})
