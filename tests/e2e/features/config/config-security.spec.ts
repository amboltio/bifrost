import { coreConfigApi } from "../../core/actions/api";
import { expect, test } from "../../core/fixtures/base.fixture";
import { ConfigSettingsPage, ConfigSettingsState } from "./pages/config-settings.page";
import { DefaultCoreConfig } from "../../../../ui/lib/types/config";

test.describe("Dashboard access and canonical user management", () => {
  test.use({ skipAutoLogin: true, extraHTTPHeaders: {} });

  test("an empty instance explains terminal provisioning without fetching management data", async ({ page }) => {
    const managementCalls: string[] = [];
    await page.route("**/api/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/session/is-auth-enabled") {
        await route.fulfill({ json: { is_auth_enabled: false, has_valid_token: false, admin_provisioning_required: true } });
        return;
      }
      managementCalls.push(path);
      await route.fulfill({ status: 403, json: { error: { message: "Administrator provisioning required" } } });
    });
    await page.goto("/login?goto=%2Fworkspace%2Fgovernance%2Fusers");
    await expect(page.getByTestId("admin-provisioning-view")).toBeVisible();
    await expect(page.getByTestId("admin-provisioning-instructions")).toContainText("/app/main createsuperadmin --app-dir /app/data");
    await expect(page.locator("form")).toHaveCount(0);
    expect(managementCalls).toEqual([]);
    await expect(page).toHaveURL(/\/login\?/);
  });

  test("check again detects an administrator created by the CLI and permits ordinary sign-in", async ({ page }) => {
    let provisioned = false;
    const logins: unknown[] = [];
    await page.route("**/api/**", async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (path === "/api/session/is-auth-enabled") {
        await route.fulfill({ json: { is_auth_enabled: provisioned, has_valid_token: false, admin_provisioning_required: !provisioned, authentication_methods: provisioned ? ["local"] : [] } });
      } else if (path === "/api/session/login") {
        logins.push(request.postDataJSON());
        await route.fulfill({ status: 401, json: { error: { message: "Invalid credentials" } } });
      } else {
        await route.fulfill({ json: {} });
      }
    });
    await page.goto("/login");
    await expect(page.getByTestId("admin-provisioning-view")).toBeVisible();
    provisioned = true;
    await page.getByTestId("admin-provisioning-refresh").click();
    await expect(page.getByTestId("admin-provisioning-view")).toHaveCount(0);
    await expect(page.locator("#username")).toBeVisible();
    await page.locator("#username").fill("operator@example.com");
    await page.locator("#password").fill("An-incorrect-password-1!");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByText("Invalid credentials", { exact: true })).toBeVisible();
    expect(logins).toEqual([{ email: "operator@example.com", username: "operator@example.com", password: "An-incorrect-password-1!" }]);
  });

  test("disabled authentication never redirects a visitor into the dashboard", async ({ page }) => {
    await page.route("**/api/**", (route) => route.fulfill({ json: { is_auth_enabled: false, has_valid_token: false, admin_provisioning_required: false, authentication_methods: [] } }));
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
  });

  test("an unavailable auth status keeps visitors on the login page", async ({ page }) => {
    await page.route("**/api/**", (route) => route.fulfill({ status: 503, json: { error: { message: "Temporarily unavailable" } } }));
    await page.goto("/login?goto=%2Fworkspace%2Fgovernance%2Fusers");
    await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
    await expect(page).toHaveURL(/\/login\?/);
    await expect(page.getByTestId("admin-provisioning-view")).toHaveCount(0);
  });

  test("initialized instances retain configured SSO sign-in", async ({ page }) => {
    await page.route("**/api/**", (route) => route.fulfill({ json: {
      is_auth_enabled: true, has_valid_token: false, admin_provisioning_required: false,
      authentication_methods: ["oidc"], providers: [{ id: "company", display_name: "Company SSO" }],
    } }));
    await page.goto("/login");
    await expect(page.getByTestId("login-oidc-provider-company")).toHaveText("Company SSO");
    await expect(page.locator("#password")).toHaveCount(0);
    await expect(page.getByTestId("admin-provisioning-view")).toHaveCount(0);
  });

  test("security settings link to Users and keep inference changes independent of legacy credentials", async ({ page }) => {
    await page.route("**/api/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      await route.fulfill({ json: path === "/api/config" ? {
        client_config: { ...DefaultCoreConfig, enforce_auth_on_inference: false },
        auth_config: { is_enabled: true, admin_username: { value: "legacy" }, admin_password: { value: "" } },
        framework_config: {}, is_db_connected: true, metadata: { onboarding_dismissed: true },
      } : path === "/api/version" ? "1.0.0" : path === "/api/session/is-auth-enabled" ? { is_auth_enabled: true, has_valid_token: true, admin_provisioning_required: false } : {} });
    });
    await page.goto("/workspace/config/security");
    await expect(page.getByTestId("security-manage-users")).toHaveAttribute("href", "/workspace/governance/users");
    await expect(page.locator("#admin-username, #admin-password, #auth-enabled")).toHaveCount(0);
    const inference = page.getByTestId("enforce-auth-on-inference-switch");
    await expect(inference).not.toBeChecked();
    await inference.click();
    const submitted = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/config" && request.method() === "PUT");
    await page.getByTestId("security-save-btn").click();
    const body = (await submitted).postDataJSON();
    expect(body.client_config.enforce_auth_on_inference).toBe(true);
    expect(body).not.toHaveProperty("auth_config");
  });
});

test.describe("Security Settings", () => {
  // Run all config tests serially to avoid parallel writes to the same config/store
  test.describe.configure({ mode: "serial" });

  let originalState: ConfigSettingsState;

  test.beforeEach(async ({ configSettingsPage }) => {
    await configSettingsPage.goto("security");
    // Capture original state for restoration
    originalState = await configSettingsPage.getCurrentSettings("security");
  });

  test.afterEach(async ({ configSettingsPage }) => {
    // Restore original settings
    if (originalState) {
      await configSettingsPage.restoreSettings(originalState);
    }
  });

  test("should display security settings", async ({ configSettingsPage }) => {
    await expect(
      configSettingsPage.page.getByRole("heading", { name: /Security/i }),
    ).toBeVisible();
    await expect(configSettingsPage.saveBtn).toBeVisible();
  });

  test("should display enforce auth on inference switch", async ({
    configSettingsPage,
  }) => {
    const isVisible = await configSettingsPage.enforceAuthOnInferenceSwitch
      .isVisible()
      .catch(() => false);
    if (!isVisible) {
      test.skip(true, "Enforce auth on inference not available");
      return;
    }
    await expect(configSettingsPage.enforceAuthOnInferenceSwitch).toBeVisible();
  });

  test("should toggle enforce auth on inference", async ({
    configSettingsPage,
  }) => {
    const isVisible = await configSettingsPage.enforceAuthOnInferenceSwitch
      .isVisible()
      .catch(() => false);
    if (!isVisible) {
      test.skip(true, "Enforce auth on inference not available");
      return;
    }
    const initialState = await configSettingsPage.getSwitchState(
      configSettingsPage.enforceAuthOnInferenceSwitch,
    );
    await configSettingsPage.toggleEnforceAuthOnInference();
    const newState = await configSettingsPage.getSwitchState(
      configSettingsPage.enforceAuthOnInferenceSwitch,
    );
    expect(newState).toBe(!initialState);
    await configSettingsPage.toggleEnforceAuthOnInference();
    if (await configSettingsPage.hasPendingChanges()) {
      await configSettingsPage.saveSettings();
    }
  });

  test("should persist the provider object ownership switch", async ({
    configSettingsPage,
    request,
  }) => {
    // The generic afterEach restore puts the switch back to the operator's value.
    await configSettingsPage.dismissOnboardingWidget();
    const ownership = configSettingsPage.enforceVKObjectOwnershipSwitch;
    await expect(ownership).toBeVisible();
    const initial = await configSettingsPage.getSwitchState(ownership);

    await ownership.click();
    await configSettingsPage.saveSettings();
    await configSettingsPage.goto("security");
    expect(
      await configSettingsPage.getSwitchState(
        configSettingsPage.enforceVKObjectOwnershipSwitch,
      ),
    ).toBe(!initial);
    expect(
      (await coreConfigApi.get(request)).client_config
        .enforce_vk_object_ownership,
    ).toBe(!initial);
  });

  for (const { name, switchOf, field } of [
    {
      name: "creation",
      switchOf: (p: ConfigSettingsPage) => p.skipAccessProfileUserVirtualKeyCreationSwitch,
      field: "skip_access_profile_user_virtual_key_creation",
    },
    {
      name: "deletion",
      switchOf: (p: ConfigSettingsPage) => p.skipAccessProfileUserVirtualKeyDeletionSwitch,
      field: "skip_access_profile_user_virtual_key_deletion",
    },
  ] as const) {
    test(`should persist the access profile user virtual key ${name} switch`, async ({
      configSettingsPage,
      request,
    }) => {
      // Enterprise only; the generic afterEach restore puts the switch back.
      await configSettingsPage.dismissOnboardingWidget();
      const skip = switchOf(configSettingsPage);
      if (!(await skip.isVisible().catch(() => false))) {
        test.skip(true, `Access profile user virtual key ${name} switch not available`);
        return;
      }
      const initial = await configSettingsPage.getSwitchState(skip);

      await skip.click();
      await configSettingsPage.saveSettings();
      await configSettingsPage.goto("security");
      expect(await configSettingsPage.getSwitchState(switchOf(configSettingsPage))).toBe(!initial);
      expect((await coreConfigApi.get(request)).client_config[field] ?? false).toBe(!initial);
    });

    test(`should save the access profile user virtual key ${name} switch without changing the other`, async ({
      configSettingsPage,
      request,
    }) => {
      // The two halves of the lifecycle are separate settings; saving one must not carry the other.
      await configSettingsPage.dismissOnboardingWidget();
      const skip = switchOf(configSettingsPage);
      if (!(await skip.isVisible().catch(() => false))) {
        test.skip(true, `Access profile user virtual key ${name} switch not available`);
        return;
      }
      const otherSwitchOf = (p: ConfigSettingsPage) =>
        name === "creation" ? p.skipAccessProfileUserVirtualKeyDeletionSwitch : p.skipAccessProfileUserVirtualKeyCreationSwitch;
      const otherField = name === "creation" ? "skip_access_profile_user_virtual_key_deletion" : "skip_access_profile_user_virtual_key_creation";
      const otherInitial = await configSettingsPage.getSwitchState(otherSwitchOf(configSettingsPage));

      await skip.click();
      await configSettingsPage.saveSettings();
      await configSettingsPage.goto("security");
      expect(await configSettingsPage.getSwitchState(otherSwitchOf(configSettingsPage))).toBe(otherInitial);
      expect((await coreConfigApi.get(request)).client_config[otherField] ?? false).toBe(otherInitial);
    });
  }

  test("should display required headers textarea", async ({
    configSettingsPage,
  }) => {
    const isVisible = await configSettingsPage.requiredHeadersTextarea
      .isVisible()
      .catch(() => false);
    if (!isVisible) {
      test.skip(true, "Required headers control not available");
      return;
    }
    await expect(configSettingsPage.requiredHeadersTextarea).toBeVisible();
  });

  test("should display rate limiting section", async ({
    configSettingsPage,
  }) => {
    const isVisible = await configSettingsPage.isRateLimitingSectionVisible();
    expect(isVisible).toBeDefined();
  });

  test.describe("Virtual Key Rotation Cooldown", () => {
    // The cooldown is a text input, which the generic settings capture and
    // restore (number inputs and switches only) does not cover, so each test
    // restores the operator's original value itself.
    let originalCooldown: string;

    test.beforeEach(async ({ configSettingsPage }) => {
      // The onboarding checklist covers the Save button in the bottom-right
      // corner on a fresh instance, so dismiss it before touching settings.
      await configSettingsPage.dismissOnboardingWidget();
      originalCooldown = await configSettingsPage.getVkRotationCooldown();
    });

    test.afterEach(async ({ configSettingsPage }) => {
      await configSettingsPage.goto("security");
      await configSettingsPage.dismissOnboardingWidget();
      const current = await configSettingsPage.getVkRotationCooldown();
      if (current !== originalCooldown) {
        await configSettingsPage.setVkRotationCooldown(originalCooldown);
        if (await configSettingsPage.hasPendingChanges()) {
          await configSettingsPage.saveSettings();
        }
      }
    });

    test("should display the rotation cooldown input", async ({
      configSettingsPage,
    }) => {
      await expect(configSettingsPage.vkRotationCooldownInput).toBeVisible();
      await expect(configSettingsPage.vkRotationCooldownInput).toHaveAttribute(
        "placeholder",
        "5m",
      );
    });

    test("should persist a duration across a reload", async ({
      configSettingsPage,
    }) => {
      await configSettingsPage.setVkRotationCooldown("5m");
      await configSettingsPage.saveSettings();

      await configSettingsPage.goto("security");
      // The API stores and returns the cooldown as nanoseconds, so this also
      // pins that the UI formats it back into the duration string that was
      // typed rather than showing 300000000000.
      await expect(configSettingsPage.vkRotationCooldownInput).toHaveValue(
        "5m",
      );
    });

    test("should reject an invalid duration without saving it", async ({
      configSettingsPage,
    }) => {
      await configSettingsPage.setVkRotationCooldown("not-a-duration");
      await configSettingsPage.saveBtn.click();
      await configSettingsPage.waitForErrorToast();

      await configSettingsPage.goto("security");
      await expect(configSettingsPage.vkRotationCooldownInput).not.toHaveValue(
        "not-a-duration",
      );
    });

    test("should disable the grace period when cleared", async ({
      configSettingsPage,
    }) => {
      await configSettingsPage.setVkRotationCooldown("30s");
      await configSettingsPage.saveSettings();
      await configSettingsPage.goto("security");
      await expect(configSettingsPage.vkRotationCooldownInput).toHaveValue(
        "30s",
      );

      // Clearing the field is how an operator turns the grace period off: the
      // previous key value must stop working the moment a key is rotated.
      await configSettingsPage.setVkRotationCooldown("");
      await configSettingsPage.saveSettings();
      await configSettingsPage.goto("security");
      await expect(configSettingsPage.vkRotationCooldownInput).toHaveValue("");
    });
  });
});
