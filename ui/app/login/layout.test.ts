import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("./page", () => ({ default: () => null }));
vi.mock("@/components/themeProvider", () => ({ ThemeProvider: () => null }));
vi.mock("@/lib/hooks/useBranding", () => ({ useBranding: () => ({}) }));
vi.mock("@/lib/store/provider", () => ({ ReduxProvider: () => null }));
vi.mock("@/lib/utils/port", () => ({ getApiBaseUrl: () => "/api" }));
vi.mock("@tanstack/react-router", () => ({
	createFileRoute: () => (options: unknown) => options,
	redirect: (options: unknown) => options,
}));

import { Route } from "./layout";

const load = () =>
	(Route as unknown as { loader: (context: { location: { searchStr: string } }) => Promise<unknown> }).loader({
		location: { searchStr: "?goto=%2Fworkspace%2Fgovernance%2Fusers" },
	});

afterEach(() => vi.unstubAllGlobals());

describe("login access", () => {
	it("shows terminal provisioning while uninitialized even with a stale session", async () => {
		const fetch = vi
			.fn()
			.mockResolvedValue(Response.json({ is_auth_enabled: false, has_valid_token: true, admin_provisioning_required: true }));
		vi.stubGlobal("fetch", fetch);
		await expect(load()).resolves.toEqual({ adminProvisioningRequired: true });
		expect(fetch).toHaveBeenCalledTimes(1);
		expect(fetch.mock.calls[0][0]).toBe("/api/session/is-auth-enabled");
	});

	it.each([false, true])("does not open the dashboard when authentication is disabled (valid session: %s)", async (hasValidToken) => {
		vi.stubGlobal(
			"fetch",
			vi
				.fn()
				.mockResolvedValue(Response.json({ is_auth_enabled: false, has_valid_token: hasValidToken, admin_provisioning_required: false })),
		);
		await expect(load()).resolves.toEqual({ adminProvisioningRequired: false });
	});

	it("keeps normal local and SSO sign-in available without a session", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(Response.json({ is_auth_enabled: true, has_valid_token: false, admin_provisioning_required: false })),
		);
		await expect(load()).resolves.toEqual({ adminProvisioningRequired: false });
	});

	it("keeps the login page when the auth status request fails", async () => {
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));
		await expect(load()).resolves.toEqual({ adminProvisioningRequired: false });
	});

	it("ignores an unsuccessful auth response even if its body claims a valid session", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json({ is_auth_enabled: true, has_valid_token: true }, { status: 503 })));
		await expect(load()).resolves.toEqual({ adminProvisioningRequired: false });
	});

	it("preserves the requested destination for an authenticated session", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(Response.json({ is_auth_enabled: true, has_valid_token: true, admin_provisioning_required: false })),
		);
		await expect(load()).rejects.toEqual({ href: "/workspace/governance/users" });
	});
});