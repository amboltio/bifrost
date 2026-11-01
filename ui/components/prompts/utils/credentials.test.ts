import { describe, expect, it } from "vitest";
import { buildPromptHeaders } from "./credentials";

describe("playground caller credentials", () => {
	it("refuses a stored virtual-key selection without an explicit secret", () => {
		expect(() => buildPromptHeaders({ apiKeyId: "virtual-key:vk-1" })).toThrow(/enter.*virtual key/i);
	});
	it("uses only the explicitly supplied secret, never a selected key ID", () => {
		expect(buildPromptHeaders({ apiKeyId: "virtual-key:vk-1", virtualKeySecret: "sk-bf-caller-secret" })).toEqual({
			"Content-Type": "application/json",
			"x-bf-vk": "sk-bf-caller-secret",
		});
	});
	it("requires fresh input for legacy persisted secret selections", () => {
		expect(() => buildPromptHeaders({ apiKeyId: "sk-bf-legacy-persisted-secret" })).toThrow(/enter.*virtual key/i);
	});
	it("preserves provider-key selection and manually supplied credential headers", () => {
		expect(buildPromptHeaders({ apiKeyId: "provider-key-id" })).toEqual({
			"Content-Type": "application/json",
			"x-bf-api-key-id": "provider-key-id",
		});
		expect(buildPromptHeaders({ apiKeyId: "__auto__", customHeaders: { "x-bf-vk": "caller-secret" } })["x-bf-vk"]).toBe("caller-secret");
	});
});