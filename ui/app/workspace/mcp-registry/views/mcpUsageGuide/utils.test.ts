import { describe, expect, it } from "vitest";
import { buildMCPHeaders } from "./utils";
import type { VirtualKey } from "@/lib/types/governance";

describe("MCP virtual key snippets", () => {
	it("uses a placeholder even if a legacy response contains a full stored secret", () => {
		const virtualKey = { id: "vk-1", name: "Example", value: "sk-bf-old-secret-never-copy", value_prefix: "sk-bf-old-" } as VirtualKey;
		expect(buildMCPHeaders({ authMethod: "virtual_key", virtualKey })).toEqual({ "x-bf-vk": "<YOUR_VIRTUAL_KEY>" });
	});
});