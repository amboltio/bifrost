export interface PromptCredentials {
	apiKeyId: string;
	virtualKeySecret?: string;
	customHeaders?: Record<string, string>;
}

export function buildPromptHeaders(config: PromptCredentials): Record<string, string> {
	const headers: Record<string, string> = { "Content-Type": "application/json" };
	const needsVirtualKey = config.apiKeyId.startsWith("virtual-key:") || config.apiKeyId.startsWith("sk-bf-");
	if (needsVirtualKey && !config.virtualKeySecret?.trim()) throw new Error("Enter a virtual key secret to run this request.");
	if (config.virtualKeySecret?.trim()) headers["x-bf-vk"] = config.virtualKeySecret.trim();
	else if (config.apiKeyId && config.apiKeyId !== "__auto__") headers["x-bf-api-key-id"] = config.apiKeyId;
	const reserved = new Set(["content-type", "authorization", "x-bf-api-key-id"]);
	for (const [name, value] of Object.entries(config.customHeaders ?? {})) {
		const trimmedName = name.trim();
		const trimmedValue = value.trim();
		if (!trimmedName || !trimmedValue || reserved.has(trimmedName.toLowerCase())) continue;
		if (trimmedName.toLowerCase() === "x-bf-vk" && headers["x-bf-vk"]) continue;
		headers[trimmedName] = trimmedValue;
	}
	return headers;
}