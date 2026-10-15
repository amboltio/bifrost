import FullPageLoader from "@/components/fullPageLoader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
	getErrorMessage,
	useCreateAccessProfileMutation,
	useDeleteAccessProfileMutation,
	useGetAccessProfilesQuery,
	useUpdateAccessProfileMutation,
} from "@/lib/store";
import type { AccessProfileProviderConfig } from "@/lib/store/apis/governanceApi";
import { KeyRound, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

const splitValues = (value: string) =>
	value
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);

export default function AccessProfilesIndexView() {
	const { data, isLoading, error } = useGetAccessProfilesQuery({ limit: 100 });
	const [createProfile, { isLoading: isCreating }] = useCreateAccessProfileMutation();
	const [updateProfile, { isLoading: isUpdating }] = useUpdateAccessProfileMutation();
	const [deleteProfile] = useDeleteAccessProfileMutation();
	const [selectedID, setSelectedID] = useState<string | null>(null);
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const [enabled, setEnabled] = useState(true);
	const [allowAllProviders, setAllowAllProviders] = useState(false);
	const [providers, setProviders] = useState("");
	const [models, setModels] = useState("");
	const [mcpTools, setMcpTools] = useState("");
	const [providerConfigs, setProviderConfigs] = useState<AccessProfileProviderConfig[]>([]);
	const selected = data?.access_profiles.find((profile) => profile.id === selectedID);

	useEffect(() => {
		if (!selected) return;
		setName(selected.name);
		setDescription(selected.description);
		setEnabled(selected.enabled);
		setAllowAllProviders(selected.allow_all_providers);
		setProviders(selected.allowed_providers.join(", "));
		setModels(selected.allowed_models.join(", "));
		setMcpTools(selected.allowed_mcp_tools.join(", "));
		setProviderConfigs(
			(selected.provider_configs ?? []).map((config) => ({
				...config,
				allowed_models: config.allowed_models ?? [],
				blacklisted_models: config.blacklisted_models ?? [],
				key_ids: config.key_ids ?? [],
			})),
		);
	}, [selected]);

	const reset = () => {
		setSelectedID(null);
		setName("");
		setDescription("");
		setEnabled(true);
		setAllowAllProviders(false);
		setProviders("");
		setModels("");
		setMcpTools("");
		setProviderConfigs([]);
	};

	const submit = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		const body = {
			name,
			description,
			enabled,
			allow_all_providers: allowAllProviders,
			allowed_providers: splitValues(providers),
			allowed_models: splitValues(models),
			provider_configs: providerConfigs,
			allowed_mcp_tools: splitValues(mcpTools),
		};
		try {
			if (selectedID) {
				await updateProfile({ id: selectedID, data: body }).unwrap();
				toast.success("Access profile updated");
			} else {
				await createProfile(body).unwrap();
				toast.success("Access profile created");
			}
			reset();
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	const remove = async (id: string) => {
		if (!window.confirm("Delete this access profile?")) return;
		try {
			await deleteProfile(id).unwrap();
			if (selectedID === id) reset();
			toast.success("Access profile deleted");
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	if (isLoading) return <FullPageLoader />;
	if (error) return <div className="text-destructive p-6 text-sm">Failed to load access profiles: {getErrorMessage(error)}</div>;

	return (
		<div className="mx-auto w-full max-w-6xl space-y-6 p-6" data-testid="access-profiles-governance-view">
			<div className="flex items-center justify-between gap-4">
				<div className="flex items-center gap-2">
					<KeyRound className="text-primary h-5 w-5" />
					<div>
						<h1 className="text-foreground text-xl font-semibold">Access profiles</h1>
						<p className="text-muted-foreground mt-1 text-sm">Reuse provider, model, and MCP access policies across users.</p>
					</div>
				</div>
				<Button type="button" onClick={reset} dataTestId="access-profile-create-button">
					<Plus className="h-4 w-4" />
					New profile
				</Button>
			</div>

			<div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_28rem]">
				<div className="border-border divide-border divide-y rounded-sm border">
					{data?.access_profiles.map((profile) => (
						<div key={profile.id} className="flex items-start justify-between gap-4 p-4" data-testid={`access-profile-row-${profile.id}`}>
							<div className="min-w-0">
								<div className="text-sm font-medium">{profile.name}</div>
								<div className="text-muted-foreground mt-1 text-xs">{profile.description || "No description"}</div>
								<div className="mt-2 flex flex-wrap gap-1 text-xs">
									<span className="bg-muted rounded px-2 py-0.5">{profile.enabled ? "Enabled" : "Disabled"}</span>
									<span className="bg-muted rounded px-2 py-0.5">
										{profile.allow_all_providers ? "All providers" : `${profile.allowed_providers.length} providers`}
									</span>
									<span className="bg-muted rounded px-2 py-0.5">{profile.allowed_models.length} models</span>
								</div>
							</div>
							<div className="flex gap-1">
								<Button
									type="button"
									variant="ghost"
									size="icon"
									onClick={() => setSelectedID(profile.id)}
									dataTestId={`access-profile-edit-${profile.id}`}
									aria-label={`Edit ${profile.name}`}
								>
									<Pencil className="h-4 w-4" />
								</Button>
								<Button
									type="button"
									variant="ghost"
									size="icon"
									onClick={() => remove(profile.id)}
									dataTestId={`access-profile-delete-${profile.id}`}
									aria-label={`Delete ${profile.name}`}
								>
									<Trash2 className="text-destructive h-4 w-4" />
								</Button>
							</div>
						</div>
					))}
					{!data?.access_profiles.length && (
						<div className="text-muted-foreground p-8 text-center text-sm">No access profiles have been created.</div>
					)}
				</div>

				<form onSubmit={submit} className="border-border h-fit space-y-4 rounded-sm border p-4" data-testid="access-profile-form">
					<h2 className="text-sm font-semibold">{selectedID ? "Edit access profile" : "Create access profile"}</h2>
					<div className="space-y-2">
						<label htmlFor="access-profile-name" className="text-sm font-medium">
							Name
						</label>
						<Input id="access-profile-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={255} />
					</div>
					<div className="space-y-2">
						<label htmlFor="access-profile-description" className="text-sm font-medium">
							Description
						</label>
						<Input
							id="access-profile-description"
							value={description}
							onChange={(event) => setDescription(event.target.value)}
							maxLength={500}
						/>
					</div>
					<label className="flex items-center gap-2 text-sm">
						<input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} /> Enabled
					</label>
					<label className="flex items-center gap-2 text-sm">
						<input type="checkbox" checked={allowAllProviders} onChange={(event) => setAllowAllProviders(event.target.checked)} /> Allow all
						providers
					</label>
					<div className="space-y-2">
						<label htmlFor="access-profile-providers" className="text-sm font-medium">
							Allowed providers
						</label>
						<Input
							id="access-profile-providers"
							placeholder="openai, anthropic"
							value={providers}
							onChange={(event) => setProviders(event.target.value)}
						/>
					</div>
					<div className="space-y-2">
						<label htmlFor="access-profile-models" className="text-sm font-medium">
							Allowed models
						</label>
						<Input
							id="access-profile-models"
							placeholder="gpt-4.1, claude"
							value={models}
							onChange={(event) => setModels(event.target.value)}
						/>
					</div>
					<div className="space-y-3 border-t pt-4">
						<div className="flex items-center justify-between gap-2">
							<div>
								<h3 className="text-sm font-medium">Provider-specific rules</h3>
								<p className="text-muted-foreground mt-1 text-xs">An empty key ID list denies every key for that provider.</p>
							</div>
							<Button
								type="button"
								variant="outline"
								size="sm"
								onClick={() =>
									setProviderConfigs((current) => [
										...current,
										{
											provider_name: "",
											all_models_allowed: false,
											allowed_models: [],
											blacklisted_models: [],
											key_ids: [],
										},
									])
								}
								dataTestId="access-profile-provider-config-add"
							>
								<Plus className="h-4 w-4" />
								Add rule
							</Button>
						</div>
						{providerConfigs.map((config, index) => {
							const updateConfig = (patch: Partial<AccessProfileProviderConfig>) =>
								setProviderConfigs((current) =>
									current.map((entry, entryIndex) => (entryIndex === index ? { ...entry, ...patch } : entry)),
								);
							return (
								<div key={`${config.provider_name}-${index}`} className="border-border space-y-3 rounded-sm border p-3">
									<div className="flex items-center gap-2">
										<Input
											aria-label={`Provider name ${index + 1}`}
											placeholder="openai"
											value={config.provider_name}
											onChange={(event) => updateConfig({ provider_name: event.target.value })}
											data-testid={`access-profile-provider-name-${index}`}
										/>
										<Button
											type="button"
											variant="ghost"
											size="icon"
											onClick={() => setProviderConfigs((current) => current.filter((_, entryIndex) => entryIndex !== index))}
											aria-label={`Remove ${config.provider_name || `provider rule ${index + 1}`}`}
											dataTestId={`access-profile-provider-remove-${index}`}
										>
											<Trash2 className="h-4 w-4" />
										</Button>
									</div>
									<label className="flex items-center gap-2 text-xs">
										<input
											type="checkbox"
											checked={config.all_models_allowed}
											onChange={(event) => updateConfig({ all_models_allowed: event.target.checked })}
											data-testid={`access-profile-provider-all-models-${index}`}
										/>
										Allow all models for this provider
									</label>
									<Input
										aria-label={`Allowed models for ${config.provider_name || `rule ${index + 1}`}`}
										placeholder="Allowed models: gpt-4.1, gpt-4o"
										value={config.allowed_models.join(", ")}
										disabled={config.all_models_allowed}
										onChange={(event) => updateConfig({ allowed_models: splitValues(event.target.value) })}
										data-testid={`access-profile-provider-allowed-models-${index}`}
									/>
									<Input
										aria-label={`Blocked models for ${config.provider_name || `rule ${index + 1}`}`}
										placeholder="Blocked models: legacy-model"
										value={config.blacklisted_models.join(", ")}
										onChange={(event) => updateConfig({ blacklisted_models: splitValues(event.target.value) })}
										data-testid={`access-profile-provider-blocked-models-${index}`}
									/>
									<Input
										aria-label={`Allowed provider key IDs for ${config.provider_name || `rule ${index + 1}`}`}
										placeholder="Key IDs: key-123, key-456"
										value={config.key_ids.join(", ")}
										onChange={(event) => updateConfig({ key_ids: splitValues(event.target.value) })}
										data-testid={`access-profile-provider-key-ids-${index}`}
									/>
								</div>
							);
						})}
					</div>
					<div className="space-y-2">
						<label htmlFor="access-profile-mcp-tools" className="text-sm font-medium">
							Allowed MCP tools
						</label>
						<Input
							id="access-profile-mcp-tools"
							placeholder="server-tool"
							value={mcpTools}
							onChange={(event) => setMcpTools(event.target.value)}
						/>
					</div>
					<div className="flex gap-2">
						<Button
							type="submit"
							isLoading={isCreating || isUpdating}
							disabled={isCreating || isUpdating}
							dataTestId="access-profile-save-button"
						>
							{selectedID ? "Save changes" : "Create"}
						</Button>
						{selectedID && (
							<Button type="button" variant="outline" onClick={reset}>
								Cancel
							</Button>
						)}
					</div>
				</form>
			</div>
		</div>
	);
}