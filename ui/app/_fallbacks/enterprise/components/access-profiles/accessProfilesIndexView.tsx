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