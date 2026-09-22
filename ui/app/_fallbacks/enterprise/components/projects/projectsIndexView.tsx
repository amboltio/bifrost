import FullPageLoader from "@/components/fullPageLoader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
	getErrorMessage,
	useCreateProjectMutation,
	useDeleteProjectMutation,
	useGetProjectsQuery,
	useUpdateProjectMutation,
} from "@/lib/store";
import { FolderKanban, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

const splitValues = (value: string) =>
	value
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);

export default function ProjectsIndexView() {
	const { data, isLoading, error } = useGetProjectsQuery({ limit: 100 });
	const [createProject, { isLoading: isCreating }] = useCreateProjectMutation();
	const [updateProject, { isLoading: isUpdating }] = useUpdateProjectMutation();
	const [deleteProject] = useDeleteProjectMutation();
	const [selectedID, setSelectedID] = useState<string | null>(null);
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");
	const [enabled, setEnabled] = useState(true);
	const [expiresAt, setExpiresAt] = useState("");
	const [accessRule, setAccessRule] = useState("union");
	const [membershipMode, setMembershipMode] = useState("explicit");
	const [accountingMode, setAccountingMode] = useState("both");
	const [splitPolicy, setSplitPolicy] = useState("none");
	const [allowAllProviders, setAllowAllProviders] = useState(false);
	const [providers, setProviders] = useState("");
	const [models, setModels] = useState("");
	const selected = data?.projects.find((project) => project.id === selectedID);

	useEffect(() => {
		if (!selected) return;
		setName(selected.name);
		setDescription(selected.description);
		setEnabled(selected.enabled);
		setExpiresAt(selected.expires_at?.slice(0, 16) ?? "");
		setAccessRule(selected.access_rule);
		setMembershipMode(selected.membership_mode);
		setAccountingMode(selected.accounting_mode);
		setSplitPolicy(selected.split_policy);
		setAllowAllProviders(selected.allow_all_providers);
		setProviders(selected.allowed_providers.join(", "));
		setModels(selected.allowed_models.join(", "));
	}, [selected]);

	const reset = () => {
		setSelectedID(null);
		setName("");
		setDescription("");
		setEnabled(true);
		setExpiresAt("");
		setAccessRule("union");
		setMembershipMode("explicit");
		setAccountingMode("both");
		setSplitPolicy("none");
		setAllowAllProviders(false);
		setProviders("");
		setModels("");
	};

	const submit = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		const body = {
			name,
			description,
			enabled,
			expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
			access_rule: accessRule,
			membership_mode: membershipMode,
			accounting_mode: accountingMode,
			split_policy: splitPolicy,
			allow_all_providers: allowAllProviders,
			allowed_providers: splitValues(providers),
			allowed_models: splitValues(models),
		};
		try {
			if (selectedID) {
				await updateProject({ id: selectedID, data: body }).unwrap();
				toast.success("Project updated");
			} else {
				await createProject(body).unwrap();
				toast.success("Project created");
			}
			reset();
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	const remove = async (id: string) => {
		if (!window.confirm("Delete this project?")) return;
		try {
			await deleteProject(id).unwrap();
			if (selectedID === id) reset();
			toast.success("Project deleted");
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	if (isLoading) return <FullPageLoader />;
	if (error) return <div className="text-destructive p-6 text-sm">Failed to load projects: {getErrorMessage(error)}</div>;

	return (
		<div className="mx-auto w-full max-w-6xl space-y-6 p-6" data-testid="projects-governance-view">
			<div className="flex items-center justify-between gap-4">
				<div className="flex items-center gap-2">
					<FolderKanban className="text-primary h-5 w-5" />
					<div>
						<h1 className="text-foreground text-xl font-semibold">Projects</h1>
						<p className="text-muted-foreground mt-1 text-sm">Define request-scoped access, membership, and accounting rules.</p>
					</div>
				</div>
				<Button type="button" onClick={reset} dataTestId="project-create-button">
					<Plus className="h-4 w-4" />
					New project
				</Button>
			</div>
			<div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_30rem]">
				<div className="border-border divide-border divide-y rounded-sm border">
					{data?.projects.map((project) => (
						<div key={project.id} className="flex items-start justify-between gap-4 p-4" data-testid={`project-row-${project.id}`}>
							<div className="min-w-0">
								<div className="text-sm font-medium">{project.name}</div>
								<div className="text-muted-foreground mt-1 text-xs">{project.description || "No description"}</div>
								<div className="mt-2 flex flex-wrap gap-1 text-xs">
									<span className="bg-muted rounded px-2 py-0.5">{project.enabled ? "Enabled" : "Disabled"}</span>
									<span className="bg-muted rounded px-2 py-0.5">{project.access_rule}</span>
									<span className="bg-muted rounded px-2 py-0.5">{project.accounting_mode}</span>
								</div>
							</div>
							<div className="flex gap-1">
								<Button
									type="button"
									variant="ghost"
									size="icon"
									onClick={() => setSelectedID(project.id)}
									dataTestId={`project-edit-${project.id}`}
									aria-label={`Edit ${project.name}`}
								>
									<Pencil className="h-4 w-4" />
								</Button>
								<Button
									type="button"
									variant="ghost"
									size="icon"
									onClick={() => remove(project.id)}
									dataTestId={`project-delete-${project.id}`}
									aria-label={`Delete ${project.name}`}
								>
									<Trash2 className="text-destructive h-4 w-4" />
								</Button>
							</div>
						</div>
					))}
					{!data?.projects.length && <div className="text-muted-foreground p-8 text-center text-sm">No projects have been created.</div>}
				</div>
				<form onSubmit={submit} className="border-border h-fit space-y-4 rounded-sm border p-4" data-testid="project-form">
					<h2 className="text-sm font-semibold">{selectedID ? "Edit project" : "Create project"}</h2>
					<div className="space-y-2">
						<label htmlFor="project-name" className="text-sm font-medium">
							Name
						</label>
						<Input id="project-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={255} />
					</div>
					<div className="space-y-2">
						<label htmlFor="project-description" className="text-sm font-medium">
							Description
						</label>
						<Input id="project-description" value={description} onChange={(event) => setDescription(event.target.value)} maxLength={500} />
					</div>
					<label className="flex items-center gap-2 text-sm">
						<input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} /> Enabled
					</label>
					<div className="grid grid-cols-2 gap-3">
						<label className="space-y-2 text-sm">
							Access rule
							<select
								className="border-input bg-background h-9 w-full rounded-sm border px-2"
								value={accessRule}
								onChange={(event) => setAccessRule(event.target.value)}
							>
								<option value="union">Union</option>
								<option value="intersect">Intersect</option>
							</select>
						</label>
						<label className="space-y-2 text-sm">
							Membership
							<select
								className="border-input bg-background h-9 w-full rounded-sm border px-2"
								value={membershipMode}
								onChange={(event) => setMembershipMode(event.target.value)}
							>
								<option value="explicit">Explicit</option>
								<option value="open">Open</option>
							</select>
						</label>
						<label className="space-y-2 text-sm">
							Accounting
							<select
								className="border-input bg-background h-9 w-full rounded-sm border px-2"
								value={accountingMode}
								onChange={(event) => setAccountingMode(event.target.value)}
							>
								<option value="both">Both</option>
								<option value="project_only">Project only</option>
								<option value="principal_only">Principal only</option>
							</select>
						</label>
						<label className="space-y-2 text-sm">
							Split policy
							<select
								className="border-input bg-background h-9 w-full rounded-sm border px-2"
								value={splitPolicy}
								onChange={(event) => setSplitPolicy(event.target.value)}
							>
								<option value="none">Shared</option>
								<option value="equal">Equal</option>
							</select>
						</label>
					</div>
					<div className="space-y-2">
						<label htmlFor="project-expires-at" className="text-sm font-medium">
							Expires at
						</label>
						<Input id="project-expires-at" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
					</div>
					<label className="flex items-center gap-2 text-sm">
						<input type="checkbox" checked={allowAllProviders} onChange={(event) => setAllowAllProviders(event.target.checked)} /> Allow all
						providers
					</label>
					<div className="space-y-2">
						<label htmlFor="project-providers" className="text-sm font-medium">
							Allowed providers
						</label>
						<Input
							id="project-providers"
							placeholder="openai, anthropic"
							value={providers}
							onChange={(event) => setProviders(event.target.value)}
						/>
					</div>
					<div className="space-y-2">
						<label htmlFor="project-models" className="text-sm font-medium">
							Allowed models
						</label>
						<Input id="project-models" placeholder="gpt-4.1, claude" value={models} onChange={(event) => setModels(event.target.value)} />
					</div>
					<div className="flex gap-2">
						<Button type="submit" isLoading={isCreating || isUpdating} disabled={isCreating || isUpdating} dataTestId="project-save-button">
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