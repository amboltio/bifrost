import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getErrorMessage, useGetUserEffectiveAccessQuery } from "@/lib/store";
import { ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";

type EffectiveAccessProps = {
	userId: string;
};

type Selection = {
	provider: string;
	model: string;
	projectId: string;
};

export default function EffectiveAccess({ userId }: EffectiveAccessProps) {
	const [provider, setProvider] = useState("");
	const [model, setModel] = useState("");
	const [projectId, setProjectId] = useState("");
	const [selection, setSelection] = useState<Selection | null>(null);
	const { currentData, isFetching, error } = useGetUserEffectiveAccessQuery(
		{
			userId,
			provider: selection?.provider,
			model: selection?.model || undefined,
			projectId: selection?.projectId || undefined,
		},
		{ skip: !selection },
	);

	const checkAccess = (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		const normalizedProvider = provider.trim().toLowerCase();
		if (!normalizedProvider) return;
		setSelection({ provider: normalizedProvider, model: model.trim(), projectId: projectId.trim() });
	};

	const projectUnavailable = currentData?.project_resolved === false;
	const allowed = currentData?.allowed === true;

	return (
		<section
			className="border-border space-y-4 border-t pt-4"
			aria-labelledby="effective-access-heading"
			data-testid="effective-access-panel"
		>
			<div>
				<h3 id="effective-access-heading" className="text-sm font-semibold">
					Effective access
				</h3>
				<p className="text-muted-foreground mt-1 text-xs">Check what this user can reach for a provider, model, and project.</p>
			</div>

			<form onSubmit={checkAccess} className="space-y-3">
				<div className="grid gap-3 sm:grid-cols-2">
					<div className="space-y-1.5">
						<label htmlFor={`effective-provider-${userId}`} className="text-xs font-medium">
							Provider
						</label>
						<Input
							id={`effective-provider-${userId}`}
							value={provider}
							onChange={(event) => setProvider(event.target.value)}
							placeholder="openai"
							required
							maxLength={128}
							data-testid="effective-access-provider"
						/>
					</div>
					<div className="space-y-1.5">
						<label htmlFor={`effective-model-${userId}`} className="text-xs font-medium">
							Model <span className="text-muted-foreground font-normal">(optional)</span>
						</label>
						<Input
							id={`effective-model-${userId}`}
							value={model}
							onChange={(event) => setModel(event.target.value)}
							placeholder="gpt-4o"
							maxLength={256}
							data-testid="effective-access-model"
						/>
					</div>
				</div>
				<div className="space-y-1.5">
					<label htmlFor={`effective-project-${userId}`} className="text-xs font-medium">
						Project ID <span className="text-muted-foreground font-normal">(optional)</span>
					</label>
					<Input
						id={`effective-project-${userId}`}
						value={projectId}
						onChange={(event) => setProjectId(event.target.value)}
						placeholder="project-id"
						maxLength={256}
						data-testid="effective-access-project"
					/>
				</div>
				<Button
					type="submit"
					size="sm"
					disabled={!provider.trim() || isFetching}
					isLoading={isFetching}
					dataTestId="effective-access-check-button"
				>
					Check access
				</Button>
			</form>

			{Boolean(error) && (
				<p className="text-destructive text-xs" role="alert">
					Could not check access: {getErrorMessage(error)}
				</p>
			)}

			{currentData && !error && (
				<div
					className={`border-l-2 p-3 ${allowed && !projectUnavailable ? "border-primary bg-muted/40" : "border-destructive bg-destructive/5"}`}
					role="status"
					aria-live="polite"
					data-testid="effective-access-result"
				>
					<div className="flex items-center gap-2">
						{allowed && !projectUnavailable ? (
							<ShieldCheck className="text-primary h-4 w-4" />
						) : (
							<ShieldX className="text-destructive h-4 w-4" />
						)}
						<span className="text-sm font-semibold">{projectUnavailable ? "Project unavailable" : allowed ? "Allowed" : "Blocked"}</span>
					</div>
					{projectUnavailable ? (
						<p className="text-muted-foreground mt-2 text-xs">This user cannot use the selected project, or it is unavailable.</p>
					) : (
						<div className="mt-3 space-y-2 text-xs">
							{currentData.contributing_profile_ids.length > 0 && (
								<p>
									<span className="text-muted-foreground">Contributing profiles:</span> {currentData.contributing_profile_ids.join(", ")}
								</p>
							)}
							{currentData.denied_profiles.length > 0 && (
								<p>
									<span className="text-muted-foreground">Blocking profiles:</span>{" "}
									{currentData.denied_profiles.map((profile) => profile.id).join(", ")}
								</p>
							)}
							{currentData.allow_all_providers ? (
								<p className="text-muted-foreground">All providers are in scope.</p>
							) : currentData.allowed_providers.length > 0 ? (
								<p>
									<span className="text-muted-foreground">Available providers:</span> {currentData.allowed_providers.join(", ")}
								</p>
							) : null}
							{currentData.allow_all_mcp_tools ? (
								<p className="text-muted-foreground">All MCP tools are in scope.</p>
							) : currentData.allowed_mcp_tools.length > 0 ? (
								<p>
									<span className="text-muted-foreground">Available MCP tools:</span> {currentData.allowed_mcp_tools.join(", ")}
								</p>
							) : null}
						</div>
					)}
				</div>
			)}
		</section>
	);
}