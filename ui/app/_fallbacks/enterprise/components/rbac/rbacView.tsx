import FullPageLoader from "@/components/fullPageLoader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
	getErrorMessage,
	useCreateManagedRoleMutation,
	useDeleteManagedRoleMutation,
	useGetManagedRolesQuery,
	useGetRBACPermissionsQuery,
	useUpdateManagedRoleMutation,
} from "@/lib/store";
import { Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

export default function RBACView() {
	const { data: rolesData, isLoading, error } = useGetManagedRolesQuery();
	const { data: permissionsData } = useGetRBACPermissionsQuery();
	const [createRole, { isLoading: isCreating }] = useCreateManagedRoleMutation();
	const [updateRole, { isLoading: isUpdating }] = useUpdateManagedRoleMutation();
	const [deleteRole] = useDeleteManagedRoleMutation();
	const [selectedID, setSelectedID] = useState<string | null>(null);
	const [name, setName] = useState("");
	const [displayName, setDisplayName] = useState("");
	const [permissions, setPermissions] = useState<string[]>([]);
	const selected = rolesData?.roles.find((role) => role.id === selectedID);

	useEffect(() => {
		if (!selected) return;
		setName(selected.name);
		setDisplayName(selected.display_name);
		setPermissions(selected.permissions);
	}, [selected]);

	const permissionGroups = useMemo(() => {
		const groups = new Map<string, { id: string; operation: string }[]>();
		for (const permission of permissionsData?.permissions ?? []) {
			const existing = groups.get(permission.resource) ?? [];
			existing.push({ id: permission.id, operation: permission.operation });
			groups.set(permission.resource, existing);
		}
		return [...groups.entries()];
	}, [permissionsData]);

	const reset = () => {
		setSelectedID(null);
		setName("");
		setDisplayName("");
		setPermissions([]);
	};

	const submit = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		try {
			if (selectedID) {
				await updateRole({ id: selectedID, data: { display_name: displayName, permissions } }).unwrap();
				toast.success("Role updated");
			} else {
				await createRole({ name, display_name: displayName, permissions }).unwrap();
				toast.success("Role created");
			}
			reset();
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	const remove = async (id: string) => {
		if (!window.confirm("Delete this role?")) return;
		try {
			await deleteRole(id).unwrap();
			if (selectedID === id) reset();
			toast.success("Role deleted");
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	if (isLoading) return <FullPageLoader />;
	if (error) return <div className="text-destructive p-6 text-sm">Failed to load roles: {getErrorMessage(error)}</div>;

	return (
		<div className="mx-auto w-full max-w-6xl space-y-6 p-6" data-testid="rbac-governance-view">
			<div className="flex items-center justify-between gap-4">
				<div className="flex items-center gap-2">
					<ShieldCheck className="text-primary h-5 w-5" />
					<div>
						<h1 className="text-foreground text-xl font-semibold">Roles and permissions</h1>
						<p className="text-muted-foreground mt-1 text-sm">Define the permissions that protect governance operations.</p>
					</div>
				</div>
				<Button type="button" onClick={reset} dataTestId="role-create-button">
					<Plus className="h-4 w-4" />
					New role
				</Button>
			</div>

			<div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_26rem]">
				<div className="border-border divide-border divide-y rounded-sm border">
					{rolesData?.roles.map((role) => (
						<div key={role.id} className="flex items-start justify-between gap-4 p-4" data-testid={`role-row-${role.id}`}>
							<div>
								<div className="text-sm font-medium">{role.display_name || role.name}</div>
								<div className="text-muted-foreground mt-1 text-xs">
									{role.permissions.length} permissions{role.is_system ? " · system role" : ""}
								</div>
							</div>
							<div className="flex gap-1">
								<Button
									type="button"
									variant="ghost"
									size="icon"
									onClick={() => setSelectedID(role.id)}
									dataTestId={`role-edit-${role.id}`}
									aria-label={`Edit ${role.display_name || role.name}`}
								>
									<Pencil className="h-4 w-4" />
								</Button>
								{!role.is_immutable && (
									<Button
										type="button"
										variant="ghost"
										size="icon"
										onClick={() => remove(role.id)}
										dataTestId={`role-delete-${role.id}`}
										aria-label={`Delete ${role.display_name || role.name}`}
									>
										<Trash2 className="text-destructive h-4 w-4" />
									</Button>
								)}
							</div>
						</div>
					))}
				</div>

				<form onSubmit={submit} className="border-border h-fit space-y-4 rounded-sm border p-4" data-testid="role-form">
					<h2 className="text-sm font-semibold">{selectedID ? "Edit role" : "Create role"}</h2>
					<div className="space-y-2">
						<label htmlFor="role-name" className="text-sm font-medium">
							Name
						</label>
						<Input
							id="role-name"
							value={name}
							onChange={(event) => setName(event.target.value)}
							required
							disabled={!!selectedID}
							maxLength={255}
						/>
					</div>
					<div className="space-y-2">
						<label htmlFor="role-display-name" className="text-sm font-medium">
							Display name
						</label>
						<Input
							id="role-display-name"
							value={displayName}
							onChange={(event) => setDisplayName(event.target.value)}
							required
							maxLength={255}
						/>
					</div>
					<div className="space-y-2">
						<div className="text-sm font-medium">Permissions</div>
						<div className="max-h-72 space-y-3 overflow-auto rounded-sm border p-3">
							{permissionGroups.map(([resource, resourcePermissions]) => (
								<div key={resource}>
									<div className="text-muted-foreground mb-1 text-xs font-semibold uppercase">{resource}</div>
									{resourcePermissions.map((permission) => (
										<label key={permission.id} className="flex items-center gap-2 py-1 text-sm">
											<input
												type="checkbox"
												checked={permissions.includes(permission.id)}
												onChange={(event) =>
													setPermissions((current) =>
														event.target.checked ? [...current, permission.id] : current.filter((id) => id !== permission.id),
													)
												}
											/>
											{permission.operation}
										</label>
									))}
								</div>
							))}
						</div>
					</div>
					<div className="flex gap-2">
						<Button type="submit" isLoading={isCreating || isUpdating} disabled={isCreating || isUpdating} dataTestId="role-save-button">
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