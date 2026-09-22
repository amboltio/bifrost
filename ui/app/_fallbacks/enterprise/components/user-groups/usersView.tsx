import FullPageLoader from "@/components/fullPageLoader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
	getErrorMessage,
	useCreateManagedUserMutation,
	useDisableManagedUserMutation,
	useGetManagedRolesQuery,
	useGetManagedUsersQuery,
} from "@/lib/store";
import { UserPlus, UserRound, UserRoundX } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

export default function UsersView() {
	const { data, isLoading, error } = useGetManagedUsersQuery({ limit: 100 });
	const { data: rolesData } = useGetManagedRolesQuery();
	const [createUser, { isLoading: isCreating }] = useCreateManagedUserMutation();
	const [disableUser] = useDisableManagedUserMutation();
	const [email, setEmail] = useState("");
	const [displayName, setDisplayName] = useState("");
	const [password, setPassword] = useState("");
	const [roleID, setRoleID] = useState("");

	useEffect(() => {
		if (!roleID && rolesData?.roles.length) setRoleID(rolesData.roles[0].id);
	}, [roleID, rolesData]);

	const reset = () => {
		setEmail("");
		setDisplayName("");
		setPassword("");
	};

	const submit = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		try {
			await createUser({ email, display_name: displayName, password, role_ids: roleID ? [roleID] : [] }).unwrap();
			toast.success("User created");
			reset();
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	const disable = async (id: string) => {
		if (!window.confirm("Disable this user?")) return;
		try {
			await disableUser(id).unwrap();
			toast.success("User disabled");
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	if (isLoading) return <FullPageLoader />;
	if (error) return <div className="text-destructive p-6 text-sm">Failed to load users: {getErrorMessage(error)}</div>;

	return (
		<div className="mx-auto w-full max-w-6xl space-y-6 p-6" data-testid="users-governance-view">
			<div className="flex items-center gap-2">
				<UserRound className="text-primary h-5 w-5" />
				<div>
					<h1 className="text-foreground text-xl font-semibold">Users</h1>
					<p className="text-muted-foreground mt-1 text-sm">Manage canonical users, local credentials, and role assignments.</p>
				</div>
			</div>

			<div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
				<div className="border-border overflow-hidden rounded-sm border">
					{data?.users.length ? (
						<div className="divide-border divide-y">
							{data.users.map((user) => (
								<div key={user.id} className="flex items-start justify-between gap-4 p-4" data-testid={`user-row-${user.id}`}>
									<div className="min-w-0">
										<div className="text-sm font-medium">{user.display_name || user.email || "Unnamed user"}</div>
										<div className="text-muted-foreground mt-1 text-sm">{user.email || "No email"}</div>
										<div className="mt-2 flex flex-wrap gap-1">
											{user.roles.map((role) => (
												<span key={role.id} className="bg-muted rounded px-2 py-0.5 text-xs">
													{role.display_name || role.name}
												</span>
											))}
										</div>
										<div className="text-muted-foreground mt-2 text-xs capitalize">{user.status}</div>
									</div>
									{user.status === "active" && (
										<Button
											type="button"
											variant="ghost"
											size="icon"
											onClick={() => disable(user.id)}
											dataTestId={`user-disable-${user.id}`}
											aria-label={`Disable ${user.email || user.id}`}
										>
											<UserRoundX className="text-destructive h-4 w-4" />
										</Button>
									)}
								</div>
							))}
						</div>
					) : (
						<div className="text-muted-foreground p-8 text-center text-sm">No users have been created.</div>
					)}
				</div>

				<form onSubmit={submit} className="border-border h-fit space-y-4 rounded-sm border p-4" data-testid="user-create-form">
					<div className="flex items-center gap-2">
						<UserPlus className="h-4 w-4" />
						<h2 className="text-sm font-semibold">Create local user</h2>
					</div>
					<div className="space-y-2">
						<label htmlFor="user-email" className="text-sm font-medium">
							Email
						</label>
						<Input
							id="user-email"
							type="email"
							value={email}
							onChange={(event) => setEmail(event.target.value)}
							required
							autoComplete="email"
						/>
					</div>
					<div className="space-y-2">
						<label htmlFor="user-display-name" className="text-sm font-medium">
							Display name
						</label>
						<Input
							id="user-display-name"
							value={displayName}
							onChange={(event) => setDisplayName(event.target.value)}
							required
							maxLength={255}
						/>
					</div>
					<div className="space-y-2">
						<label htmlFor="user-password" className="text-sm font-medium">
							Temporary password
						</label>
						<Input
							id="user-password"
							type="password"
							value={password}
							onChange={(event) => setPassword(event.target.value)}
							required
							minLength={12}
							autoComplete="new-password"
						/>
					</div>
					<div className="space-y-2">
						<label htmlFor="user-role" className="text-sm font-medium">
							Role
						</label>
						<select
							id="user-role"
							className="border-input bg-background h-9 w-full rounded-sm border px-3 text-sm"
							value={roleID}
							onChange={(event) => setRoleID(event.target.value)}
							required
						>
							{rolesData?.roles.map((role) => (
								<option key={role.id} value={role.id}>
									{role.display_name || role.name}
								</option>
							))}
						</select>
					</div>
					<Button type="submit" isLoading={isCreating} disabled={isCreating || !roleID} dataTestId="user-create-button">
						Create user
					</Button>
				</form>
			</div>
		</div>
	);
}