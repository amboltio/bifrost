import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { getErrorMessage, useAppDispatch, useChangeOwnPasswordMutation, useSetManagedPasswordMutation } from "@/lib/store";
import { baseApi, clearAuthStorage } from "@/lib/store/apis/baseApi";
import { passwordReplacementSchema } from "@/lib/types/schemas";
import { beginLogout } from "@/lib/utils/logoutState";
import { stopWebSocket } from "@/hooks/useWebSocket";
import { toast } from "sonner";

// Mounted only while open: passwords are discarded on close and never persisted.
export function PasswordDialog({ userId, onClose }: { userId?: string; onClose: () => void }) {
	const [values, setValues] = useState({ current_password: "", new_password: "", confirm_password: "" });
	const [error, setError] = useState("");
	const [changeOwn, ownState] = useChangeOwnPasswordMutation();
	const [setManaged, managedState] = useSetManagedPasswordMutation();
	const navigate = useNavigate();
	const dispatch = useAppDispatch();
	const busy = ownState.isLoading || managedState.isLoading;
	const submit = async (event: React.FormEvent) => {
		event.preventDefault();
		setError("");
		const parsed = passwordReplacementSchema.safeParse(values);
		if (!parsed.success) {
			setError(parsed.error.issues[0].message);
			return;
		}
		if (!userId && !values.current_password) {
			setError("Enter your current password");
			return;
		}
		try {
			if (userId) {
				await setManaged({ userId, new_password: values.new_password, confirm_password: values.confirm_password }).unwrap();
				toast.success("Password reset. Existing sessions have been revoked.");
				onClose();
			} else {
				await changeOwn({ current_password: values.current_password, new_password: values.new_password }).unwrap();
				beginLogout();
				stopWebSocket();
				clearAuthStorage();
				await navigate({ to: "/login" });
				dispatch(baseApi.util.resetApiState());
			}
		} catch (failure) {
			setError(getErrorMessage(failure));
		} finally {
			ownState.reset();
			managedState.reset();
		}
	};
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open && !busy) onClose();
			}}
		>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>{userId ? "Reset password" : "Change password"}</DialogTitle>
					<DialogDescription>All existing sessions will be signed out. Use at least 12 characters.</DialogDescription>
				</DialogHeader>
				<form onSubmit={submit} className="space-y-4" data-testid="password-dialog-form">
					{([...(userId ? [] : ["current_password" as const]), "new_password", "confirm_password"] as const).map((field) => (
						<div key={field} className="space-y-2">
							<Label htmlFor={`password-${field}`}>
								{field === "current_password" ? "Current password" : field === "new_password" ? "New password" : "Confirm password"}
							</Label>
							<Input
								id={`password-${field}`}
								data-testid={`password-${field}`}
								type="password"
								autoComplete={field === "current_password" ? "current-password" : "new-password"}
								value={values[field]}
								onChange={(event) => setValues({ ...values, [field]: event.target.value })}
								required
								disabled={busy}
							/>
						</div>
					))}
					{error && (
						<p role="alert" className="text-destructive text-sm" data-testid="password-error">
							{error}
						</p>
					)}
					<DialogFooter>
						<Button type="button" variant="outline" disabled={busy} onClick={onClose}>
							Cancel
						</Button>
						<Button type="submit" disabled={busy} data-testid="password-submit">
							{busy ? "Saving…" : "Save password"}
						</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}