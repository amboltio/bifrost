import { Button } from "@/components/ui/button";
import { useRouter } from "@tanstack/react-router";
import { Terminal } from "lucide-react";
import { useState } from "react";

export default function AdminProvisioningView() {
	const router = useRouter();
	const [isChecking, setIsChecking] = useState(false);

	const checkAgain = async () => {
		setIsChecking(true);
		try {
			await router.invalidate();
		} finally {
			setIsChecking(false);
		}
	};

	return (
		<div className="flex min-h-screen items-center justify-center p-4">
			<section className="border-border bg-card w-full max-w-lg space-y-5 rounded-sm border p-8" data-testid="admin-provisioning-view">
				<Terminal className="text-muted-foreground h-6 w-6" aria-hidden="true" />
				<h1 className="text-foreground text-xl font-semibold">Administrator required</h1>
				<p className="text-muted-foreground text-sm">
					The dashboard is locked until an operator creates a superadmin from the Bifrost server terminal.
				</p>
				<div className="space-y-2 text-sm" data-testid="admin-provisioning-instructions">
					<p>In the deployed container&apos;s terminal, run:</p>
					<pre className="bg-muted overflow-x-auto rounded-sm p-3 text-xs">
						<code>/app/main createsuperadmin --app-dir /app/data</code>
					</pre>
					<p className="text-muted-foreground">
						Follow the prompts for email, display name, and password. For a local binary, run <code>createsuperadmin --app-dir PATH</code>{" "}
						with the gateway&apos;s data directory.
					</p>
				</div>
				<p className="text-muted-foreground text-sm">After the operator finishes, check again to sign in.</p>
				<Button type="button" onClick={checkAgain} isLoading={isChecking} disabled={isChecking} data-testid="admin-provisioning-refresh">
					Check again
				</Button>
			</section>
		</div>
	);
}