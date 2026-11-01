import { useState } from "react";
import { Eye, EyeOff, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useCopyToClipboard } from "@/hooks/useCopyToClipboard";
import type { IssuedVirtualKeySecret } from "@/lib/types/governance";

/** Mount only for an issuance; the owner discards every secret on close. */
export function IssuedVirtualKeyDialog({ secrets, onClose }: { secrets: IssuedVirtualKeySecret[]; onClose: () => void }) {
	const [revealed, setRevealed] = useState<Set<string>>(new Set());
	const { copy } = useCopyToClipboard({ successMessage: "Virtual key copied" });
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open) onClose();
			}}
		>
			<DialogContent data-testid="vk-issued-secret-dialog" className="max-h-[80vh] overflow-y-auto">
				<DialogHeader>
					<DialogTitle>Save your new virtual {secrets.length === 1 ? "key" : "keys"}</DialogTitle>
					<DialogDescription>
						These secrets are shown only once. Save them securely before closing. They cannot be retrieved later.
					</DialogDescription>
				</DialogHeader>
				<div className="space-y-4">
					{secrets.map(({ id, name, secret }) => (
						<div key={id} className="space-y-2 rounded-md border p-3" data-testid="vk-issued-secret-entry">
							<p className="font-medium">{name}</p>
							<code className="block text-sm break-all" data-testid="vk-issued-secret-value">
								{revealed.has(id) ? secret : "••••••••••••••••"}
							</code>
							<div className="flex gap-2">
								<Button
									variant="outline"
									size="sm"
									data-testid="vk-issued-secret-reveal"
									onClick={() =>
										setRevealed((prev) => {
											const next = new Set(prev);
											if (next.has(id)) next.delete(id);
											else next.add(id);
											return next;
										})
									}
								>
									{revealed.has(id) ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
									{revealed.has(id) ? "Hide" : "Reveal"}
								</Button>
								<Button variant="outline" size="sm" data-testid="vk-issued-secret-copy" onClick={() => copy(secret)}>
									<Copy className="size-4" />
									Copy
								</Button>
							</div>
						</div>
					))}
				</div>
				<DialogFooter>
					<Button data-testid="vk-issued-secret-close" onClick={onClose}>
						I have saved the {secrets.length === 1 ? "key" : "keys"}
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}