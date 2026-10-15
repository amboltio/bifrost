import FullPageLoader from "@/components/fullPageLoader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
	getErrorMessage,
	useCreateBusinessUnitMutation,
	useDeleteBusinessUnitMutation,
	useGetBusinessUnitsQuery,
	useUpdateBusinessUnitMutation,
} from "@/lib/store";
import { Building2, Pencil, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

export function BusinessUnitsView() {
	const { data, isLoading, error } = useGetBusinessUnitsQuery({ limit: 100 });
	const [createBusinessUnit, { isLoading: isCreating }] = useCreateBusinessUnitMutation();
	const [updateBusinessUnit, { isLoading: isUpdating }] = useUpdateBusinessUnitMutation();
	const [deleteBusinessUnit] = useDeleteBusinessUnitMutation();
	const [selectedID, setSelectedID] = useState<string | null>(null);
	const [name, setName] = useState("");
	const [description, setDescription] = useState("");

	const selected = data?.business_units.find((unit) => unit.id === selectedID);
	useEffect(() => {
		if (!selected) return;
		setName(selected.name);
		setDescription(selected.description);
	}, [selected]);

	const reset = () => {
		setSelectedID(null);
		setName("");
		setDescription("");
	};

	const submit = async (event: React.FormEvent<HTMLFormElement>) => {
		event.preventDefault();
		try {
			if (selectedID) {
				await updateBusinessUnit({ id: selectedID, data: { name, description } }).unwrap();
				toast.success("Business unit updated");
			} else {
				await createBusinessUnit({ name, description }).unwrap();
				toast.success("Business unit created");
			}
			reset();
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	const remove = async (id: string) => {
		if (!window.confirm("Delete this business unit?")) return;
		try {
			await deleteBusinessUnit(id).unwrap();
			if (selectedID === id) reset();
			toast.success("Business unit deleted");
		} catch (mutationError) {
			toast.error(getErrorMessage(mutationError));
		}
	};

	if (isLoading) return <FullPageLoader />;
	if (error) return <div className="text-destructive p-6 text-sm">Failed to load business units: {getErrorMessage(error)}</div>;

	return (
		<div className="mx-auto w-full max-w-5xl space-y-6 p-6" data-testid="business-units-governance-view">
			<div className="flex items-center justify-between gap-4">
				<div>
					<div className="flex items-center gap-2">
						<Building2 className="text-primary h-5 w-5" />
						<h1 className="text-foreground text-xl font-semibold">Business units</h1>
					</div>
					<p className="text-muted-foreground mt-1 text-sm">Organize users and teams into durable governance scopes.</p>
				</div>
				<Button type="button" onClick={reset} dataTestId="business-units-create-button">
					<Plus className="h-4 w-4" />
					New business unit
				</Button>
			</div>

			<div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
				<div className="border-border rounded-sm border">
					{data?.business_units.length ? (
						<div className="divide-border divide-y">
							{data.business_units.map((unit) => (
								<div key={unit.id} className="flex items-start justify-between gap-4 p-4" data-testid={`business-unit-row-${unit.id}`}>
									<div className="min-w-0">
										<div className="text-sm font-medium">{unit.name}</div>
										<div className="text-muted-foreground mt-1 text-sm">{unit.description || "No description"}</div>
									</div>
									<div className="flex shrink-0 gap-1">
										<Button
											type="button"
											variant="ghost"
											size="icon"
											onClick={() => setSelectedID(unit.id)}
											dataTestId={`business-unit-edit-${unit.id}`}
											aria-label={`Edit ${unit.name}`}
										>
											<Pencil className="h-4 w-4" />
										</Button>
										<Button
											type="button"
											variant="ghost"
											size="icon"
											onClick={() => remove(unit.id)}
											dataTestId={`business-unit-delete-${unit.id}`}
											aria-label={`Delete ${unit.name}`}
										>
											<Trash2 className="text-destructive h-4 w-4" />
										</Button>
									</div>
								</div>
							))}
						</div>
					) : (
						<div className="text-muted-foreground p-8 text-center text-sm">No business units have been created.</div>
					)}
				</div>

				<form onSubmit={submit} className="border-border h-fit space-y-4 rounded-sm border p-4" data-testid="business-unit-form">
					<h2 className="text-sm font-semibold">{selectedID ? "Edit business unit" : "Create business unit"}</h2>
					<div className="space-y-2">
						<label htmlFor="business-unit-name" className="text-sm font-medium">
							Name
						</label>
						<Input id="business-unit-name" value={name} onChange={(event) => setName(event.target.value)} required maxLength={255} />
					</div>
					<div className="space-y-2">
						<label htmlFor="business-unit-description" className="text-sm font-medium">
							Description
						</label>
						<Textarea
							id="business-unit-description"
							value={description}
							onChange={(event) => setDescription(event.target.value)}
							rows={4}
							maxLength={2000}
						/>
					</div>
					<div className="flex gap-2">
						<Button
							type="submit"
							isLoading={isCreating || isUpdating}
							disabled={isCreating || isUpdating}
							dataTestId="business-unit-save-button"
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