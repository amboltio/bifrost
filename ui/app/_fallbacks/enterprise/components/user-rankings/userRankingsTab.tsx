import FullPageLoader from "@/components/fullPageLoader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getErrorMessage, useGetCurrentUserQuery, useGetUserAnalyticsQuery } from "@/lib/store";
import { formatCompactNumber, formatCurrencyNumber } from "@/lib/utils/numbers";
import { BarChart3, CircleAlert } from "lucide-react";

const filters = { period: "30d" } as const;

function MetricCard({ label, value }: { label: string; value: string }) {
	return (
		<Card>
			<CardContent className="pt-6">
				<p className="text-muted-foreground text-xs tracking-wide uppercase">{label}</p>
				<p className="mt-2 text-2xl font-semibold">{value}</p>
			</CardContent>
		</Card>
	);
}

export default function UserRankingsTab() {
	const { data: currentUser, isLoading: isLoadingUser, error: userError } = useGetCurrentUserQuery();
	const { data, isLoading, error } = useGetUserAnalyticsQuery(
		{ userId: currentUser?.id ?? "", filters, limit: 10 },
		{ skip: !currentUser?.id },
	);

	if (isLoadingUser || isLoading) return <FullPageLoader />;
	if (userError || error) {
		return (
			<div className="text-muted-foreground flex min-h-[40vh] flex-col items-center justify-center gap-3 text-center">
				<CircleAlert className="h-8 w-8" />
				<p>Unable to load your usage analytics.</p>
				<p className="text-xs">{getErrorMessage(userError ?? error)}</p>
			</div>
		);
	}
	if (!data) return null;

	const stats = data.stats;
	return (
		<div className="h-full w-full space-y-6 overflow-auto p-1">
			<div className="flex items-center gap-3">
				<BarChart3 className="text-muted-foreground h-5 w-5" />
				<div>
					<h2 className="text-lg font-semibold">My usage analytics</h2>
					<p className="text-muted-foreground text-sm">Your activity over the last 30 days.</p>
				</div>
			</div>

			<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<MetricCard label="Requests" value={formatCompactNumber(stats.total_requests)} />
				<MetricCard label="Tokens" value={formatCompactNumber(stats.total_tokens)} />
				<MetricCard label="Cost" value={formatCurrencyNumber(stats.total_cost)} />
				<MetricCard label="Success rate" value={`${stats.success_rate.toFixed(1)}%`} />
			</div>

			<Card>
				<CardHeader>
					<CardTitle>Models</CardTitle>
				</CardHeader>
				<CardContent>
					<div className="divide-y">
						{data.models.rankings.length === 0 ? (
							<p className="text-muted-foreground py-4 text-sm">No model usage recorded in this period.</p>
						) : (
							data.models.rankings.map((model) => (
								<div className="flex items-center justify-between gap-4 py-3" key={`${model.provider}:${model.model}`}>
									<div className="min-w-0">
										<p className="truncate text-sm font-medium">{model.model}</p>
										<p className="text-muted-foreground truncate text-xs">{model.provider}</p>
									</div>
									<div className="text-right text-sm">
										<p>{formatCompactNumber(model.total_requests)} requests</p>
										<p className="text-muted-foreground text-xs">{formatCurrencyNumber(model.total_cost)}</p>
									</div>
								</div>
							))
						)}
					</div>
				</CardContent>
			</Card>
		</div>
	);
}