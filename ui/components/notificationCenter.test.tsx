import type { PropsWithChildren } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	notifications: [
		{
			id: "config-failed",
			severity: "error",
			title: "Configuration failed",
			message: "Database unavailable",
			created_at: "2026-10-30T10:00:00Z",
		},
	],
	notificationError: undefined as unknown,
	newsQuery: vi.fn(() => ({ data: { enabled: true, items: [] } })),
	liveNotices: [{ id: "cluster-warning", severity: "warning", title: "Cluster degraded", message: "One node is unavailable" }],
}));

vi.mock("@/lib/store", () => ({
	useAppDispatch: () => vi.fn(),
	useAppSelector: (selector: () => unknown) => selector(),
	selectVisibleNotifications: () => state.notifications,
	selectUnreadNotificationsCount: () => state.notifications.length,
	selectNotificationPreferences: () => ({ readIds: [], dismissedIds: [] }),
	useGetNotificationsQuery: () => ({
		isLoading: false,
		isError: !!state.notificationError,
		error: state.notificationError,
		refetch: vi.fn(),
	}),
	useGetSidekiqJobsQuery: () => ({ data: { jobs: [{ id: "running", status: "running", kind: "logs_recalculate_cost" }] } }),
	useCancelSidekiqJobMutation: () => [vi.fn(), {}],
	useGetRSSItemsQuery: state.newsQuery,
	getErrorMessage: () => "Request failed",
	clearAllNotifications: vi.fn(),
	markAllNotificationsRead: vi.fn(),
	markNotificationRead: vi.fn(),
	removeNotification: vi.fn(),
}));
vi.mock("@enterprise/lib", () => ({
	RbacResource: { BackgroundJobs: "jobs", Settings: "settings" },
	RbacOperation: { View: "view", Update: "update" },
	useRbac: () => true,
}));
vi.mock("@enterprise/lib/registrations/liveNotices", () => ({}));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn() }));
vi.mock("@/lib/registries/liveNotices", () => ({
	useLiveNotices: () => state.liveNotices,
	countAttentionNotices: (notices: unknown[]) => notices.length,
}));
vi.mock("@/components/ui/popover", () => {
	const Wrapper = ({ children }: PropsWithChildren) => <div>{children}</div>;
	return { Popover: Wrapper, PopoverContent: Wrapper, PopoverTrigger: Wrapper };
});
vi.mock("@/components/ui/tabs", () => {
	const Wrapper = ({ children }: PropsWithChildren) => <div>{children}</div>;
	return { Tabs: Wrapper, TabsContent: Wrapper, TabsList: Wrapper, TabsTrigger: Wrapper };
});
vi.mock("@/components/ui/scrollArea", () => ({ ScrollArea: ({ children }: PropsWithChildren) => <div>{children}</div> }));
vi.mock("@/components/sidekiqJobsSection", () => ({ default: () => <div>Recalculating log costs</div> }));
vi.mock("@/components/rssSourcesSheet", () => ({ default: () => <div>News sources</div> }));
vi.mock("@/components/rssFeedIcon", () => ({ default: () => null }));

import NotificationCenter from "./notificationCenter";

describe("operational notification center", () => {
	beforeEach(() => {
		state.newsQuery.mockClear();
		state.notificationError = undefined;
	});

	it("keeps operational errors, live conditions and jobs without querying or presenting news", () => {
		const markup = renderToStaticMarkup(<NotificationCenter />);
		expect(markup).toContain("Configuration failed");
		expect(markup).toContain("Database unavailable");
		expect(markup).toContain("Cluster degraded");
		expect(markup).toContain("Recalculating log costs");
		expect(markup).not.toContain("News sources");
		expect(markup).not.toContain("notification-tab-news");
		expect(state.newsQuery).not.toHaveBeenCalled();
	});

	it("keeps transient notification failures visible and retryable", () => {
		state.notificationError = { status: 500 };
		const markup = renderToStaticMarkup(<NotificationCenter />);
		expect(markup).toContain("Notifications could not be loaded.");
		expect(markup).toContain("Try again");
		expect(markup).toContain("Cluster degraded");
	});
});