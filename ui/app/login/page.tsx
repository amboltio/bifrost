import LoginView from "@enterprise/components/login/loginView";
import { getRouteApi } from "@tanstack/react-router";
import AdminProvisioningView from "./views/adminProvisioningView";

const loginRoute = getRouteApi("/login");

export default function LoginPage() {
	const loaderData = loginRoute.useLoaderData();
	return <div className="overflow-hidden">{loaderData?.adminProvisioningRequired ? <AdminProvisioningView /> : <LoginView />}</div>;
}