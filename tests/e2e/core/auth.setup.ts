import { test as setup } from "@playwright/test";
import { mkdirSync } from "fs";
import { loginAdmin } from "./actions/auth";
import { AUTH_DIR, storageStatePath } from "../plan";

setup("authenticate", async ({ request }, testInfo) => {
  const worker = testInfo.project.metadata.worker as string;
  mkdirSync(AUTH_DIR, { recursive: true });

  await loginAdmin(request);
  // The onboarding checklist is a fixed card over the bottom-right corner, where
  // forms put their Save buttons. Hide it for everyone on this worker's server.
  const dismissed = await request.post("/api/config/metadata", {
    data: { onboarding_dismissed: true },
  });
  if (!dismissed.ok()) {
    throw new Error(
      `dismissing onboarding for worker "${worker}" failed: ${dismissed.status()} ${await dismissed.text()}`,
    );
  }
  await request.storageState({ path: storageStatePath(worker) });
});
