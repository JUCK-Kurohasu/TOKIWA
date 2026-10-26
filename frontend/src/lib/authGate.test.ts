import { describe, expect, it } from "vitest";
import { decideProtected, publicRedirect } from "./authGate";

const ok = (setup_required: boolean) => ({ isLoading: false, isError: false, data: { setup_required } });

describe("decideProtected", () => {
  it("waits while the status is loading", () => {
    expect(decideProtected({ isLoading: true, isError: false }, false)).toBe("loading");
  });

  it("reports an unreachable API instead of sending the user to the login screen", () => {
    expect(decideProtected({ isLoading: false, isError: true }, false)).toBe("unreachable");
    expect(decideProtected({ isLoading: false, isError: true }, true)).toBe("unreachable");
  });

  it("sends a fresh install to setup, even with a stale token in storage", () => {
    expect(decideProtected(ok(true), false)).toBe("setup");
    expect(decideProtected(ok(true), true)).toBe("setup");
  });

  it("asks for a login once an admin exists, and lets authenticated users through", () => {
    expect(decideProtected(ok(false), false)).toBe("login");
    expect(decideProtected(ok(false), true)).toBe("allow");
  });
});

describe("publicRedirect", () => {
  it("moves /login to /setup on a fresh install", () => {
    expect(publicRedirect("login", { setup_required: true }, false)).toBe("/setup");
    expect(publicRedirect("login", { setup_required: false }, false)).toBeNull();
  });

  it("moves /setup away once setup is done", () => {
    expect(publicRedirect("setup", { setup_required: true }, false)).toBeNull();
    expect(publicRedirect("setup", { setup_required: false }, false)).toBe("/login");
    expect(publicRedirect("setup", { setup_required: false }, true)).toBe("/");
  });

  it("stays put while the status is unknown", () => {
    expect(publicRedirect("login", undefined, false)).toBeNull();
    expect(publicRedirect("setup", undefined, false)).toBeNull();
  });
});
