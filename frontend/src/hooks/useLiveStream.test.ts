import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authStore } from "@/stores/auth";
import { LiveStreamManager } from "./useLiveStream";

class FakeEventSource {
  static readonly CLOSED = 2;
  static instances: FakeEventSource[] = [];
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }
  close() {
    this.readyState = FakeEventSource.CLOSED;
  }
}

const user = { id: "u1", username: "alice", role: "viewer" as const, created_at: "2026-11-23T00:00:00Z" };

function ticketResponse(ticket: string): Response {
  return new Response(JSON.stringify({ ticket, expires_in: 60 }), { status: 200 });
}

describe("LiveStreamManager (audit #100: ticket auth)", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    FakeEventSource.instances = [];
    vi.stubGlobal("window", { location: { origin: "http://tokiwa.test" } });
    vi.stubGlobal("EventSource", FakeEventSource);
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    authStore.login("jwt-1", user);
  });

  afterEach(() => {
    authStore.logout();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("opens the stream with a single-use ticket, never with the JWT in the URL", async () => {
    fetchMock.mockResolvedValueOnce(ticketResponse("t-1"));
    const unsubscribe = new LiveStreamManager().subscribe(() => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/v1/stream/ticket");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer jwt-1");
    expect(FakeEventSource.instances.map((es) => es.url)).toEqual(["/api/v1/stream?ticket=t-1"]);
    expect(FakeEventSource.instances[0].url).not.toContain("jwt-1");
    unsubscribe();
  });

  it("discards a ticket that arrives after the token changed", async () => {
    let resolveFirst: (r: Response) => void = () => {};
    fetchMock
      .mockReturnValueOnce(new Promise<Response>((resolve) => (resolveFirst = resolve)))
      .mockResolvedValueOnce(ticketResponse("t-2"));
    const unsubscribe = new LiveStreamManager().subscribe(() => {});
    authStore.login("jwt-2", user); // reconnect with the new JWT while the first ticket is in flight
    await vi.advanceTimersByTimeAsync(0);
    resolveFirst(ticketResponse("t-1"));
    await vi.advanceTimersByTimeAsync(0);

    expect(FakeEventSource.instances.map((es) => es.url)).toEqual(["/api/v1/stream?ticket=t-2"]);
    unsubscribe();
  });

  it("reconnects with a fresh ticket when the used one is refused", async () => {
    fetchMock.mockResolvedValueOnce(ticketResponse("t-1")).mockResolvedValueOnce(ticketResponse("t-2"));
    const unsubscribe = new LiveStreamManager().subscribe(() => {});
    await vi.advanceTimersByTimeAsync(0);
    const first = FakeEventSource.instances[0];
    first.readyState = FakeEventSource.CLOSED; // browser retried the old URL and got 401
    first.onerror?.();
    await vi.advanceTimersByTimeAsync(2_000); // first backoff step

    expect(FakeEventSource.instances.map((es) => es.url)).toEqual([
      "/api/v1/stream?ticket=t-1",
      "/api/v1/stream?ticket=t-2",
    ]);
    unsubscribe();
  });

  it("retries with backoff when the ticket request fails", async () => {
    fetchMock
      .mockRejectedValueOnce(new TypeError("network down"))
      .mockResolvedValueOnce(ticketResponse("t-1"));
    const unsubscribe = new LiveStreamManager().subscribe(() => {});
    await vi.advanceTimersByTimeAsync(0);
    expect(FakeEventSource.instances).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(2_000);

    expect(FakeEventSource.instances.map((es) => es.url)).toEqual(["/api/v1/stream?ticket=t-1"]);
    unsubscribe();
  });
});
