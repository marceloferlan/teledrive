import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/logger", () => ({
  logger: { warn: vi.fn(), error: vi.fn(), log: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../client", () => ({ ensureConnected: vi.fn(async () => {}) }));

import {
  FLOOD_WAIT_TOTAL_BUDGET_SECONDS,
  withTelegramRetry,
  type TelegramRetryEvent,
} from "../rateLimit";

const flood = (seconds: number) => ({ seconds, message: `FLOOD_WAIT_${seconds}` });

/** Runs the call to completion, advancing fake timers through every wait. */
async function settle<T>(promise: Promise<T>): Promise<PromiseSettledResult<T>> {
  const result = promise.then(
    (value) => ({ status: "fulfilled", value }) as const,
    (reason) => ({ status: "rejected", reason }) as const,
  );
  await vi.runAllTimersAsync();
  return result;
}

describe("withTelegramRetry", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns the value of the first successful attempt", async () => {
    const fn = vi.fn(async () => "ok");
    expect(await settle(withTelegramRetry(fn, "t"))).toMatchObject({
      status: "fulfilled",
      value: "ok",
    });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("does not spend attempts on flood waits", async () => {
    // Six consecutive flood waits would exhaust a 5-attempt budget.
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(flood(30))
      .mockRejectedValueOnce(flood(30))
      .mockRejectedValueOnce(flood(30))
      .mockRejectedValueOnce(flood(30))
      .mockRejectedValueOnce(flood(30))
      .mockRejectedValueOnce(flood(30))
      .mockResolvedValue("done");
    const result = await settle(withTelegramRetry(fn, "t", 5));
    expect(result).toMatchObject({ status: "fulfilled", value: "done" });
    expect(fn).toHaveBeenCalledTimes(7);
  });

  it("waits the full time Telegram asked, even beyond the old 300s clamp", async () => {
    const waits: number[] = [];
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(flood(600))
      .mockResolvedValue("done");
    const result = await settle(
      withTelegramRetry(fn, "t", 5, (e: TelegramRetryEvent) => waits.push(e.waitMs)),
    );
    expect(result).toMatchObject({ status: "fulfilled" });
    expect(waits[0]).toBeGreaterThanOrEqual(600_000);
  });

  it("fails at once when one flood wait exceeds the total budget", async () => {
    const fn = vi.fn(async () => {
      throw flood(FLOOD_WAIT_TOTAL_BUDGET_SECONDS + 1);
    });
    const result = await settle(withTelegramRetry(fn, "upload", 5));
    expect(result.status).toBe("rejected");
    expect((result as PromiseRejectedResult).reason.message).toMatch(/asked to wait 901s/);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("fails once cumulative flood waiting would pass the budget", async () => {
    const fn = vi.fn(async () => {
      throw flood(400);
    });
    const result = await settle(withTelegramRetry(fn, "upload", 5));
    expect(result.status).toBe("rejected");
    // 400s + 400s fit in 900s; the third request does not.
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("still limits non-flood transient errors to maxAttempts", async () => {
    const fn = vi.fn(async () => {
      throw new Error("network timeout");
    });
    const result = await settle(withTelegramRetry(fn, "upload", 3));
    expect(result.status).toBe("rejected");
    expect((result as PromiseRejectedResult).reason.message).toMatch(/Failed after 3 attempts/);
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("throws hard errors immediately without retrying", async () => {
    const fn = vi.fn(async () => {
      throw new Error("CHANNEL_PRIVATE");
    });
    const result = await settle(withTelegramRetry(fn, "upload", 5));
    expect(result.status).toBe("rejected");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("reports the flood seconds and keeps the attempt number unchanged", async () => {
    const events: TelegramRetryEvent[] = [];
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(flood(10))
      .mockRejectedValueOnce(flood(10))
      .mockResolvedValue("done");
    await settle(withTelegramRetry(fn, "t", 5, (e) => events.push(e)));
    expect(events.map((e) => [e.attempt, e.floodSeconds])).toEqual([
      [1, 10],
      [1, 10],
    ]);
  });
});
