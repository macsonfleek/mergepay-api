/**
 * Issue #403 — rate-limit presets for the withdrawal payment routes.
 *
 * `POST /withdraw` and `POST /withdraw/:id/confirm` are on-chain payment
 * flows (SEP-24 withdrawal start and signed-envelope confirm), but unlike
 * every other submission route they declared no per-route policy and were
 * covered only by the blanket global bucket (100/min). This suite pins the
 * two new presets (`withdrawalCreate`, `withdrawalConfirm`) end to end:
 *
 *   1. requests within the budget succeed, and request max+1 returns 429
 *      with the standard headers and the production `RATE_LIMITED` envelope;
 *   2. the buckets are keyed by the authenticated SEP-10 public key, so one
 *      wallet exhausting its budget cannot lock out another behind the same
 *      address;
 *   3. the presets are structurally independent (own prefixes, both tighter
 *      than the global default).
 *
 * All downstream work is mocked (Prisma, the Stellar account read, and the
 * anchor TOML/token/interactive calls), so the suite is fast and fully
 * offline; every in-budget response is a real 200 through the real app.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

const h = vi.hoisted(() => {
  const model = () => ({
    create: vi.fn(),
    createMany: vi.fn(),
    findUnique: vi.fn(),
    findFirst: vi.fn(),
    findMany: vi.fn(async () => []),
    update: vi.fn(),
    updateMany: vi.fn(async () => ({ count: 1 })),
    upsert: vi.fn(),
    delete: vi.fn(),
    deleteMany: vi.fn(),
    count: vi.fn(async () => 0),
  });
  const prisma: any = {
    user: model(),
    group: model(),
    groupMember: model(),
    expense: model(),
    expenseShare: model(),
    settlement: model(),
    treasuryTransaction: model(),
    auditLog: model(),
    idempotencyKey: model(),
    withdrawal: {
      create: vi.fn(),
      findUnique: vi.fn(),
      findFirst: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(async () => ({ count: 1 })),
    },
    $transaction: vi.fn(async (arg: any) =>
      typeof arg === "function" ? arg(prisma) : Promise.all(arg)
    ),
    $disconnect: vi.fn(),
  };
  return { prisma };
});

vi.mock("../src/db", () => ({ prisma: h.prisma }));

vi.mock("../src/services/stellar", () => ({
  stellar: {
    loadAccount: vi.fn(),
    buildPayment: vi.fn(),
    submitPayment: vi.fn(),
    submitSigned: vi.fn(),
  },
  memoText: vi.fn((code: string) => `MP:${code}`),
  toAsset: vi.fn(),
}));

vi.mock("../src/services/anchor", () => ({
  anchorService: {
    getToml: vi.fn(),
    getToken: vi.fn(),
    startInteractive: vi.fn(),
  },
  mapAnchorStatus: vi.fn((s: string) => s),
}));

import { buildApp } from "../src/app";
import { signToken } from "../src/plugins/auth";
import { rateLimitPolicies } from "../src/lib/rate-limit";
import { Keypair } from "@stellar/stellar-sdk";

const prisma = h.prisma;
const policies = rateLimitPolicies();

let app: Awaited<ReturnType<typeof buildApp>>;

beforeEach(async () => {
  vi.clearAllMocks();
  if (!app) app = await buildApp();

  const { stellar } = await import("../src/services/stellar");
  const { anchorService } = await import("../src/services/anchor");
  vi.mocked(stellar.loadAccount).mockResolvedValue({
    exists: true,
    sequence: "12345",
    balances: [
      { assetCode: "XLM", assetIssuer: null, balance: "100.0000000" },
    ],
    signers: [{ key: "GA", weight: 1 }],
    thresholds: { low: 1, med: 1, high: 1 },
  } as never);
  vi.mocked(anchorService.getToml).mockResolvedValue({
    homeDomain: "testanchor.stellar.org",
    webAuthEndpoint: "https://testanchor.stellar.org/auth",
    transferServerSep24: "https://testanchor.stellar.org/sep24",
    signingKey: "GA",
    assets: [],
  } as never);
  vi.mocked(anchorService.getToken).mockResolvedValue("anchor-jwt");
  vi.mocked(anchorService.startInteractive).mockResolvedValue({
    url: "https://testanchor.stellar.org/sep24/interactive/abc",
    id: "ANCH-TX-1",
  } as never);
});

const withdrawalRow = (over: Partial<any> = {}) => ({
  id: "wth_1",
  userId: "user_1",
  amount: "5",
  assetCode: "XLM",
  assetIssuer: null,
  memo: null,
  anchorTxId: null,
  interactiveUrl: "https://testanchor.stellar.org/sep24/withdraw",
  status: "pending",
  failureReason: null,
  createdAt: new Date("2026-04-01T00:00:00.000Z"),
  updatedAt: new Date("2026-04-01T00:00:00.000Z"),
  ...over,
});

/** Bearer token bound to a fixed wallet, so the bucket persists across calls. */
function authHeaderFor(keypair: Keypair, id = "user_1") {
  const token = signToken({ id, stellarPublicKey: keypair.publicKey() });
  return { authorization: `Bearer ${token}` };
}

describe("withdrawal rate-limit presets (#403)", () => {
  it("defines the two presets as separate user-keyed buckets tighter than the global default", () => {
    expect(policies.withdrawalCreate.keyBy).toBe("user-or-ip");
    expect(policies.withdrawalCreate.hook).toBe("preHandler");
    expect(policies.withdrawalCreate.prefix).toBe("withdrawal.create");
    expect(policies.withdrawalCreate.max).toBeLessThan(policies.global.max);

    expect(policies.withdrawalConfirm.keyBy).toBe("user-or-ip");
    expect(policies.withdrawalConfirm.hook).toBe("preHandler");
    expect(policies.withdrawalConfirm.prefix).toBe("withdrawal.confirm");
    expect(policies.withdrawalConfirm.max).toBeLessThan(policies.global.max);

    // Separate buckets: burning the create budget must not spend the
    // confirm allowance, and vice versa.
    expect(policies.withdrawalCreate.prefix).not.toBe(
      policies.withdrawalConfirm.prefix
    );
  });

  it("POST /withdraw — requests in budget succeed; the next one is 429 with the standard envelope", async () => {
    const wallet = Keypair.random();
    const headers = authHeaderFor(wallet);
    prisma.withdrawal.create.mockResolvedValue(withdrawalRow());
    prisma.withdrawal.findUnique.mockResolvedValue(withdrawalRow());

    const max = policies.withdrawalCreate.max;
    for (let i = 0; i < max; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/withdraw",
        headers,
        payload: { amount: "5", assetCode: "XLM" },
      });
      expect(res.statusCode, `create request ${i + 1}`).toBe(200);
    }

    const blocked = await app.inject({
      method: "POST",
      url: "/withdraw",
      headers,
      payload: { amount: "5", assetCode: "XLM" },
    });
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers["x-ratelimit-limit"]).toBe(String(max));
    expect(blocked.headers["x-ratelimit-remaining"]).toBe("0");
    expect(blocked.headers["retry-after"]).toBeDefined();

    const body = blocked.json();
    expect(body.code).toBe("RATE_LIMITED");
    expect(body.requestId).toBeTruthy();
    expect(typeof body.message).toBe("string");
  });

  it("POST /withdraw/:id/confirm — requests in budget succeed; the next one is 429", async () => {
    const wallet = Keypair.random();
    const headers = authHeaderFor(wallet);
    // Each confirm re-reads the row (guard + post-update); always pending so
    // every in-budget request runs the full mocked happy path.
    prisma.withdrawal.findUnique.mockResolvedValue(withdrawalRow());

    const max = policies.withdrawalConfirm.max;
    for (let i = 0; i < max; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/withdraw/wth_1/confirm",
        headers,
        payload: { signedXdr: "AAAA..." },
      });
      expect(res.statusCode, `confirm request ${i + 1}`).toBe(200);
    }

    const blocked = await app.inject({
      method: "POST",
      url: "/withdraw/wth_1/confirm",
      headers,
      payload: { signedXdr: "AAAA..." },
    });
    expect(blocked.statusCode).toBe(429);
    expect(blocked.headers["x-ratelimit-limit"]).toBe(String(max));
    expect(blocked.headers["x-ratelimit-remaining"]).toBe("0");
    expect(blocked.headers["retry-after"]).toBeDefined();
    expect(blocked.json().code).toBe("RATE_LIMITED");
  });

  it("keys both buckets per wallet — a second wallet keeps its own budget after one is exhausted", async () => {
    const noisy = Keypair.random();
    const neighbour = Keypair.random();
    prisma.withdrawal.create.mockResolvedValue(withdrawalRow());
    prisma.withdrawal.findUnique.mockResolvedValue(withdrawalRow());

    const max = policies.withdrawalCreate.max;
    for (let i = 0; i < max; i++) {
      await app.inject({
        method: "POST",
        url: "/withdraw",
        headers: authHeaderFor(noisy),
        payload: { amount: "5", assetCode: "XLM" },
      });
    }
    const noisyBlocked = await app.inject({
      method: "POST",
      url: "/withdraw",
      headers: authHeaderFor(noisy),
      payload: { amount: "5", assetCode: "XLM" },
    });
    expect(noisyBlocked.statusCode).toBe(429);

    // Same client address, different SEP-10 identity: full budget remaining.
    const other = await app.inject({
      method: "POST",
      url: "/withdraw",
      headers: authHeaderFor(neighbour),
      payload: { amount: "5", assetCode: "XLM" },
    });
    expect(other.statusCode).toBe(200);
    expect(other.headers["x-ratelimit-remaining"]).toBe(
      String(policies.withdrawalCreate.max - 1)
    );
  });
});
