import { create } from "@zitadel/client";
import { RequestChallengesSchema } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";

vi.mock("next/headers", () => ({
  headers: vi.fn(),
}));

vi.mock("../service-url", () => ({
  getServiceConfig: vi.fn(),
}));

vi.mock("@/lib/zitadel", () => ({
  createSessionForUserIdAndIdpIntent: vi.fn(),
  createSessionFromChecksAndChallenges: vi.fn(),
  getSecuritySettings: vi.fn(),
  getSession: vi.fn(),
  setSession: vi.fn(),
}));

vi.mock("@/lib/cookies", () => ({
  addSessionToCookie: vi.fn(),
  takeRememberMeIntentCookie: vi.fn(),
  updateSessionCookie: vi.fn(),
}));

import { addSessionToCookie, takeRememberMeIntentCookie, updateSessionCookie } from "@/lib/cookies";
import {
  createSessionForUserIdAndIdpIntent,
  createSessionFromChecksAndChallenges,
  getSecuritySettings,
  getSession,
  setSession,
} from "@/lib/zitadel";
import { headers } from "next/headers";
import { getServiceConfig } from "../service-url";
import { createSessionAndUpdateCookie, createSessionForIdpAndUpdateCookie, setSessionAndUpdateCookie } from "./cookie";

// A challenge request as an attacker-controlled browser could construct it: both OTP methods
// asking for the code to come back in the response instead of being sent to the user.
function returnCodeChallenges() {
  return create(RequestChallengesSchema, {
    otpSms: { returnCode: true },
    otpEmail: { deliveryType: { case: "returnCode", value: {} } },
  });
}

function expectSanitized(challenges: any) {
  expect(challenges.otpSms.returnCode).toBe(false);
  expect(challenges.otpEmail.deliveryType.case).toBe("sendCode");
}

describe("session challenge sanitization", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(headers).mockResolvedValue({} as any);
    vi.mocked(getServiceConfig).mockReturnValue({ serviceConfig: {} } as any);
    vi.mocked(getSecuritySettings).mockResolvedValue({ embeddedIframe: { enabled: false } } as any);
    vi.mocked(getSession).mockResolvedValue({
      session: {
        id: "sessionId",
        factors: { user: { loginName: "victim@example.com", organizationId: "orgId" } },
      },
    } as any);
    vi.mocked(addSessionToCookie).mockResolvedValue(undefined as any);
    vi.mocked(updateSessionCookie).mockResolvedValue(undefined as any);
  });

  test("createSessionAndUpdateCookie strips returnCode before calling the API", async () => {
    vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
      sessionId: "sessionId",
      sessionToken: "sessionToken",
    } as any);

    await createSessionAndUpdateCookie({
      checks: {} as any,
      requestId: undefined,
      challenges: returnCodeChallenges(),
    });

    expect(createSessionFromChecksAndChallenges).toHaveBeenCalledTimes(1);
    expectSanitized(vi.mocked(createSessionFromChecksAndChallenges).mock.calls[0][0].challenges);
  });

  test("setSessionAndUpdateCookie strips returnCode before calling the API", async () => {
    vi.mocked(setSession).mockResolvedValue({
      sessionToken: "sessionToken",
      details: {},
    } as any);

    await setSessionAndUpdateCookie({
      recentCookie: {
        id: "sessionId",
        token: "sessionToken",
        loginName: "victim@example.com",
        creationTs: "",
        expirationTs: "",
        changeTs: "",
      },
      challenges: returnCodeChallenges(),
      lifetime: {} as any,
    });

    expect(setSession).toHaveBeenCalledTimes(1);
    expectSanitized(vi.mocked(setSession).mock.calls[0][0].challenges);
  });
});

// Spalk: a new session's wrong password carries its failed-attempt count, as a session update's does.
describe("createSessionAndUpdateCookie on a wrong password", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(headers).mockResolvedValue({} as any);
    vi.mocked(getServiceConfig).mockReturnValue({ serviceConfig: {} } as any);
  });

  test("rejects with the failed-attempt count", async () => {
    vi.mocked(createSessionFromChecksAndChallenges).mockRejectedValue({
      findDetails: () => [{ failedAttempts: 2 }],
    });

    await expect(createSessionAndUpdateCookie({ checks: {} as any, requestId: undefined })).rejects.toMatchObject({
      failedAttempts: 2,
    });
  });
});

// Spalk: "Keep me signed in" decides a session's lifetime, its metadata and its cookie entry.
describe("remember me", () => {
  const day = 24 * 60 * 60;
  const policyLifetime = { seconds: BigInt(30 * day), nanos: 0 } as any;
  const remembered = new TextEncoder().encode("true");

  const recentCookie = {
    id: "sessionId",
    token: "sessionToken",
    loginName: "user@example.com",
    creationTs: "1700000000000",
    expirationTs: "1700086400000",
    changeTs: "1700000000000",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.ZITADEL_LOGIN_UNREMEMBERED_SESSION_LIFETIME;

    vi.mocked(headers).mockResolvedValue({} as any);
    vi.mocked(getServiceConfig).mockReturnValue({ serviceConfig: {} } as any);
    vi.mocked(getSecuritySettings).mockResolvedValue({ embeddedIframe: { enabled: false } } as any);
    vi.mocked(getSession).mockResolvedValue({
      session: {
        id: "sessionId",
        expirationDate: { seconds: BigInt(1702592000), nanos: 0 },
        factors: { user: { id: "userId", loginName: "user@example.com", organizationId: "orgId" } },
      },
    } as any);
    vi.mocked(createSessionFromChecksAndChallenges).mockResolvedValue({
      sessionId: "sessionId",
      sessionToken: "sessionToken",
    } as any);
    vi.mocked(createSessionForUserIdAndIdpIntent).mockResolvedValue({
      sessionId: "sessionId",
      sessionToken: "sessionToken",
    } as any);
    vi.mocked(setSession).mockResolvedValue({ sessionToken: "newToken", details: {} } as any);
  });

  function createdWith() {
    return vi.mocked(createSessionFromChecksAndChallenges).mock.calls[0][0];
  }

  function cookieEntry() {
    return vi.mocked(addSessionToCookie).mock.calls[0][0].session;
  }

  test("a ticked box keeps the login policy's lifetime, records the choice and persists the cookie entry", async () => {
    await createSessionAndUpdateCookie({
      checks: {} as any,
      requestId: undefined,
      lifetime: policyLifetime,
      remember: true,
    });

    expect(createdWith().lifetime).toBe(policyLifetime);
    expect(createdWith().metadata).toEqual({ "spalk:remember": remembered });
    expect(cookieEntry().remember).toBe(true);
  });

  test("an unticked box caps the lifetime at 24 hours and clears the choice", async () => {
    await createSessionAndUpdateCookie({
      checks: {} as any,
      requestId: undefined,
      lifetime: policyLifetime,
      remember: false,
    });

    expect(createdWith().lifetime).toEqual({ seconds: BigInt(day), nanos: 0 });
    expect(createdWith().metadata).toEqual({ "spalk:remember": new Uint8Array() });
    expect(cookieEntry().remember).toBeUndefined();
  });

  test("a session nobody was asked about is capped and leaves the metadata alone", async () => {
    await createSessionAndUpdateCookie({ checks: {} as any, requestId: undefined, lifetime: policyLifetime });

    expect(createdWith().lifetime).toEqual({ seconds: BigInt(day), nanos: 0 });
    expect(createdWith().metadata).toBeUndefined();
  });

  test("a shorter policy lifetime than the cap is kept", async () => {
    const short = { seconds: BigInt(60 * 60), nanos: 0 } as any;

    await createSessionAndUpdateCookie({ checks: {} as any, requestId: undefined, lifetime: short, remember: false });

    expect(createdWith().lifetime).toBe(short);
  });

  test.each([
    ["12h", 12 * 60 * 60],
    ["1h30m", 90 * 60],
    ["3600", 3600],
    ["a week", day],
  ])("ZITADEL_LOGIN_UNREMEMBERED_SESSION_LIFETIME=%s caps at %i seconds", async (value, seconds) => {
    process.env.ZITADEL_LOGIN_UNREMEMBERED_SESSION_LIFETIME = value;

    await createSessionAndUpdateCookie({
      checks: {} as any,
      requestId: undefined,
      lifetime: policyLifetime,
      remember: false,
    });

    expect(createdWith().lifetime).toEqual({ seconds: BigInt(seconds), nanos: 0 });
  });

  test("a session update with a choice records it and follows the session's new expiration", async () => {
    await setSessionAndUpdateCookie({ recentCookie, lifetime: policyLifetime, remember: true });

    expect(vi.mocked(setSession).mock.calls[0][0]).toMatchObject({
      lifetime: policyLifetime,
      metadata: { "spalk:remember": remembered },
    });
    expect(vi.mocked(updateSessionCookie).mock.calls[0][0].session).toMatchObject({
      remember: true,
      expirationTs: "1702592000000",
    });
  });

  test("a second factor keeps a remembered session's choice and its own lifetime", async () => {
    const mfaLifetime = { seconds: BigInt(5 * day), nanos: 0 } as any;

    await setSessionAndUpdateCookie({ recentCookie: { ...recentCookie, remember: true }, lifetime: mfaLifetime });

    expect(vi.mocked(setSession).mock.calls[0][0].lifetime).toBe(mfaLifetime);
    expect(vi.mocked(setSession).mock.calls[0][0].metadata).toBeUndefined();
    expect(vi.mocked(updateSessionCookie).mock.calls[0][0].session.remember).toBe(true);
  });

  test("a second factor on a session that wasn't remembered takes the shorter lifetime", async () => {
    await setSessionAndUpdateCookie({ recentCookie, lifetime: policyLifetime });

    expect(vi.mocked(setSession).mock.calls[0][0].lifetime).toEqual({ seconds: BigInt(day), nanos: 0 });
    expect(vi.mocked(updateSessionCookie).mock.calls[0][0].session.remember).toBeUndefined();
  });

  test("an IdP session takes the choice made before leaving for the IdP", async () => {
    vi.mocked(takeRememberMeIntentCookie).mockResolvedValue(true);

    await createSessionForIdpAndUpdateCookie({
      userId: "userId",
      idpIntent: { idpIntentId: "intentId", idpIntentToken: "intentToken" },
      requestId: undefined,
      lifetime: policyLifetime,
    });

    expect(vi.mocked(createSessionForUserIdAndIdpIntent).mock.calls[0][0]).toMatchObject({
      lifetime: policyLifetime,
      metadata: { "spalk:remember": remembered },
    });
    expect(cookieEntry().remember).toBe(true);
  });

  test("an IdP session without a stored choice is not remembered", async () => {
    vi.mocked(takeRememberMeIntentCookie).mockResolvedValue(undefined);

    await createSessionForIdpAndUpdateCookie({
      userId: "userId",
      idpIntent: { idpIntentId: "intentId", idpIntentToken: "intentToken" },
      requestId: undefined,
      lifetime: policyLifetime,
    });

    expect(vi.mocked(createSessionForUserIdAndIdpIntent).mock.calls[0][0]).toMatchObject({
      lifetime: { seconds: BigInt(day), nanos: 0 },
      metadata: undefined,
    });
    expect(cookieEntry().remember).toBeUndefined();
  });
});
