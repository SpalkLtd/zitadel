// Spalk: registerUserAndLinkToIDP creates the user from the IdP intent, in one call.
import * as cookie from "@/lib/server/cookie";
import * as zitadel from "@/lib/zitadel";
import { Code, ConnectError, create } from "@zitadel/client";
import { CreateUserRequest, CreateUserRequestSchema } from "@zitadel/proto/zitadel/user/v2/user_service_pb";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { registerUserAndLinkToIDP } from "./register";

vi.mock("next/headers", () => ({
  headers: vi.fn(async () => new Headers()),
  cookies: vi.fn(),
}));

vi.mock("next-intl/server", () => ({
  getTranslations: vi.fn(async () => (key: string) => key),
}));

vi.mock("../service-url", () => ({
  getServiceConfig: vi.fn(() => ({ serviceConfig: {} })),
}));

vi.mock("@/lib/zitadel", () => ({
  addHumanUser: vi.fn(),
  createUser: vi.fn(),
  getLoginSettings: vi.fn(),
  getUserByID: vi.fn(),
  listAuthenticationMethodTypes: vi.fn(),
  retrieveIDPIntent: vi.fn(),
}));

vi.mock("@/lib/server/cookie", () => ({
  createSessionAndUpdateCookie: vi.fn(),
  createSessionForIdpAndUpdateCookie: vi.fn(),
}));

vi.mock("../verify-helper", () => ({
  checkEmailVerification: vi.fn(),
  checkMFAFactors: vi.fn(),
}));

vi.mock("../client", () => ({
  completeFlowOrGetUrl: vi.fn(async () => ({ redirect: "/done" })),
}));

vi.mock("../fingerprint", () => ({
  getOrSetFingerprintId: vi.fn(),
}));

const command = {
  email: "someone-else@example.com",
  firstName: "Ada",
  lastName: "Lovelace",
  organization: "default-org",
  idpIntent: { idpIntentId: "intent-1", idpIntentToken: "token-1" },
  idpUserId: "g-1",
  idpId: "google",
  idpUserName: "ada@example.com",
};

// An intent from Google with no family name: login v2 sends the person to the
// complete-registration form for it.
function intentWithoutFamilyName() {
  return {
    userAction: {
      case: "createUser",
      value: create(CreateUserRequestSchema, {
        username: "ada@example.com",
        userType: {
          case: "human",
          value: {
            profile: { givenName: "Ada", displayName: "Ada" },
            email: { email: "ada@example.com", verification: { case: "isVerified", value: true } },
            idpLinks: [{ idpId: "google", userId: "g-1", userName: "ada@example.com" }],
          },
        },
      }),
    },
  };
}

describe("registerUserAndLinkToIDP", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(zitadel.getLoginSettings).mockResolvedValue({ allowRegister: true } as any);
    vi.mocked(zitadel.retrieveIDPIntent).mockResolvedValue(intentWithoutFamilyName() as any);
    vi.mocked(zitadel.createUser).mockResolvedValue({ id: "new-user" } as any);
    vi.mocked(zitadel.listAuthenticationMethodTypes).mockResolvedValue({ authMethodTypes: [] } as any);
    vi.mocked(cookie.createSessionForIdpAndUpdateCookie).mockResolvedValue({
      id: "session-1",
      factors: { user: { id: "new-user", loginName: "ada", organizationId: "default-org" } },
    } as any);
  });

  test("creates the user with the IdP's verified email and link, and the form's names, in one call", async () => {
    const result = await registerUserAndLinkToIDP(command);

    expect(result).toEqual({ redirect: "/done" });
    expect(zitadel.retrieveIDPIntent).toHaveBeenCalledWith({ serviceConfig: {}, id: "intent-1", token: "token-1" });
    expect(zitadel.addHumanUser).not.toHaveBeenCalled();
    expect(zitadel.createUser).toHaveBeenCalledTimes(1);
    const request = vi.mocked(zitadel.createUser).mock.calls[0][0].request as CreateUserRequest;
    expect(request.organizationId).toBe("default-org");
    expect(request.userType.case).toBe("human");
    const human = request.userType.value as any;
    expect(human.email.email).toBe("ada@example.com");
    expect(human.email.verification).toEqual({ case: "isVerified", value: true });
    expect(human.idpLinks).toHaveLength(1);
    expect(human.idpLinks[0].userId).toBe("g-1");
    expect(human.profile.givenName).toBe("Ada");
    expect(human.profile.familyName).toBe("Lovelace");
    expect(human.profile.displayName).toBe("Ada");
    expect(cookie.createSessionForIdpAndUpdateCookie).toHaveBeenCalledWith(
      expect.objectContaining({ userId: "new-user", idpIntent: command.idpIntent }),
    );
  });

  test("shows the user-creation hook's message for a taken email", async () => {
    vi.mocked(zitadel.createUser).mockRejectedValue(
      new ConnectError("An account with this email already exists.", Code.AlreadyExists),
    );

    const result = await registerUserAndLinkToIDP(command);

    expect(result).toEqual({ error: "An account with this email already exists." });
    expect(cookie.createSessionForIdpAndUpdateCookie).not.toHaveBeenCalled();
  });

  test("an intent that can't be retrieved creates nobody", async () => {
    vi.mocked(zitadel.retrieveIDPIntent).mockRejectedValue(new Error("expired"));

    const result = await registerUserAndLinkToIDP(command);

    expect(result).toEqual({ error: "errors.couldNotCreateUser" });
    expect(zitadel.createUser).not.toHaveBeenCalled();
  });
});
