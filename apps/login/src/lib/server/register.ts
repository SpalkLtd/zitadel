"use server";

import { createSessionAndUpdateCookie, createSessionForIdpAndUpdateCookie } from "@/lib/server/cookie";
import {
  addHumanUser,
  createUser,
  getLoginSettings,
  getUserByID,
  listAuthenticationMethodTypes,
  retrieveIDPIntent,
} from "@/lib/zitadel";
import { Code, ConnectError, Duration, create } from "@zitadel/client";
import { Factors } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { Checks, ChecksJson, ChecksSchema } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { SetHumanProfileSchema } from "@zitadel/proto/zitadel/user/v2/user_pb";
import crypto from "crypto";
import { getTranslations } from "next-intl/server";
import { cookies, headers } from "next/headers";
import { completeFlowOrGetUrl } from "../client";
import { getOrSetFingerprintId } from "../fingerprint";
import { buildCreateUserRequest } from "../idp-create-user";
import { createLogger } from "../logger";
import { getServiceConfig } from "../service-url";
import { checkEmailVerification, checkMFAFactors } from "../verify-helper";

const logger = createLogger("register");

const MAX_SESSION_RETRIES = 3;
const RETRY_DELAYS_MS = [500, 1000, 2000];

/**
 * After user creation, backend projections (users, login_names) may not be updated yet.
 * This helper retries createSessionAndUpdateCookie on NotFound errors with increasing delays.
 */
async function createSessionWithRetry(command: { checks: Checks; requestId: string | undefined; lifetime?: Duration }) {
  let lastError: unknown;
  for (let attempt = 0; attempt < MAX_SESSION_RETRIES; attempt++) {
    try {
      return await createSessionAndUpdateCookie(command);
    } catch (error) {
      lastError = error;
      const isNotFound = error instanceof ConnectError && error.code === Code.NotFound;
      const isLastAttempt = attempt + 1 >= MAX_SESSION_RETRIES;
      if (!isNotFound || isLastAttempt) {
        throw error;
      }
      const delay = RETRY_DELAYS_MS[attempt] ?? 2000;
      logger.warn(
        `Session creation failed with NotFound (attempt ${attempt + 1}/${MAX_SESSION_RETRIES}), retrying in ${delay}ms...`,
      );
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
  throw lastError;
}

// Spalk: alreadyExistsMessage is the message of a user-creation error that says the
// username or email is taken: Zitadel's own, or the one Spalk's user-creation hook
// gives (a 409, which Zitadel returns as AlreadyExists), without Zitadel's error ID.
function alreadyExistsMessage(error: unknown): string | undefined {
  if (!(error instanceof ConnectError) || error.code !== Code.AlreadyExists) {
    return undefined;
  }
  return error.rawMessage.replace(/ \([A-Za-z0-9]+-[A-Za-z0-9]+\)$/, "") || undefined;
}

type RegisterUserCommand = {
  email: string;
  firstName: string;
  lastName: string;
  username?: string; // Spalk: the username the user chose
  password?: string;
  organization: string;
  requestId?: string;
};

export type RegisterUserResponse = {
  userId: string;
  sessionId: string;
  factors: Factors | undefined;
};
export async function registerUser(
  command: RegisterUserCommand,
): Promise<{ error: string } | { redirect: string } | { samlData: { url: string; fields: Record<string, string> } }> {
  const t = await getTranslations("register");
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const loginSettings = await getLoginSettings({ serviceConfig, organization: command.organization });

  if (!loginSettings) {
    return { error: t("errors.couldNotGetLoginSettings") };
  }

  if (!loginSettings.allowRegister) {
    return { error: t("errors.registerNotAllowed") };
  }

  if (command.password && !loginSettings.allowLocalAuthentication) {
    return { error: t("errors.localAuthenticationNotAllowed") };
  }

  const addResponse = await addHumanUser({
    serviceConfig,
    email: command.email,
    firstName: command.firstName,
    lastName: command.lastName,
    username: command.username,
    password: command.password ? command.password : undefined,
    organization: command.organization,
  }).catch((error) => {
    logger.error("Failed to create user", { error });
    // Spalk: a taken username or email is the user's to fix, so they are told which
    return alreadyExistsMessage(error) ?? null;
  });

  if (!addResponse) {
    return { error: t("errors.couldNotCreateUser") };
  }
  if (typeof addResponse === "string") {
    return { error: addResponse };
  }

  let checkPayload: any = {
    user: { search: { case: "userId", value: addResponse.userId } },
  };

  if (command.password) {
    checkPayload = {
      ...checkPayload,
      password: { password: command.password },
    } as ChecksJson;
  }

  const checks = create(ChecksSchema, checkPayload);

  const result = await createSessionWithRetry({
    checks,
    requestId: command.requestId,
    lifetime: command.password ? loginSettings?.passwordCheckLifetime : undefined,
  }).catch((error) => {
    logger.error("Failed to create session after user creation", { error });
    return null;
  });

  const session = result?.session;

  if (!session || !session.factors?.user) {
    return { error: t("errors.couldNotCreateSession") };
  }

  if (!command.password) {
    const params = new URLSearchParams({
      loginName: session.factors.user.loginName,
      organization: session.factors.user.organizationId,
    });

    if (command.requestId) {
      params.append("requestId", command.requestId);
    }

    // Set verification cookie for users registering with passkey (no password)
    // This allows them to proceed with passkey registration without additional verification
    const cookiesList = await cookies();
    const userAgentId = await getOrSetFingerprintId();

    const verificationCheck = crypto.createHash("sha256").update(`${session.factors.user.id}:${userAgentId}`).digest("hex");

    await cookiesList.set({
      name: "verificationCheck",
      value: verificationCheck,
      httpOnly: true,
      path: "/",
      maxAge: 300, // 5 minutes
    });

    return { redirect: "/passkey/set?" + params };
  } else {
    const userResponse = await getUserByID({ serviceConfig, userId: session?.factors?.user?.id }).catch((error) => {
      logger.error("Failed to get user after session creation", { error });
      return null;
    });

    if (!userResponse?.user) {
      return { error: t("errors.userNotFound") };
    }

    const humanUser = userResponse.user.type.case === "human" ? userResponse.user.type.value : undefined;

    const emailVerificationCheck = await checkEmailVerification(
      session,
      humanUser,
      session.factors.user.organizationId,
      command.requestId,
    );

    if (emailVerificationCheck?.redirect) {
      return emailVerificationCheck;
    }

    return completeFlowOrGetUrl(
      command.requestId && session.id
        ? {
            sessionId: session.id,
            requestId: command.requestId,
            organization: session.factors.user.organizationId,
          }
        : {
            loginName: session.factors.user.loginName,
            organization: session.factors.user.organizationId,
          },
      loginSettings?.defaultRedirectUri,
    );
  }
}

type RegisterUserAndLinkToIDPommand = {
  email: string;
  firstName: string;
  lastName: string;
  organization: string;
  requestId?: string;
  idpIntent: {
    idpIntentId: string;
    idpIntentToken: string;
  };
  idpUserId: string;
  idpId: string;
  idpUserName: string;
};

export type registerUserAndLinkToIDPResponse = {
  userId: string;
  sessionId: string;
  factors: Factors | undefined;
};
export async function registerUserAndLinkToIDP(
  command: RegisterUserAndLinkToIDPommand,
): Promise<{ error: string } | { redirect: string } | { samlData: { url: string; fields: Record<string, string> } }> {
  const t = await getTranslations("register");

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  const loginSettings = await getLoginSettings({ serviceConfig, organization: command.organization });

  if (!loginSettings) {
    return { error: t("errors.couldNotGetLoginSettings") };
  }

  if (!loginSettings.allowRegister) {
    return { error: t("errors.registerNotAllowed") };
  }

  // Spalk: the user is created as login v2's auto-creation creates one, from the
  // IdP intent, retrieved again here: with the IdP's email, verified as the IdP
  // says, and the IdP link, in one call. Only the names come from the form,
  // which the IdP left out. Upstream created the user from the form, its email
  // unverified and editable, then linked the IdP in a second call, which
  // Spalk's user-creation hook refuses for an unverified email, leaving a user
  // with neither a password nor a link. The form's email is not used.
  const intent = await retrieveIDPIntent({
    serviceConfig,
    id: command.idpIntent.idpIntentId,
    token: command.idpIntent.idpIntentToken,
  }).catch((error) => {
    logger.error("Failed to retrieve the IDP intent", { error });
    return undefined;
  });
  const createUserRequest = intent ? buildCreateUserRequest(intent, command.organization) : undefined;
  if (!createUserRequest || createUserRequest.userType.case !== "human") {
    return { error: t("errors.couldNotCreateUser") };
  }
  const human = createUserRequest.userType.value;
  human.profile = create(SetHumanProfileSchema, {
    ...human.profile,
    givenName: command.firstName,
    familyName: command.lastName,
  });

  const addUserResponse = await createUser({ serviceConfig, request: createUserRequest })
    .then((response) => ({ userId: response.id }))
    .catch((error) => {
      logger.error("Failed to create user", { error });
      return alreadyExistsMessage(error) ?? null;
    });
  if (!addUserResponse) {
    return { error: t("errors.couldNotCreateUser") };
  }
  if (typeof addUserResponse === "string") {
    return { error: addUserResponse };
  }

  const session = await createSessionForIdpAndUpdateCookie({
    requestId: command.requestId,
    userId: addUserResponse.userId, // the user we just created
    idpIntent: command.idpIntent,
    lifetime: loginSettings?.externalLoginCheckLifetime,
  });

  if (!session || !session.factors?.user) {
    return { error: t("errors.couldNotCreateSession") };
  }

  // const userResponse = await getUserByID({
  //   serviceConfig.baseUrl,
  //   userId: session?.factors?.user?.id,
  // });

  // if (!userResponse.user) {
  //   return { error: "User not found in the system" };
  // }

  // const humanUser = userResponse.user.type.case === "human" ? userResponse.user.type.value : undefined;

  // check to see if user was verified
  // const emailVerificationCheck = checkEmailVerification(session, humanUser, command.organization, command.requestId);

  // if (emailVerificationCheck?.redirect) {
  //   return emailVerificationCheck;
  // }

  // check if user has MFA methods
  let authMethods;
  if (session.factors?.user?.id) {
    const response = await listAuthenticationMethodTypes({ serviceConfig, userId: session.factors.user.id });
    if (response.authMethodTypes && response.authMethodTypes.length) {
      authMethods = response.authMethodTypes;
    }
  }

  // Always check MFA factors, even if no auth methods are configured
  // This ensures that force MFA settings are respected
  const mfaFactorCheck = await checkMFAFactors(
    serviceConfig,
    session,
    loginSettings,
    authMethods || [], // Pass empty array if no auth methods
    command.organization,
    command.requestId,
  );

  if (mfaFactorCheck?.redirect) {
    return mfaFactorCheck;
  }

  return completeFlowOrGetUrl(
    command.requestId && session.id
      ? {
          sessionId: session.id,
          requestId: command.requestId,
          organization: session.factors.user.organizationId,
        }
      : {
          loginName: session.factors.user.loginName,
          organization: session.factors.user.organizationId,
        },
    loginSettings?.defaultRedirectUri,
  );
}
