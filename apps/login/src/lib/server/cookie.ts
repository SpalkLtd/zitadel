"use server";

import { addSessionToCookie, takeRememberMeIntentCookie, updateSessionCookie } from "@/lib/cookies";
import { createLogger } from "@/lib/logger";
import { sanitizeChallenges } from "@/lib/server/challenges";
import {
  createSessionForUserIdAndIdpIntent,
  createSessionFromChecksAndChallenges,
  getSecuritySettings,
  getSession,
  setSession,
} from "@/lib/zitadel";
import { ConnectError, Duration, timestampMs } from "@zitadel/client";
import { CredentialsCheckError, CredentialsCheckErrorSchema, ErrorDetail } from "@zitadel/proto/zitadel/message_pb";
import { Challenges, RequestChallenges } from "@zitadel/proto/zitadel/session/v2/challenge_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { Checks } from "@zitadel/proto/zitadel/session/v2/session_service_pb";
import { headers } from "next/headers";
import { getServiceConfig } from "../service-url";

const logger = createLogger("cookie");

type CustomCookieData = {
  id: string;
  token: string;
  loginName: string;
  organization?: string;
  creationTs: string;
  expirationTs: string;
  changeTs: string;
  requestId?: string; // if its linked to an OIDC flow
  remember?: boolean; // Spalk: the user ticked "Keep me signed in"
};

// Spalk: "Keep me signed in". The session metadata key that records the user's choice ("true" when ticked,
// absent otherwise), which Spalk's API reads with GetSession for the ID token's `sid`.
const REMEMBER_ME_METADATA_KEY = "spalk:remember";
const DEFAULT_UNREMEMBERED_SESSION_LIFETIME_SECONDS = 24 * 60 * 60;

// Spalk: ZITADEL_LOGIN_UNREMEMBERED_SESSION_LIFETIME as seconds: a Go-style duration ("24h", "1h30m", "90s")
// or a plain number of seconds. Unset or invalid values fall back to 24 hours.
function unrememberedSessionLifetimeSeconds(): number {
  const value = process.env.ZITADEL_LOGIN_UNREMEMBERED_SESSION_LIFETIME?.trim();
  if (!value) {
    return DEFAULT_UNREMEMBERED_SESSION_LIFETIME_SECONDS;
  }
  if (/^\d+$/.test(value)) {
    return Number(value) || DEFAULT_UNREMEMBERED_SESSION_LIFETIME_SECONDS;
  }
  if (!/^(\d+[hms])+$/.test(value)) {
    logger.warn(`Invalid ZITADEL_LOGIN_UNREMEMBERED_SESSION_LIFETIME "${value}", using 24h`);
    return DEFAULT_UNREMEMBERED_SESSION_LIFETIME_SECONDS;
  }
  const unitSeconds: Record<string, number> = { h: 3600, m: 60, s: 1 };
  const seconds = (value.match(/\d+[hms]/g) ?? []).reduce(
    (total, part) => total + Number(part.slice(0, -1)) * unitSeconds[part.slice(-1)],
    0,
  );
  return seconds || DEFAULT_UNREMEMBERED_SESSION_LIFETIME_SECONDS;
}

// Spalk: a session the user didn't ask to remember lives no longer than the unremembered lifetime, whatever
// the login policy allows; a remembered one gets the policy's lifetime.
function lifetimeForRemember(lifetime: Duration, remember: boolean): Duration {
  const cap = unrememberedSessionLifetimeSeconds();
  if (remember || Number(lifetime.seconds) + (lifetime.nanos ?? 0) / 1e9 <= cap) {
    return lifetime;
  }
  return { seconds: BigInt(cap), nanos: 0 } as Duration;
}

// Spalk: the session metadata for an explicit choice; an empty value removes the key.
function rememberMetadata(remember: boolean | undefined): Record<string, Uint8Array> | undefined {
  if (remember === undefined) {
    return undefined;
  }
  return { [REMEMBER_ME_METADATA_KEY]: remember ? new TextEncoder().encode("true") : new Uint8Array() };
}

const passwordAttemptsHandler = (error: ConnectError) => {
  const details = error.findDetails(CredentialsCheckErrorSchema);

  if (details[0] && "failedAttempts" in details[0]) {
    const failedAttempts = details[0].failedAttempts;
    throw {
      error: `Failed to authenticate: You had ${failedAttempts} password attempts.`,
      failedAttempts: failedAttempts,
    };
  }
  throw error;
};

export async function createSessionAndUpdateCookie(command: {
  checks: Checks;
  requestId: string | undefined;
  lifetime?: Duration;
  challenges?: RequestChallenges;
  remember?: boolean; // Spalk: the user's "Keep me signed in" choice, if they were asked
}): Promise<{ session: Session; sessionCookie: CustomCookieData; challenges?: Challenges }> {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  let sessionLifetime = command.lifetime;

  if (!sessionLifetime || !sessionLifetime.seconds) {
    logger.warn("No session lifetime provided, using default of 24 hours");

    sessionLifetime = {
      seconds: BigInt(24 * 60 * 60), // 24 hours
      nanos: 0,
    } as Duration; // for usecases where the lifetime is not specified (user discovery)
  }

  // Spalk: a wrong password carries its failed-attempt count here too, as it does for setSessionAndUpdateCookie.
  const createdSession = await createSessionFromChecksAndChallenges({
    serviceConfig,
    checks: command.checks,
    lifetime: lifetimeForRemember(sessionLifetime, !!command.remember),
    challenges: sanitizeChallenges(command.challenges),
    metadata: rememberMetadata(command.remember),
  }).catch(passwordAttemptsHandler);

  if (createdSession) {
    return getSession({
      serviceConfig,
      sessionId: createdSession.sessionId,
      sessionToken: createdSession.sessionToken,
    }).then(async (response) => {
      if (response?.session && response.session?.factors?.user?.loginName) {
        const sessionCookie: CustomCookieData = {
          id: createdSession.sessionId,
          token: createdSession.sessionToken,
          creationTs: response.session.creationDate ? `${timestampMs(response.session.creationDate)}` : "",
          expirationTs: response.session.expirationDate ? `${timestampMs(response.session.expirationDate)}` : "",
          changeTs: response.session.changeDate ? `${timestampMs(response.session.changeDate)}` : "",
          loginName: response.session.factors.user.loginName ?? "",
        };

        if (command.requestId) {
          sessionCookie.requestId = command.requestId;
        }

        if (command.remember) {
          sessionCookie.remember = true;
        }

        if (response.session.factors.user.organizationId) {
          sessionCookie.organization = response.session.factors.user.organizationId;
        }

        const securitySettings = await getSecuritySettings({ serviceConfig });
        const iFrameEnabled = !!securitySettings?.embeddedIframe?.enabled;

        await addSessionToCookie({ session: sessionCookie, iFrameEnabled });

        return { session: response.session as Session, sessionCookie, challenges: createdSession.challenges };
      } else {
        throw new Error("could not get session or session does not have loginName");
      }
    });
  } else {
    throw new Error("Could not create session");
  }
}

export async function createSessionForIdpAndUpdateCookie({
  userId,
  idpIntent,
  requestId,
  lifetime,
  remember,
}: {
  userId: string;
  idpIntent: {
    idpIntentId?: string | undefined;
    idpIntentToken?: string | undefined;
  };
  requestId: string | undefined;
  lifetime?: Duration;
  remember?: boolean; // Spalk: defaults to the choice made before leaving for the IdP
}): Promise<Session> {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  let sessionLifetime = lifetime;

  if (!sessionLifetime || !sessionLifetime.seconds) {
    logger.warn("No IDP session lifetime provided, using default of 24 hours");

    sessionLifetime = {
      seconds: BigInt(24 * 60 * 60), // 24 hours
      nanos: 0,
    } as Duration;
  }

  // Spalk: the choice the user made before leaving for the IdP
  const rememberChoice = remember ?? (await takeRememberMeIntentCookie());

  const createdSession = await createSessionForUserIdAndIdpIntent({
    serviceConfig,
    userId,
    idpIntent,
    lifetime: lifetimeForRemember(sessionLifetime, !!rememberChoice),
    metadata: rememberMetadata(rememberChoice),
  }).catch((error: ErrorDetail | CredentialsCheckError) => {
    logger.error("Could not set session", { error });
    if ("failedAttempts" in error && error.failedAttempts) {
      throw {
        error: `Failed to authenticate: You had ${error.failedAttempts} password attempts.`,
        failedAttempts: error.failedAttempts,
      };
    }
    throw error;
  });

  if (!createdSession) {
    throw new Error("Could not create session");
  }

  const { session } = await getSession({
    serviceConfig,
    sessionId: createdSession.sessionId,
    sessionToken: createdSession.sessionToken,
  });

  if (!session || !session.factors?.user?.loginName) {
    throw new Error("Could not retrieve session");
  }

  const sessionCookie: CustomCookieData = {
    id: createdSession.sessionId,
    token: createdSession.sessionToken,
    creationTs: session.creationDate ? `${timestampMs(session.creationDate)}` : "",
    expirationTs: session.expirationDate ? `${timestampMs(session.expirationDate)}` : "",
    changeTs: session.changeDate ? `${timestampMs(session.changeDate)}` : "",
    loginName: session.factors.user.loginName ?? "",
    organization: session.factors.user.organizationId ?? "",
  };

  if (requestId) {
    sessionCookie.requestId = requestId;
  }

  if (rememberChoice) {
    sessionCookie.remember = true;
  }

  if (session.factors.user.organizationId) {
    sessionCookie.organization = session.factors.user.organizationId;
  }

  const securitySettings = await getSecuritySettings({ serviceConfig });
  const iFrameEnabled = !!securitySettings?.embeddedIframe?.enabled;

  return addSessionToCookie({ session: sessionCookie, iFrameEnabled }).then(() => {
    return session as Session;
  });
}

export type SessionWithChallenges = Session & {
  challenges: Challenges | undefined;
};

export async function setSessionAndUpdateCookie(command: {
  recentCookie: CustomCookieData;
  checks?: Checks;
  challenges?: RequestChallenges;
  requestId?: string;
  lifetime: Duration;
  remember?: boolean; // Spalk: the user's "Keep me signed in" choice, if they were asked on this step
}) {
  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  // Spalk: a step that doesn't ask (e.g. a second factor) keeps the session's earlier choice
  const remember = command.remember ?? !!command.recentCookie.remember;

  return setSession({
    serviceConfig,
    sessionId: command.recentCookie.id,
    sessionToken: command.recentCookie.token,
    challenges: sanitizeChallenges(command.challenges),
    checks: command.checks,
    lifetime: lifetimeForRemember(command.lifetime, remember),
    metadata: rememberMetadata(command.remember),
  })
    .then((updatedSession) => {
      if (updatedSession) {
        const sessionCookie: CustomCookieData = {
          id: command.recentCookie.id,
          token: updatedSession.sessionToken,
          creationTs: command.recentCookie.creationTs,
          expirationTs: command.recentCookie.expirationTs,
          // just overwrite the changeDate with the new one
          changeTs: updatedSession.details?.changeDate ? `${timestampMs(updatedSession.details.changeDate)}` : "",
          loginName: command.recentCookie.loginName,
          organization: command.recentCookie.organization,
        };

        if (command.requestId) {
          sessionCookie.requestId = command.requestId;
        }

        return getSession({ serviceConfig, sessionId: sessionCookie.id, sessionToken: sessionCookie.token }).then(
          async (response) => {
            if (!response?.session || !response.session.factors?.user?.loginName) {
              throw new Error("could not get session or session does not have loginName");
            }

            const { session } = response;
            const newCookie: CustomCookieData = {
              id: sessionCookie.id,
              token: updatedSession.sessionToken,
              creationTs: sessionCookie.creationTs,
              // Spalk: a new lifetime moves the expiration, which the remembered cookie's own expiry follows
              expirationTs: session.expirationDate ? `${timestampMs(session.expirationDate)}` : sessionCookie.expirationTs,
              // just overwrite the changeDate with the new one
              changeTs: updatedSession.details?.changeDate ? `${timestampMs(updatedSession.details.changeDate)}` : "",
              loginName: session.factors?.user?.loginName ?? "",
              organization: session.factors?.user?.organizationId ?? "",
            };

            if (sessionCookie.requestId) {
              newCookie.requestId = sessionCookie.requestId;
            }

            if (remember) {
              newCookie.remember = true;
            }

            const securitySettings = await getSecuritySettings({ serviceConfig });
            const iFrameEnabled = !!securitySettings?.embeddedIframe?.enabled;

            return updateSessionCookie({
              id: sessionCookie.id,
              session: newCookie,
              iFrameEnabled,
            }).then(() => {
              return { challenges: updatedSession.challenges, ...session };
            });
          },
        );
      } else {
        throw new Error("Session could not be set");
      }
    })
    .catch(passwordAttemptsHandler);
}
