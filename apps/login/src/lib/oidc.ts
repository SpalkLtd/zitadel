import { isSafeRedirectUri } from "@/lib/client-utils";
import { Cookie } from "@/lib/cookies";
import { isClassifiedError } from "@/lib/grpc/interceptors/error-classification";
import { sendLoginname, SendLoginnameCommand } from "@/lib/server/loginname";
import { createCallback, getLoginSettings, ServiceConfig } from "@/lib/zitadel";
import { Code, create } from "@zitadel/client";
import { ErrorReason } from "@zitadel/proto/zitadel/oidc/v2/authorization_pb";
import { CreateCallbackRequestSchema, SessionSchema } from "@zitadel/proto/zitadel/oidc/v2/oidc_service_pb";
import { Session } from "@zitadel/proto/zitadel/session/v2/session_pb";
import { isSessionValid } from "./session";

type LoginWithOIDCAndSession = {
  serviceConfig: ServiceConfig;
  authRequest: string;
  sessionId: string;
  sessions: Session[];
  sessionCookies: Cookie[];
};
export async function loginWithOIDCAndSession({
  serviceConfig,
  authRequest,
  sessionId,
  sessions,
  sessionCookies,
}: LoginWithOIDCAndSession): Promise<{ error: string } | { redirect: string }> {
  const selectedSession = sessions.find((s) => s.id === sessionId);

  if (selectedSession && selectedSession.id) {
    const isValid = await isSessionValid({ serviceConfig, session: selectedSession });

    console.log("Session is valid:", isValid);

    if (!isValid && selectedSession.factors?.user) {
      // if the session is not valid anymore, we need to redirect the user to re-authenticate /
      // TODO: handle IDP intent direcly if available
      const command: SendLoginnameCommand = {
        loginName: selectedSession.factors.user?.loginName,
        organization: selectedSession.factors?.user?.organizationId,
        requestId: `oidc_${authRequest}`,
      };

      const res = await sendLoginname(command);

      if (res && "redirect" in res && res?.redirect) {
        return { redirect: res.redirect };
      }
    }

    const cookie = sessionCookies.find((cookie) => cookie.id === selectedSession?.id);

    if (cookie && cookie.id && cookie.token) {
      const session = {
        sessionId: cookie?.id,
        sessionToken: cookie?.token,
      };

      try {
        const { callbackUrl } = await createCallback({
          serviceConfig,
          req: create(CreateCallbackRequestSchema, {
            authRequestId: authRequest,
            callbackKind: {
              case: "session",
              value: create(SessionSchema, session),
            },
          }),
        });
        if (callbackUrl) {
          if (!isSafeRedirectUri(callbackUrl)) {
            console.warn("loginWithOIDCAndSession: Blocked unsafe OIDC callback URL:", callbackUrl);
            return { error: "Unsafe redirect URI was blocked" };
          }
          return { redirect: callbackUrl };
        } else {
          return { error: "An error occurred!" };
        }
      } catch (error: unknown) {
        // handle already handled gracefully as these could come up if old emails with requestId are used (reset password, register emails etc.)
        console.error(error);
        // Spalk: Zitadel refuses a user outside the organisation the auth request scopes
        // (COMMAND-59ljd, Errors.User.NotAllowedOrg). Fail the auth request with access_denied so
        // the app hears of it, rather than going to the default redirect, which restarts the login.
        if (isClassifiedError(error) && error.code === Code.FailedPrecondition && error.message.includes("COMMAND-59ljd")) {
          const denied = await createCallback({
            serviceConfig,
            req: create(CreateCallbackRequestSchema, {
              authRequestId: authRequest,
              callbackKind: {
                case: "error",
                value: {
                  error: ErrorReason.ACCESS_DENIED,
                  errorDescription: "This account isn't a member of the organisation it tried to log in to",
                },
              },
            }),
          }).catch((err: unknown) => {
            console.error(err);
            return undefined;
          });
          if (denied?.callbackUrl && isSafeRedirectUri(denied.callbackUrl)) {
            return { redirect: denied.callbackUrl };
          }
          return { error: "This account isn't a member of the organisation it tried to log in to" };
        }
        if (isClassifiedError(error) && error.code === Code.FailedPrecondition) {
          const loginSettings = await getLoginSettings({
            serviceConfig,
            organization: selectedSession.factors?.user?.organizationId,
          });

          if (loginSettings?.defaultRedirectUri && isSafeRedirectUri(loginSettings.defaultRedirectUri)) {
            return { redirect: loginSettings.defaultRedirectUri };
          } else if (loginSettings?.defaultRedirectUri) {
            console.warn("loginWithOIDCAndSession: Unsafe defaultRedirectUri prevented:", loginSettings.defaultRedirectUri);
          }

          const signedinUrl = "/signedin";

          const params = new URLSearchParams();
          if (selectedSession.factors?.user?.loginName) {
            params.append("loginName", selectedSession.factors?.user?.loginName);
          }
          if (selectedSession.factors?.user?.organizationId) {
            params.append("organization", selectedSession.factors?.user?.organizationId);
          }
          return { redirect: signedinUrl + "?" + params.toString() };
        } else {
          return { error: "Unknown error occurred" };
        }
      }
    }
  }

  // If no session found or no valid cookie, return error
  return { error: "Session not found or invalid" };
}
