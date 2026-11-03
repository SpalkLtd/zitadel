// Spalk: moved out of lib/server/idp-intent.ts, a server-action module, so that
// registerUserAndLinkToIDP (lib/server/register.ts) builds the same request.
import type { retrieveIDPIntent } from "@/lib/zitadel";
import { create } from "@zitadel/client";
import { CreateUserRequest, CreateUserRequestSchema } from "@zitadel/proto/zitadel/user/v2/user_service_pb";

type IDPIntentResult = Awaited<ReturnType<typeof retrieveIDPIntent>>;

/**
 * Builds the request for the non-deprecated CreateUser endpoint from an IDP intent response.
 *
 * Prefers the new `user_action.create_user` oneof: the action's request is passed through as-is
 * and only the resolved organization is injected. Falls back to mapping the deprecated
 * `add_human_user` (flat) fields into the new nested shape for older API responses.
 */
export function buildCreateUserRequest(intent: IDPIntentResult, organizationId: string): CreateUserRequest | undefined {
  if (intent.userAction?.case === "createUser") {
    return create(CreateUserRequestSchema, {
      ...intent.userAction.value,
      organizationId,
    });
  }

  // Fallback: map the deprecated flat add_human_user payload into the CreateUserRequest shape.
  if (intent.addHumanUser) {
    const add = intent.addHumanUser;
    return create(CreateUserRequestSchema, {
      organizationId,
      username: add.username,
      userType: {
        case: "human",
        value: {
          profile: add.profile,
          email: add.email,
          phone: add.phone,
          idpLinks: add.idpLinks,
        },
      },
      // SetMetadataEntry and Metadata share the same {key, value} shape; map explicitly.
      metadata: add.metadata?.map((entry) => ({ key: entry.key, value: entry.value })),
    });
  }

  return undefined;
}

/**
 * Spalk: for a user the login creates and then signs in with createNewSessionFromIdpIntent. When the
 * IdP did not verify the email, Zitadel's intent asks CreateUser to send a code; the sign-in's
 * checkEmailVerification then sends a second one that replaces it, so the first emailed code is
 * rejected. Creating the email as unverified (as ordinary registration does) leaves the login's send
 * as the only code. A verified email is left untouched.
 */
export function withoutCreateEmailCode(request: CreateUserRequest): CreateUserRequest {
  if (request.userType.case !== "human") {
    return request;
  }
  const email = request.userType.value.email;
  if (email?.verification?.case !== "sendCode") {
    return request;
  }
  return {
    ...request,
    userType: {
      case: "human",
      value: {
        ...request.userType.value,
        email: { ...email, verification: { case: "isVerified", value: false } },
      },
    },
  };
}
