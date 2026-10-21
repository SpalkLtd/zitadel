import { Alert } from "@/components/alert";
import { DynamicTheme } from "@/components/dynamic-theme";
import { LoginPasskey } from "@/components/login-passkey";
import { SignInWithIdp } from "@/components/sign-in-with-idp";
import { Translated } from "@/components/translated";
import { UserAvatar } from "@/components/user-avatar";
import { getSessionCookieById } from "@/lib/cookies";
import { getServiceConfig } from "@/lib/service-url";
import { loadMostRecentSession } from "@/lib/session";
import { getActiveIdentityProviders, getBrandingSettings, getDefaultOrg, getLoginSettings, getSession } from "@/lib/zitadel";
import { Organization } from "@zitadel/proto/zitadel/org/v2/org_pb";
import { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("passkey");
  return { title: t("verify.title") };
}

export default async function Page(props: { searchParams: Promise<Record<string | number | symbol, string | undefined>> }) {
  const searchParams = await props.searchParams;

  const { loginName, altPassword, requestId, organization, sessionId } = searchParams;

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  let defaultOrganization;
  if (!organization) {
    const org: Organization | null = await getDefaultOrg({ serviceConfig });

    if (org) {
      defaultOrganization = org.id;
    }
  }

  let sessionFactors = sessionId ? await loadSessionById(sessionId, organization) : undefined;

  if (!sessionFactors && !sessionId) {
    sessionFactors = await loadMostRecentSession({
      serviceConfig,
      sessionParams: { loginName, organization },
    });
  }

  async function loadSessionById(sessionId: string, organization?: string) {
    const recent = await getSessionCookieById({ sessionId, organization });

    if (!recent) {
      return undefined;
    }

    return getSession({ serviceConfig, sessionId: recent.id, sessionToken: recent.token }).then((response) => {
      if (response?.session) {
        return response.session;
      }
    });
  }

  const branding = await getBrandingSettings({
    serviceConfig,
    organization: organization ?? sessionFactors?.factors?.user?.organizationId ?? defaultOrganization,
  });

  // Spalk: offer the organization's active IdPs below the passkey prompt, so a user whose device lacks their passkey
  // can still sign in with their linked IdP (altPassword only offers the password). Signing in through one logs the
  // user in by their IdP link.
  const loginSettings = await getLoginSettings({
    serviceConfig,
    organization: organization ?? sessionFactors?.factors?.user?.organizationId ?? defaultOrganization,
  });
  const identityProviders = loginSettings?.allowExternalIdp
    ? await getActiveIdentityProviders({
        serviceConfig,
        orgId: organization ?? sessionFactors?.factors?.user?.organizationId ?? defaultOrganization,
      }).then((resp) => resp.identityProviders)
    : [];

  return (
    <DynamicTheme branding={branding}>
      <div className="flex flex-col space-y-4">
        <h1>
          <Translated i18nKey="verify.title" namespace="passkey" />
        </h1>

        <p className="ztdl-p mb-6 block">
          <Translated i18nKey="verify.description" namespace="passkey" />
        </p>

        {sessionFactors ? (
          <UserAvatar
            loginName={loginName ?? sessionFactors.factors?.user?.loginName}
            displayName={sessionFactors.factors?.user?.displayName}
            showDropdown
            searchParams={searchParams}
          ></UserAvatar>
        ) : loginName ? (
          <UserAvatar loginName={loginName} displayName={loginName} showDropdown searchParams={searchParams}></UserAvatar>
        ) : null}
      </div>

      <div className="w-full">
        {!(loginName || sessionId) && (
          <Alert>
            <Translated i18nKey="unknownContext" namespace="error" />
          </Alert>
        )}

        {(loginName || sessionId) && (
          <LoginPasskey
            loginName={loginName}
            sessionId={sessionId}
            requestId={requestId}
            altPassword={altPassword === "true"}
            organization={organization}
          />
        )}

        {/* Spalk: the IdPs as an alternative to the passkey, as on the loginname page. */}
        {(loginName || sessionId) && loginSettings?.allowExternalIdp && !!identityProviders?.length && (
          <div className="w-full pt-6 pb-4">
            <SignInWithIdp
              identityProviders={identityProviders}
              requestId={requestId}
              organization={organization}
              postErrorRedirectUrl="/loginname"
              loginHint={loginName ?? sessionFactors?.factors?.user?.loginName}
            ></SignInWithIdp>
          </div>
        )}
      </div>
    </DynamicTheme>
  );
}
