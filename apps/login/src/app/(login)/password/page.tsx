import { Alert } from "@/components/alert";
import { DynamicTheme } from "@/components/dynamic-theme";
import { PasswordForm } from "@/components/password-form";
import { SignInWithIdp } from "@/components/sign-in-with-idp";
import { Translated } from "@/components/translated";
import { UserAvatar } from "@/components/user-avatar";
import { getServiceConfig } from "@/lib/service-url";
import { loadMostRecentSession } from "@/lib/session";
import { getActiveIdentityProviders, getBrandingSettings, getDefaultOrg, getLoginSettings } from "@/lib/zitadel";
import { Organization } from "@zitadel/proto/zitadel/org/v2/org_pb";
import { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { headers } from "next/headers";

export async function generateMetadata(): Promise<Metadata> {
  const t = await getTranslations("password");
  return { title: t("verify.title") };
}

export default async function Page(props: { searchParams: Promise<Record<string | number | symbol, string | undefined>> }) {
  const searchParams = await props.searchParams;
  let { loginName, organization, requestId } = searchParams;

  const _headers = await headers();
  const { serviceConfig } = getServiceConfig(_headers);

  let defaultOrganization;
  if (!organization) {
    const org: Organization | null = await getDefaultOrg({ serviceConfig });

    if (org) {
      defaultOrganization = org.id;
    }
  }

  // also allow no session to be found (ignoreUnkownUsername)
  const sessionFactors = await loadMostRecentSession({
    serviceConfig,
    sessionParams: {
      loginName,
      organization,
    },
  });

  const branding = await getBrandingSettings({
    serviceConfig,
    organization: organization ?? sessionFactors?.factors?.user?.organizationId ?? defaultOrganization,
  });
  const loginSettings = await getLoginSettings({
    serviceConfig,
    organization: organization ?? sessionFactors?.factors?.user?.organizationId ?? defaultOrganization,
  });

  // Spalk: sendLoginname sends a user with both a password and an IdP here rather than to the IdP, so offer the
  // organization's active IdPs below the form. Signing in through one of them logs the user in by their IdP link.
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
          <Translated i18nKey="verify.title" namespace="password" />
        </h1>
        <p className="ztdl-p">
          <Translated i18nKey="verify.description" namespace="password" />
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
        {/* Only warn when there is no loginName to continue with (e.g. a direct visit
            without searchParams). A failed session lookup alone is not an error: the
            form still works via the user-search fallback in sendPassword, and under
            enumeration protection no session exists by design. */}
        {!loginName && (
          <div className="py-4">
            <Alert>
              <Translated i18nKey="unknownContext" namespace="error" />
            </Alert>
          </div>
        )}

        {loginName && (
          <PasswordForm
            loginName={loginName}
            requestId={requestId}
            organization={organization} // stick to "organization" as we still want to do user discovery based on the searchParams not the default organization, later the organization is determined by the found user
            defaultOrganization={defaultOrganization}
            loginSettings={loginSettings}
          />
        )}

        {/* Spalk: the IdPs as an alternative to the password, as on the loginname page. */}
        {loginName && loginSettings?.allowExternalIdp && !!identityProviders?.length && (
          <div className="w-full pt-6 pb-4">
            <SignInWithIdp
              identityProviders={identityProviders}
              requestId={requestId}
              organization={organization}
              postErrorRedirectUrl="/loginname"
              loginHint={loginName}
            ></SignInWithIdp>
          </div>
        )}
      </div>
    </DynamicTheme>
  );
}
