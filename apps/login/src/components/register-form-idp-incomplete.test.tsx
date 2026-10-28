import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { RegisterFormIDPIncomplete } from "./register-form-idp-incomplete";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string) => key,
}));

vi.mock("@/lib/server/register", () => ({
  registerUserAndLinkToIDP: vi.fn(),
}));

vi.mock("@/lib/client", () => ({
  handleServerActionResponse: vi.fn(),
}));

const defaultProps = {
  organization: "org-1",
  idpIntent: { idpIntentId: "intent-1", idpIntentToken: "token-1" },
  idpUserId: "user-1",
  idpId: "idp-1",
};

describe("RegisterFormIDPIncomplete", () => {
  afterEach(cleanup);

  test("should autofocus the username input when idpUserName is not provided", () => {
    const { getByTestId } = render(<RegisterFormIDPIncomplete {...defaultProps} />);
    expect(getByTestId("username-text-input")).toHaveFocus();
  });

  test("should autofocus the firstname input when idpUserName is provided", () => {
    const { getByTestId } = render(<RegisterFormIDPIncomplete {...defaultProps} idpUserName="existing-user" />);
    expect(getByTestId("firstname-text-input")).toHaveFocus();
  });

  // Spalk: the user gets the identity provider's email, so it can't be edited
  test("shows the identity provider's email read-only", () => {
    const { getByTestId } = render(
      <RegisterFormIDPIncomplete {...defaultProps} defaultValues={{ email: "person@example.com" }} />,
    );
    const email = getByTestId("email-text-input");
    expect(email).toHaveValue("person@example.com");
    expect(email).toHaveAttribute("readonly");
  });
});
