import { registerUser } from "@/lib/server/register";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { create } from "@zitadel/client";
import { LegalAndSupportSettingsSchema } from "@zitadel/proto/zitadel/settings/v2/legal_settings_pb";
import { afterEach, describe, expect, test, vi } from "vitest";
import { RegisterForm } from "./register-form";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string) => key,
}));

vi.mock("@/lib/server/register", () => ({
  registerUser: vi.fn(),
}));

vi.mock("@/lib/client", () => ({
  handleServerActionResponse: vi.fn(),
}));

const defaultLegal = create(LegalAndSupportSettingsSchema, {});

describe("RegisterForm", () => {
  afterEach(cleanup);

  test("should autofocus the firstname input on mount", () => {
    const { getByTestId } = render(<RegisterForm legal={defaultLegal} organization="org-1" idpCount={0} />);
    expect(getByTestId("firstname-text-input")).toHaveFocus();
  });

  // Spalk: the user chooses their username, which Zitadel's login would otherwise make their email
  describe("username", () => {
    function fill(getByTestId: (id: string) => HTMLElement, username: string) {
      fireEvent.change(getByTestId("firstname-text-input"), { target: { value: "Ada" } });
      fireEvent.change(getByTestId("lastname-text-input"), { target: { value: "Lovelace" } });
      fireEvent.change(getByTestId("email-text-input"), { target: { value: "ada@example.com" } });
      fireEvent.change(getByTestId("username-text-input"), { target: { value: username } });
    }

    test("is sent with the registration", async () => {
      const { getByTestId } = render(<RegisterForm legal={defaultLegal} organization="org-1" idpCount={0} />);
      fill(getByTestId, "ada");
      await waitFor(() => expect(getByTestId("submit-button")).toBeEnabled());
      fireEvent.click(getByTestId("submit-button"));
      await waitFor(() =>
        expect(registerUser).toHaveBeenCalledWith(expect.objectContaining({ username: "ada", email: "ada@example.com" })),
      );
    });

    test("is required", async () => {
      const { getByTestId } = render(<RegisterForm legal={defaultLegal} organization="org-1" idpCount={0} />);
      fill(getByTestId, "");
      await waitFor(() => expect(getByTestId("email-text-input")).toHaveValue("ada@example.com"));
      expect(getByTestId("submit-button")).toBeDisabled();
    });

    test("cannot be an email", async () => {
      const { getByTestId, findByText } = render(<RegisterForm legal={defaultLegal} organization="org-1" idpCount={0} />);
      fill(getByTestId, "ada@example.com");
      expect(await findByText("errors.usernameIsEmail")).toBeInTheDocument();
      expect(getByTestId("submit-button")).toBeDisabled();
    });
  });
});
