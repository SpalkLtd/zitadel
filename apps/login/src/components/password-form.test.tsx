import { sendPassword } from "@/lib/server/password";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { PasswordForm } from "./password-form";
import { RememberMeProvider } from "./remember-me";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string) => key,
}));

vi.mock("@/lib/server/password", () => ({
  sendPassword: vi.fn(),
  resetPassword: vi.fn(),
}));

describe("PasswordForm", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  test("should autofocus the password input on mount", () => {
    const { getByTestId } = render(<PasswordForm loginSettings={undefined} loginName="test@example.com" />);
    expect(getByTestId("password-text-input")).toHaveFocus();
  });

  // Spalk
  test.each([
    [false, false],
    [true, true],
  ])("sends the password with remember=%s when the box is ticked=%s", async (tick, remember) => {
    vi.mocked(sendPassword).mockResolvedValue({ error: "" });
    const { getByTestId } = render(<PasswordForm loginSettings={undefined} loginName="test@example.com" />);

    expect(getByTestId("remember-me-checkbox")).not.toBeChecked();
    if (tick) {
      fireEvent.click(getByTestId("remember-me-checkbox"));
    }
    fireEvent.input(getByTestId("password-text-input"), { target: { value: "secret" } });
    await waitFor(() => expect(getByTestId("submit-button")).toBeEnabled());
    fireEvent.click(getByTestId("submit-button"));

    await waitFor(() => expect(sendPassword).toHaveBeenCalledWith(expect.objectContaining({ remember })));
  });

  // Spalk: ticked on the loginname page
  test("starts ticked when the page's choice is on", () => {
    const { getByTestId } = render(
      <RememberMeProvider initial>
        <PasswordForm loginSettings={undefined} loginName="test@example.com" />
      </RememberMeProvider>,
    );
    expect(getByTestId("remember-me-checkbox")).toBeChecked();
  });
});
