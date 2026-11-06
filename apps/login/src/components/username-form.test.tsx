import { sendLoginname } from "@/lib/server/loginname";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { UsernameForm } from "./username-form";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("next-intl", () => ({
  useTranslations: () => (key: string) => key,
}));

vi.mock("@/lib/server/loginname", () => ({
  sendLoginname: vi.fn(),
}));

describe("UsernameForm", () => {
  afterEach(cleanup);

  test("should autofocus the loginName input on mount", () => {
    const { getByTestId } = render(
      <UsernameForm loginName="" requestId={undefined} loginSettings={undefined} submit={false} allowRegister={false} />,
    );
    expect(getByTestId("username-text-input")).toHaveFocus();
  });

  // Spalk
  test.each([
    [false, false],
    [true, true],
  ])("sends the loginname with remember=%s when the box is ticked=%s", async (tick, remember) => {
    vi.mocked(sendLoginname).mockResolvedValue({ error: "" });
    const { getByTestId } = render(
      <UsernameForm loginName="" requestId={undefined} loginSettings={undefined} submit={false} allowRegister={false} />,
    );

    expect(getByTestId("remember-me-checkbox")).not.toBeChecked();
    if (tick) {
      fireEvent.click(getByTestId("remember-me-checkbox"));
    }
    fireEvent.input(getByTestId("username-text-input"), { target: { value: "user" } });
    await waitFor(() => expect(getByTestId("submit-button")).toBeEnabled());
    fireEvent.click(getByTestId("submit-button"));

    await waitFor(() => expect(sendLoginname).toHaveBeenCalledWith(expect.objectContaining({ remember })));
  });
});
