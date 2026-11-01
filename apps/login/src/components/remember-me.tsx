"use client";

import { createContext, Dispatch, ReactNode, SetStateAction, useContext, useState } from "react";
import { Checkbox } from "./checkbox";
import { Translated } from "./translated";

// Spalk: the "Keep me signed in" choice. A page with more than one way to sign in (a password and IdPs) wraps
// them in a RememberMeProvider so that one checkbox serves them all; without one, a component keeps its own.

type RememberMeState = [boolean, Dispatch<SetStateAction<boolean>>];

const RememberMeContext = createContext<RememberMeState | null>(null);

export function RememberMeProvider({ children }: { children: ReactNode }) {
  const state = useState<boolean>(false);
  return <RememberMeContext.Provider value={state}>{children}</RememberMeContext.Provider>;
}

export function useRememberMe(): RememberMeState {
  const local = useState<boolean>(false);
  return useContext(RememberMeContext) ?? local;
}

export function RememberMeCheckbox({ state }: { state: RememberMeState }) {
  const [remember, setRemember] = state;

  return (
    <label className="mt-4 flex items-center">
      <Checkbox
        className="mr-4"
        checked={remember}
        onChangeVal={(checked: boolean) => setRemember(checked)}
        data-testid="remember-me-checkbox"
      />
      <span className="text-text-light-500 dark:text-text-dark-500 text-sm">
        <Translated i18nKey="rememberMe" namespace="common" />
      </span>
    </label>
  );
}
