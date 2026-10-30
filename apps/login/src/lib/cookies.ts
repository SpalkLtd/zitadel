"use server";

import { timestampDate, timestampFromMs } from "@zitadel/client";
import { cookies } from "next/headers";
import { LANGUAGE_COOKIE_NAME } from "./i18n";
import { createLogger } from "./logger";
import { parseAndVerifySessions, signSession } from "./session-cookie-signature";

const logger = createLogger("cookies");

// TODO: improve this to handle overflow
// Browsers cap a single cookie at ~4096 bytes (name, value and attributes). Keep a margin for
// the attributes and for the signature that is added to every entry when the cookie is written.
const MAX_COOKIE_SIZE = 3500;

// Spalk: a session the user chose to remember ("Keep me signed in") is kept in a second, persistent cookie
// instead of the browser-session "sessions" cookie, so an account that wasn't ticked is never persisted.
// Every read takes the union of both cookies; every write splits the entries between them by `remember`.
const SESSIONS_COOKIE_NAME = "sessions";
const REMEMBERED_SESSIONS_COOKIE_NAME = "sessions_remembered";

// Spalk: carries the "Keep me signed in" choice across the round trip to an external IdP.
const REMEMBER_ME_INTENT_COOKIE_NAME = "remember_me_intent";
const REMEMBER_ME_INTENT_MAX_AGE_SECONDS = 60 * 60;

export type Cookie = {
  id: string;
  token: string;
  loginName: string;
  organization?: string;
  creationTs: string;
  expirationTs: string;
  changeTs: string;
  requestId?: string; // if its linked to an OIDC flow
  remember?: boolean; // Spalk: the user ticked "Keep me signed in", so the entry is persisted
};

type SessionCookie<T> = Cookie & T;

async function setSessionHttpOnlyCookie<T>(sessions: SessionCookie<T>[], iFrameEnabled: boolean = false) {
  const cookiesList = await cookies();

  // "none" is required for iframe embedding (with secure flag)
  let resolvedSameSite: "lax" | "strict" | "none";

  if (iFrameEnabled) {
    // When embedded in iframe, must use "none" with secure flag
    resolvedSameSite = "none";
  } else {
    // This allows cookies during top-level navigation while blocking cross-origin requests
    resolvedSameSite = "lax";
  }

  const attributes = {
    httpOnly: true,
    path: "/",
    sameSite: resolvedSameSite,
    // "none" is only accepted by browsers together with "secure", otherwise the cookie is silently dropped
    secure: process.env.NODE_ENV === "production" || resolvedSameSite === "none",
  };

  // Spalk: a remembered entry that has expired goes back to the browser-session cookie, where upstream keeps
  // expired entries so the account can be picked again; it is no longer kept on the device.
  const now = Date.now();
  const remembered = sessions.filter((session) => session.remember && Number(session.expirationTs) > now);

  const result = cookiesList.set({
    name: SESSIONS_COOKIE_NAME,
    value: JSON.stringify(
      sessions.filter((session) => !remembered.includes(session)).map((session) => signSession(session)),
    ),
    ...attributes,
  });

  if (remembered.length) {
    // the cookie lives as long as the longest-lived remembered session
    const expires = new Date(Math.max(...remembered.map((session) => Number(session.expirationTs))));
    cookiesList.set({
      name: REMEMBERED_SESSIONS_COOKIE_NAME,
      value: JSON.stringify(remembered.map((session) => signSession(session))),
      expires,
      ...attributes,
    });
  } else if (readRememberedSessionCookies(cookiesList).length) {
    cookiesList.set({ name: REMEMBERED_SESSIONS_COOKIE_NAME, value: "", expires: new Date(0), ...attributes });
  }

  return result;
}

// Spalk: only remembered entries count from the remembered cookie.
function readRememberedSessionCookies<T>(cookiesList: Awaited<ReturnType<typeof cookies>>): SessionCookie<T>[] {
  return readSessionCookies<T>(cookiesList.get(REMEMBERED_SESSIONS_COOKIE_NAME)?.value).filter(
    (session) => session.remember,
  );
}

// Spalk: whether either session cookie is present, with or without valid entries.
async function hasSessionCookie(): Promise<boolean> {
  const cookiesList = await cookies();
  return !!(cookiesList.get(SESSIONS_COOKIE_NAME)?.value || cookiesList.get(REMEMBERED_SESSIONS_COOKIE_NAME)?.value);
}

// Spalk: the union of both session cookies; an entry in both (which writes never produce) is taken once.
async function readAllSessionCookies<T>(): Promise<SessionCookie<T>[]> {
  const cookiesList = await cookies();
  const sessions = readSessionCookies<T>(cookiesList.get(SESSIONS_COOKIE_NAME)?.value);
  const remembered = readRememberedSessionCookies<T>(cookiesList).filter(
    (session) => !sessions.some((s) => s.id === session.id),
  );
  return [...sessions, ...remembered];
}

function readSessionCookies<T>(value: string | undefined): SessionCookie<T>[] {
  const sessions = parseAndVerifySessions<SessionCookie<T>>(value);

  if (value && sessions.length < countCookieEntries(value)) {
    logger.warn(
      `readSessionCookies: ignoring ${countCookieEntries(value) - sessions.length} session cookie entries with a missing or invalid signature (unsigned legacy cookie or signing secret changed)`,
    );
  }

  return sessions;
}

function countCookieEntries(value: string): number {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.length : 0;
  } catch {
    return 0;
  }
}

export async function setLanguageCookie(language: string) {
  const cookiesList = await cookies();

  await cookiesList.set({
    name: LANGUAGE_COOKIE_NAME,
    value: language,
    httpOnly: true,
    path: "/",
  });
}

export async function getLanguageCookie(): Promise<string | undefined> {
  const cookiesList = await cookies();
  const languageCookie = cookiesList.get(LANGUAGE_COOKIE_NAME);
  return languageCookie?.value;
}

export async function addSessionToCookie<T>({
  session,
  cleanup,
  iFrameEnabled,
}: {
  session: SessionCookie<T>;
  cleanup?: boolean;
  iFrameEnabled?: boolean;
}): Promise<any> {
  let currentSessions: SessionCookie<T>[] = await readAllSessionCookies<T>();

  const index = currentSessions.findIndex((s) => s.loginName === session.loginName);

  if (index > -1) {
    currentSessions[index] = session;
  } else {
    const temp = [...currentSessions, session];

    // measure the value as it will be written (including signatures)
    if (JSON.stringify(temp.map((s) => signSession(s))).length >= MAX_COOKIE_SIZE) {
      logger.warn("WARNING COOKIE OVERFLOW");
      // TODO: improve cookie handling
      // this replaces the first session (oldest) with the new one
      currentSessions = [session].concat(currentSessions.slice(1));
    } else {
      currentSessions = [session].concat(currentSessions);
    }
  }

  if (cleanup) {
    const now = new Date();
    const filteredSessions = currentSessions.filter((session) =>
      session.expirationTs ? timestampDate(timestampFromMs(Number(session.expirationTs))) > now : true,
    );
    return setSessionHttpOnlyCookie(filteredSessions, iFrameEnabled);
  } else {
    return setSessionHttpOnlyCookie(currentSessions, iFrameEnabled);
  }
}

export async function updateSessionCookie<T>({
  id,
  session,
  cleanup,
  iFrameEnabled,
}: {
  id: string;
  session: SessionCookie<T>;
  cleanup?: boolean;
  iFrameEnabled?: boolean;
}): Promise<any> {
  const sessions: SessionCookie<T>[] = (await hasSessionCookie()) ? await readAllSessionCookies<T>() : [session];

  const foundIndex = sessions.findIndex((session) => session.id === id);

  if (foundIndex > -1) {
    sessions[foundIndex] = session;
    if (cleanup) {
      const now = new Date();
      const filteredSessions = sessions.filter((session) =>
        session.expirationTs ? timestampDate(timestampFromMs(Number(session.expirationTs))) > now : true,
      );
      return setSessionHttpOnlyCookie(filteredSessions, iFrameEnabled);
    } else {
      return setSessionHttpOnlyCookie(sessions, iFrameEnabled);
    }
  } else {
    throw "updateSessionCookie<T>: session id not found";
  }
}

export async function removeSessionFromCookie<T>({
  session,
  cleanup,
  iFrameEnabled,
}: {
  session: SessionCookie<T>;
  cleanup?: boolean;
  iFrameEnabled?: boolean;
}) {
  const sessions: SessionCookie<T>[] = (await hasSessionCookie()) ? await readAllSessionCookies<T>() : [session];

  const reducedSessions = sessions.filter((s) => s.id !== session.id);
  if (cleanup) {
    const now = new Date();
    const filteredSessions = reducedSessions.filter((session) =>
      session.expirationTs ? timestampDate(timestampFromMs(Number(session.expirationTs))) > now : true,
    );
    return setSessionHttpOnlyCookie(filteredSessions, iFrameEnabled);
  } else {
    return setSessionHttpOnlyCookie(reducedSessions, iFrameEnabled);
  }
}

export async function getMostRecentSessionCookie<T>(): Promise<Cookie | undefined> {
  const sessions = await readAllSessionCookies<T>();
  if (!sessions.length) {
    return undefined;
  }

  return sessions.reduce((prev, current) => {
    return prev.changeTs > current.changeTs ? prev : current;
  });
}

export async function getSessionCookieById<T>({
  sessionId,
  organization,
}: {
  sessionId: string;
  organization?: string;
}): Promise<SessionCookie<T> | undefined> {
  const sessions = await readAllSessionCookies<T>();
  return sessions.find((s) => (organization ? s.organization === organization && s.id === sessionId : s.id === sessionId));
}

export async function getSessionCookieByLoginName<T>({
  loginName,
  organization,
}: {
  loginName?: string;
  organization?: string;
}): Promise<SessionCookie<T> | undefined> {
  const sessions = await readAllSessionCookies<T>();
  return sessions.find((s) =>
    organization ? s.organization === organization && s.loginName === loginName : s.loginName === loginName,
  );
}

/**
 *
 * @param cleanup when true, excludes expired sessions from the result, default false
 * @returns Session Cookies
 */
export async function getAllSessionCookieIds<T>(cleanup: boolean = false): Promise<string[]> {
  const sessions = await getAllSessions<T>(cleanup);
  return sessions.map(({ id }) => id);
}

/**
 *
 * @param cleanup when true, excludes expired sessions from the result, default false
 * @returns Session Cookies
 */
export async function getAllSessions<T>(cleanup: boolean = false): Promise<SessionCookie<T>[]> {
  const sessions = await readAllSessionCookies<T>();

  if (!sessions.length) {
    logger.info("getAllSessions: No session cookie found, returning empty array");
    return [];
  }

  if (cleanup) {
    const now = new Date();
    return sessions.filter((session) =>
      session.expirationTs ? timestampDate(timestampFromMs(Number(session.expirationTs))) > now : true,
    );
  }

  return sessions;
}

/**
 * Returns most recent session filtered by optinal loginName
 * @param loginName optional loginName to filter cookies, if non provided, returns most recent session
 * @param organization optional organization to filter cookies
 * @returns most recent session
 */
export async function getMostRecentCookieWithLoginname<T>({
  loginName,
  organization,
}: {
  loginName?: string;
  organization?: string;
}): Promise<any> {
  const sessions = await readAllSessionCookies<T>();

  if (!sessions.length) {
    return undefined;
  }

  let filtered = sessions;

  if (loginName) {
    filtered = filtered.filter((cookie) => cookie.loginName === loginName);
  }

  if (organization) {
    filtered = filtered.filter((cookie) => cookie.organization === organization);
  }

  if (!filtered || !filtered.length) {
    return undefined;
  }

  return filtered.reduce((prev, current) => {
    return prev.changeTs > current.changeTs ? prev : current;
  });
}

/**
 * Spalk: remembers the "Keep me signed in" choice while the user is away at an external IdP, until the
 * session is created on their return.
 */
export async function setRememberMeIntentCookie(remember: boolean) {
  const cookiesList = await cookies();

  cookiesList.set({
    name: REMEMBER_ME_INTENT_COOKIE_NAME,
    value: remember ? "true" : "false",
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: REMEMBER_ME_INTENT_MAX_AGE_SECONDS,
  });
}

/**
 * Spalk: returns the choice stored by setRememberMeIntentCookie, if any, and removes it.
 */
export async function takeRememberMeIntentCookie(): Promise<boolean | undefined> {
  const cookiesList = await cookies();
  const value = cookiesList.get(REMEMBER_ME_INTENT_COOKIE_NAME)?.value;

  if (value === undefined) {
    return undefined;
  }

  cookiesList.delete(REMEMBER_ME_INTENT_COOKIE_NAME);
  return value === "true";
}
