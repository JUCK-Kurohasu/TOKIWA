/**
 * Display time zone for every date/time in the UI (audit #165).
 *
 * The API returns UTC ("…Z"); the raw JSON view, Gate/nginx logs, SIEM exports and notifications are UTC too.
 * The UI used to convert to the browser's local zone without saying so, so the same event read "0:43:09" on a
 * UTC machine and "9:43:09" in Japan with nothing on screen to tell them apart. Now every formatted date/time
 * carries a zone name ("JST", "UTC", "GMT+9"), the zone can be switched between the browser's local zone and
 * UTC from the top bar (remembered per browser), and tooltips add the ISO-8601 UTC value.
 *
 * State lives in this module (read by the plain formatting functions) and is mirrored into React state by
 * `LangProvider` (lib/i18n.tsx) so that a switch re-renders every component that uses `useLocal`/`useLang`.
 */

export type DisplayTz = "local" | "utc";

const STORAGE_KEY = "tokiwa.tz";

let current: DisplayTz = (() => {
  try {
    return localStorage.getItem(STORAGE_KEY) === "utc" ? "utc" : "local";
  } catch {
    return "local";
  }
})();

export function getDisplayTz(): DisplayTz {
  return current;
}

/** Update the module state and remember it (call through `useLang().setTz` so React re-renders). */
export function storeDisplayTz(tz: DisplayTz): void {
  current = tz;
  try {
    localStorage.setItem(STORAGE_KEY, tz);
  } catch {
    /* private mode / blocked storage: keep it for this page only */
  }
}

/** `timeZone` option for Intl: "UTC" or undefined (= the browser's zone). */
export function intlTimeZone(tz: DisplayTz = current): string | undefined {
  return tz === "utc" ? "UTC" : undefined;
}

/** Short name of the zone in effect at `at` (default now), e.g. "JST", "UTC", "GMT+9". */
export function zoneName(locale: string, tz: DisplayTz = current, at: Date = new Date()): string {
  try {
    const part = new Intl.DateTimeFormat(locale, { timeZone: intlTimeZone(tz), timeZoneName: "short" })
      .formatToParts(at)
      .find((p) => p.type === "timeZoneName");
    return part?.value ?? (tz === "utc" ? "UTC" : "");
  } catch {
    return tz === "utc" ? "UTC" : "";
  }
}
