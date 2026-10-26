/**
 * Page state kept in the URL query string (shareable / survives reload / back button).
 *
 *   const [f, setF] = useSearchState(["kind", "q", "offset"] as const);
 *   setF({ kind: "http", offset: null });   // null/"" removes the key
 */
import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router";

export function useSearchState<K extends string>(
  keys: readonly K[],
): [
  Record<K, string>,
  (patch: Partial<Record<K, string | number | null | undefined>>, replace?: boolean) => void,
] {
  const [params, setParams] = useSearchParams();
  const keyId = keys.join("|");

  // biome-ignore lint/correctness/useExhaustiveDependencies: keyId is the stable identity of `keys`
  const values = useMemo(() => {
    const out = {} as Record<K, string>;
    for (const k of keys) out[k] = params.get(k) ?? "";
    return out;
  }, [params, keyId]);

  const update = useCallback(
    (patch: Partial<Record<K, string | number | null | undefined>>, replace = true) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(patch) as [string, string | number | null | undefined][]) {
            if (v === null || v === undefined || v === "") next.delete(k);
            else next.set(k, String(v));
          }
          return next;
        },
        { replace },
      );
    },
    [setParams],
  );

  return [values, update];
}
