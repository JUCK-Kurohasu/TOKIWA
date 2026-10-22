/**
 * Page state kept in the URL query string (tabs, filters, selected item) so views are linkable and survive reload.
 */
import { useCallback } from "react";
import { useSearchParams } from "react-router";

export type ParamPatch = Record<string, string | number | boolean | null | undefined>;

/** Batch-update several query params at once (null/""/undefined/false removes the key). */
export function useUrlParams(): [URLSearchParams, (patch: ParamPatch) => void] {
  const [params, setParams] = useSearchParams();
  const update = useCallback(
    (patch: ParamPatch) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(patch)) {
            if (v === null || v === undefined || v === "" || v === false) next.delete(k);
            else next.set(k, String(v));
          }
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );
  return [params, update];
}

export function useUrlParam(key: string, fallback = ""): [string, (v: string | null) => void] {
  const [params, update] = useUrlParams();
  const value = params.get(key) ?? fallback;
  const set = useCallback((v: string | null) => update({ [key]: v }), [key, update]);
  return [value, set];
}
