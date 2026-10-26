/** Software inventory helpers: editable rows ↔ SoftwareItem, and bulk-paste parsing. */
import type { SoftwareItem } from "@/api/types";

export interface SoftwareRow {
  key: string;
  vendor: string;
  product: string;
  version: string;
  cpe: string;
  ecosystem: string;
}

let seq = 0;
export function newRow(init: Partial<SoftwareRow> = {}): SoftwareRow {
  seq += 1;
  return {
    key: `sw-${Date.now()}-${seq}`,
    vendor: "",
    product: "",
    version: "",
    cpe: "",
    ecosystem: "",
    ...init,
  };
}

export function toRows(items: SoftwareItem[]): SoftwareRow[] {
  return items.map((s) =>
    newRow({
      vendor: s.vendor ?? "",
      product: s.product ?? "",
      version: s.version ?? "",
      cpe: s.cpe ?? "",
      ecosystem: s.ecosystem ?? "",
    }),
  );
}

const nullIfEmpty = (s: string) => (s.trim() ? s.trim() : null);

export function isBlankRow(r: SoftwareRow): boolean {
  return !r.vendor.trim() && !r.product.trim() && !r.version.trim() && !r.cpe.trim() && !r.ecosystem.trim();
}

export function toItems(rows: SoftwareRow[]): SoftwareItem[] {
  return rows
    .filter((r) => !isBlankRow(r))
    .map((r) => ({
      vendor: nullIfEmpty(r.vendor),
      product: r.product.trim(),
      version: nullIfEmpty(r.version),
      cpe: nullIfEmpty(r.cpe),
      ecosystem: nullIfEmpty(r.ecosystem),
    }));
}

/** cpe:2.3:part:vendor:product:version:... (escaped colons are not handled — rare in inventories). */
export function parseCpe23(cpe: string): { vendor?: string; product?: string; version?: string } | null {
  const parts = cpe.trim().split(":");
  if (parts.length < 6 || parts[0] !== "cpe" || parts[1] !== "2.3") return null;
  const clean = (v: string | undefined) => (v && v !== "*" && v !== "-" ? v.replace(/\\/g, "") : undefined);
  return { vendor: clean(parts[3]), product: clean(parts[4]), version: clean(parts[5]) };
}

export function looksLikeCpe(cpe: string): boolean {
  return /^cpe:(2\.3:[aho*-]:|\/[aho]:)/i.test(cpe.trim());
}

/**
 * Bulk paste: one package per line. Accepted forms:
 *   cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*
 *   django==4.2.7          (pip freeze)
 *   @scope/pkg@1.2.3       (npm)
 *   openssl 3.0.13         (name + version separated by whitespace, e.g. dpkg/rpm lists)
 *   nginx                  (product only)
 */
export function parseBulk(text: string, ecosystem: string): SoftwareRow[] {
  const rows: SoftwareRow[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (line.toLowerCase().startsWith("cpe:")) {
      const p = parseCpe23(line);
      rows.push(
        newRow({
          cpe: line,
          vendor: p?.vendor ?? "",
          product: p?.product ?? line,
          version: p?.version ?? "",
        }),
      );
      continue;
    }
    let product = line;
    let version = "";
    const pip = /^([A-Za-z0-9_.\-[\]]+)\s*(?:===?|~=|>=)\s*([^\s;]+)/.exec(line);
    const npm = /^(@?[^@\s]+)@([^\s]+)$/.exec(line);
    const ws = /^(\S+)\s+(\S+)/.exec(line);
    if (pip) [, product, version] = pip;
    else if (npm) [, product, version] = npm;
    else if (ws) [, product, version] = ws;
    rows.push(newRow({ product, version, ecosystem }));
  }
  return rows;
}
