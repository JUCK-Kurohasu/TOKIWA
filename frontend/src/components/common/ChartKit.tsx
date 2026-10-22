/**
 * Shared recharts styling: theme-aware palette, recessive axes/grid, tooltip box, legend swatches.
 *
 * Palettes were checked with the dataviz validator (OKLab CVD separation, normal-vision floor, contrast):
 * - status (2xx / 4xx / 5xx): dark #1fbf72 #facc15 #ef4444, light #007b43 #ca8a04 #dc2626 — always paired
 *   with a second encoding (marker shape) and a legend, because light-mode amber is < 3:1 vs white.
 * - emphasis (other vs AI): grey + purple; AI purple is the only saturated hue so AI signals stand out.
 */
import { type ReactNode, useEffect, useState } from "react";
import { cn } from "@/lib/utils";

export interface ChartPalette {
  dark: boolean;
  accent: string;
  muted: string;
  grid: string;
  surface: string;
  fg: string;
  ai: string;
  ok: string;
  warn: string;
  danger: string;
  neutral: string;
}

const DARK: ChartPalette = {
  dark: true,
  accent: "#1fbf72",
  muted: "#8a9c93",
  grid: "#22312a",
  surface: "#0e1613",
  fg: "#e3ece7",
  ai: "#c084fc",
  ok: "#1fbf72",
  warn: "#facc15",
  danger: "#ef4444",
  neutral: "#5f716a",
};

const LIGHT: ChartPalette = {
  dark: false,
  accent: "#007b43",
  muted: "#5b6b63",
  grid: "#d9e2dd",
  surface: "#ffffff",
  fg: "#0f1a15",
  ai: "#9333ea",
  ok: "#007b43",
  warn: "#ca8a04",
  danger: "#dc2626",
  neutral: "#7c8a83",
};

function isDark(): boolean {
  return typeof document !== "undefined" && document.documentElement.classList.contains("dark");
}

/** Follows the `dark` class on <html> (toggled by the top bar). */
export function useChartPalette(): ChartPalette {
  const [dark, setDark] = useState(isDark);
  useEffect(() => {
    const obs = new MutationObserver(() => setDark(isDark()));
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => obs.disconnect();
  }, []);
  return dark ? DARK : LIGHT;
}

/** Props for XAxis/YAxis: hairline axis, muted 11px ticks, no tick marks. */
export function axisProps(p: ChartPalette) {
  return {
    stroke: p.grid,
    tick: { fill: p.muted, fontSize: 11 },
    tickLine: false,
    axisLine: { stroke: p.grid },
  } as const;
}

export function ChartTooltipBox({ title, children }: { title?: ReactNode; children: ReactNode }) {
  return (
    <div className="pointer-events-none min-w-[140px] rounded-md border border-line bg-surface/95 px-2.5 py-2 text-xs shadow-lg backdrop-blur">
      {title != null && <div className="mb-1 font-medium text-fg">{title}</div>}
      <div className="space-y-0.5 text-muted">{children}</div>
    </div>
  );
}

export function TooltipRow({ color, label, value }: { color?: string; label: ReactNode; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="flex items-center gap-1.5">
        {color && <span className="inline-block h-2 w-2 rounded-sm" style={{ background: color }} />}
        {label}
      </span>
      <span className="font-medium tabular-nums text-fg">{value}</span>
    </div>
  );
}

export function LegendSwatch({
  color,
  label,
  shape = "square",
  className,
}: {
  color: string;
  label: ReactNode;
  shape?: "square" | "line" | "circle" | "triangle" | "diamond" | "band";
  className?: string;
}) {
  const mark =
    shape === "line" ? (
      <span className="inline-block h-0.5 w-3 rounded" style={{ background: color }} />
    ) : shape === "circle" ? (
      <span className="inline-block h-2 w-2 rounded-full" style={{ background: color }} />
    ) : shape === "triangle" ? (
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
        <path d="M5 1 L9 9 L1 9 Z" fill={color} />
      </svg>
    ) : shape === "diamond" ? (
      <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
        <path d="M5 0.5 L9.5 5 L5 9.5 L0.5 5 Z" fill={color} />
      </svg>
    ) : shape === "band" ? (
      <span className="inline-block h-2.5 w-3 rounded-sm opacity-40" style={{ background: color }} />
    ) : (
      <span className="inline-block h-2 w-2 rounded-sm" style={{ background: color }} />
    );
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs text-muted", className)}>
      {mark}
      {label}
    </span>
  );
}
