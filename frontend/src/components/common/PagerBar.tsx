/** Offset pagination footer for `Page<T>` responses: "1–50 / 1,234" + prev/next + page size. */
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button, Select } from "@/components/ui";
import { formatNumber } from "@/lib/format";
import { useLocal } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function PagerBar({
  total,
  limit,
  offset,
  onOffset,
  onLimit,
  limits = [25, 50, 100, 200],
  busy,
  className,
}: {
  total: number;
  limit: number;
  offset: number;
  onOffset: (offset: number) => void;
  onLimit?: (limit: number) => void;
  limits?: number[];
  busy?: boolean;
  className?: string;
}) {
  const L = useLocal({
    ja: { prev: "前へ", next: "次へ", perPage: "件/ページ", of: "件中" },
    en: { prev: "Previous", next: "Next", perPage: "per page", of: "of" },
  });
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <div className={cn("flex flex-wrap items-center justify-between gap-2 text-xs text-muted", className)}>
      <span className="tabular-nums">
        {formatNumber(from)}–{formatNumber(to)} / {formatNumber(total)}
      </span>
      <div className="flex items-center gap-2">
        {onLimit && (
          <span className="flex items-center gap-1.5">
            <Select
              value={limit}
              onChange={(e) => onLimit(Number(e.target.value))}
              className="h-7 text-xs"
              aria-label={L.perPage}
            >
              {limits.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </Select>
            {L.perPage}
          </span>
        )}
        <Button
          size="sm"
          variant="outline"
          disabled={busy || offset <= 0}
          onClick={() => onOffset(Math.max(0, offset - limit))}
          aria-label={L.prev}
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          {L.prev}
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={busy || offset + limit >= total}
          onClick={() => onOffset(offset + limit)}
          aria-label={L.next}
        >
          {L.next}
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}
