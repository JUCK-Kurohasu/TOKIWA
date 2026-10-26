/** Prev/next pager for `Page<T>` (limit/offset) responses. */
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui";
import { formatNumber } from "@/lib/format";
import { useLocal } from "@/lib/i18n";

export function OffsetPager({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const L = useLocal({
    ja: { prev: "前へ", next: "次へ", of: "件中" },
    en: { prev: "Previous", next: "Next", of: "of" },
  });
  if (total <= 0) return null;
  const from = Math.min(total, offset + 1);
  const to = Math.min(total, offset + limit);
  return (
    <div className="flex items-center justify-between gap-2 border-t border-line px-3 py-2 text-xs text-muted">
      <span className="tabular-nums">
        {formatNumber(from)}–{formatNumber(to)} {L.of} {formatNumber(total)}
      </span>
      <div className="flex gap-1">
        <Button
          variant="ghost"
          size="sm"
          disabled={offset <= 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          aria-label={L.prev}
        >
          <ChevronLeft className="h-4 w-4" aria-hidden />
          {L.prev}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
          aria-label={L.next}
        >
          {L.next}
          <ChevronRight className="h-4 w-4" aria-hidden />
        </Button>
      </div>
    </div>
  );
}
