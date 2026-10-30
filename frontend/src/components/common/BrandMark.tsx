/**
 * TOKIWA's mark: a mountain range (3 peaks). Same stroke style as lucide icons so it sits next to them;
 * keep the path in sync with public/favicon.svg.
 */
import type { SVGProps } from "react";

export const BRAND_MARK_PATH = "M2 20 6 12l3 4 3-10 3.5 9 2.5-4 4 9z";

export function BrandMark(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    >
      <path d={BRAND_MARK_PATH} />
    </svg>
  );
}
