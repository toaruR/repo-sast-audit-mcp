import type { Finding } from "./identity.js";
import { compareFindings } from "./sort.js";

export interface TruncateResult<T extends Finding> {
  findings: T[];
  truncated: boolean;
}

/**
 * Keep the top K findings in 5.3 order using a bounded heap (root = current minimum, i.e. worst).
 * A new finding replaces the minimum only if strictly higher in sort order. O(n log K).
 */
export function truncateTopK<T extends Finding>(input: Iterable<T>, k: number): TruncateResult<T> {
  const heap: T[] = [];
  // "worse" means later in 5.3 order.
  const worse = (a: T, b: T): boolean => compareFindings(a, b) > 0;
  const swap = (i: number, j: number): void => {
    const t = heap[i] as T;
    heap[i] = heap[j] as T;
    heap[j] = t;
  };
  const up = (start: number): void => {
    let i = start;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (!worse(heap[i] as T, heap[p] as T)) break;
      swap(i, p);
      i = p;
    }
  };
  const down = (start: number): void => {
    let i = start;
    for (;;) {
      const l = 2 * i + 1;
      const r = l + 1;
      let m = i;
      if (l < heap.length && worse(heap[l] as T, heap[m] as T)) m = l;
      if (r < heap.length && worse(heap[r] as T, heap[m] as T)) m = r;
      if (m === i) break;
      swap(i, m);
      i = m;
    }
  };
  let truncated = false;
  for (const f of input) {
    if (heap.length < k) {
      heap.push(f);
      up(heap.length - 1);
    } else {
      truncated = true;
      if (k > 0 && compareFindings(f, heap[0] as T) < 0) {
        heap[0] = f;
        down(0);
      }
    }
  }
  return { findings: heap.sort(compareFindings), truncated };
}
