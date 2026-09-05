import { formatInteger } from '@/lib/format';

import type { VendorCount } from './dashboard.helpers';

/** Ranked leaderboard of the vendors most often hit by ransomware-linked KEVs. */
export function RansomwareTargets({ data }: { data: VendorCount[] }) {
  if (data.length === 0) {
    return (
      <p className="py-12 text-center text-sm text-muted-foreground">
        No ransomware-linked exploits recorded.
      </p>
    );
  }

  return (
    <ol className="flex flex-col gap-1">
      {data.map((entry, index) => (
        <li
          key={entry.vendor}
          className="flex items-center gap-3 rounded-md px-2 py-2 transition-colors hover:bg-muted/50"
        >
          <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-bold tabular-nums text-muted-foreground">
            {index + 1}
          </span>
          <span className="flex-1 truncate text-sm font-medium text-foreground">{entry.vendor}</span>
          <span className="text-sm font-bold tabular-nums text-severity-critical">
            {formatInteger(entry.count)}
          </span>
        </li>
      ))}
    </ol>
  );
}
