import { Biohazard } from 'lucide-react';

import { cn } from '@/lib/utils';

/**
 * The "you are shipping something known-bad" badge for a `COMPROMISE` row
 * (Phase 6) — deliberately not a variant of {@link ExploitBadge}. `ExploitBadge`
 * answers "how exploitable is this vulnerability" (a probability, shading from
 * amber to red); this badge answers a categorically different question —
 * "this artefact IS malicious" is a fact, not a risk gradient — so it gets a
 * **solid** fill (the same `bg-destructive`/`text-destructive-foreground` pair
 * `Badge`'s `destructive` variant uses) rather than the tinted `/10` treatment
 * every other pill on this table uses, plus a distinct icon (`Biohazard`,
 * unused elsewhere in the icon vocabulary) so it reads as unmistakably
 * different at a glance, not just "an angrier exploit badge".
 */
export function MaliciousBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 whitespace-nowrap rounded-full bg-destructive px-2 py-0.5 text-xs font-bold text-destructive-foreground',
        className,
      )}
    >
      <Biohazard className="h-3.5 w-3.5" aria-hidden="true" />
      Malicious
    </span>
  );
}
