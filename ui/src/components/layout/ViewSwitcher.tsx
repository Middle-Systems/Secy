import { ChevronDown, Shield, UserCog, ChartLine } from 'lucide-react';
import { useNavigate } from '@tanstack/react-router';
import type { LucideIcon } from 'lucide-react';

import { useMyAccess } from '@/api/queries';
import type { TenantRole } from '@/api/types';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useCurrentView, VIEW_HOME } from '@/lib/current-view';

const VIEW_LABEL: Record<TenantRole, string> = {
  SECURITY_ENGINEER: 'Security Engineer',
  SOFTWARE_ENGINEER: 'Software Engineer',
  LEADERSHIP: 'Leadership',
};

const VIEW_ICON: Record<TenantRole, LucideIcon> = {
  SECURITY_ENGINEER: Shield,
  SOFTWARE_ENGINEER: UserCog,
  LEADERSHIP: ChartLine,
};

/**
 * M1k's stateless view switcher — mounted in {@link Header}. Renders nothing while `/me/access` is
 * loading, errored (e.g. unauthenticated, or a backend that predates M1k), or when the caller has
 * at most one view (a switcher is pointless with nothing to switch to) — this is deliberate, not an
 * oversight: it keeps `app.test.tsx`'s shell assertions and every other existing view test green
 * without any of them needing to mock `/me/access`.
 */
export function ViewSwitcher() {
  const { data: access, isPending, isError } = useMyAccess();
  const navigate = useNavigate();
  const { currentView, setCurrentView } = useCurrentView(access);

  if (isPending || isError || !access || access.views.length <= 1 || !currentView) {
    return null;
  }

  function handleSelect(view: string) {
    const role = view as TenantRole;
    setCurrentView(role);
    void navigate({ to: VIEW_HOME[role] });
  }

  const Icon = VIEW_ICON[currentView];

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label="Switch view"
        className="flex items-center gap-2 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-foreground outline-none transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Icon className="h-4 w-4" aria-hidden="true" />
        <span>{VIEW_LABEL[currentView]}</span>
        <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" aria-hidden="true" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-52">
        <DropdownMenuRadioGroup value={currentView} onValueChange={handleSelect}>
          {access.views.map((view) => (
            <DropdownMenuRadioItem key={view} value={view}>
              {VIEW_LABEL[view]}
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
