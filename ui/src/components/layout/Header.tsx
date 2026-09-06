import { Bell, LogOut, Search } from 'lucide-react';
import { Link } from '@tanstack/react-router';

import secyLogo from '@/assets/img/secy-logo.svg';
import { displayNameOf, initialsOf } from '@/auth/initials';
import { useAuth } from '@/auth/useAuth';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

/**
 * Fixed 58px application header.
 *
 * The user menu is real — it reflects the signed-in account and signs out.
 * The search box and the notification count are still visual placeholders;
 * replace them when the corresponding features land.
 */
export function Header() {
  const { user, logout } = useAuth();
  const name = displayNameOf(user);
  const initials = initialsOf(user);

  return (
    <header className="fixed inset-x-0 top-0 z-30 flex h-header items-center border-b border-border bg-card">
      {/* Brand — width matches the sidenav so the border lines up. */}
      <div className="flex h-header w-sidenav shrink-0 items-center justify-center border-r border-border">
        <Link to="/dashboard" className="flex items-center gap-2">
          <img src={secyLogo} alt="Secy" className="h-8 w-8" />
          <span className="text-xl font-bold tracking-tight text-foreground">Secy</span>
        </Link>
      </div>

      <div className="flex flex-1 items-center justify-between gap-4 px-4">
        {/* Global search — non-functional placeholder. */}
        <div className="relative w-1/2 max-w-xl">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search CVEs, CWEs, or Products..."
            aria-label="Search CVEs, CWEs, or Products"
            className="h-9 border-0 bg-muted pl-9"
          />
        </div>

        <div className="flex items-center">
          <button
            type="button"
            title="Notifications"
            aria-label="Notifications, 3 unread"
            className="relative rounded-md px-3 py-2 text-muted-foreground transition-colors hover:text-foreground"
          >
            <Bell className="h-[18px] w-[18px]" />
            <span className="absolute right-1 top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-semibold leading-none text-destructive-foreground">
              3
            </span>
          </button>

          <Separator orientation="vertical" className="mx-3 h-5" />

          <DropdownMenu>
            <DropdownMenuTrigger
              aria-label={`Account menu for ${name}`}
              className="flex items-center gap-2 rounded-md px-1 py-1 outline-none transition-colors hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring"
            >
              <span className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">
                {initials}
              </span>
              <span className="text-sm font-semibold">{name}</span>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel className="font-normal">
                <span className="block text-sm font-semibold text-foreground">{name}</span>
                <span className="block truncate text-xs font-normal text-muted-foreground">
                  {user?.email}
                </span>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem disabled>Profile</DropdownMenuItem>
              <DropdownMenuItem disabled>Settings</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => logout()}>
                <LogOut className="mr-2 h-4 w-4" aria-hidden="true" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
}
