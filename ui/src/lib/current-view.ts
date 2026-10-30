import { useEffect, useState } from 'react';

import type { MyAccess, TenantRole } from '@/api/types';

/** `localStorage` key for the last view the user picked — a per-viewer convenience, not state the
 *  server knows anything about (M1k is stateless — see `GET /me/access`'s Javadoc). */
const STORAGE_KEY = 'secy.currentView';

/** Where each view's home screen lives. */
export const VIEW_HOME: Record<TenantRole, string> = {
  SECURITY_ENGINEER: '/',
  SOFTWARE_ENGINEER: '/my-work',
  LEADERSHIP: '/leadership',
};

function readStoredView(): TenantRole | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw === 'LEADERSHIP' || raw === 'SECURITY_ENGINEER' || raw === 'SOFTWARE_ENGINEER' ? raw : null;
  } catch {
    return null;
  }
}

function writeStoredView(view: TenantRole): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, view);
  } catch {
    // Private window / blocked storage — the view just won't be remembered next visit.
  }
}

/**
 * The view currently selected: the stored one if it's still in `access.views`, else
 * `access.defaultView`. Returns `null` when `access` is undefined (still loading/errored) or has
 * no views at all.
 */
export function useCurrentView(access: MyAccess | undefined): {
  currentView: TenantRole | null;
  setCurrentView: (view: TenantRole) => void;
} {
  const [stored, setStored] = useState<TenantRole | null>(() => readStoredView());

  const currentView =
    access && stored && access.views.includes(stored) ? stored : access?.defaultView ?? null;

  useEffect(() => {
    if (currentView) {
      writeStoredView(currentView);
    }
  }, [currentView]);

  const setCurrentView = (view: TenantRole) => {
    setStored(view);
    writeStoredView(view);
  };

  return { currentView, setCurrentView };
}
