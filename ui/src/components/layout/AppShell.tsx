import { Outlet } from '@tanstack/react-router';

import { Footer } from '@/components/layout/Footer';
import { Header } from '@/components/layout/Header';
import { Sidenav } from '@/components/layout/Sidenav';
import { Toaster } from '@/components/ui/sonner';

/**
 * Application shell: fixed header (58px) + fixed sidenav (240px) + sticky
 * footer (45px), with a single scroll container in the middle.
 *
 * Route components render into the `<Outlet />` inside `.app-content` — that is
 * the ONLY element on the page that scrolls (`html, body { overflow: hidden }`
 * in `styles/index.css`), so a view must never add its own full-page scroller.
 * Views get a `container` with `py-4` padding for free; render your own
 * page heading inside it.
 */
export function AppShell() {
  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <Header />

      <div className="mt-header flex flex-1">
        <Sidenav />

        <main className="app-content ml-sidenav flex flex-1 flex-col overflow-y-auto overflow-x-hidden bg-background">
          <div className="w-full px-4 py-4">
            <Outlet />
          </div>
        </main>

        <Footer />
      </div>

      <Toaster position="bottom-right" richColors closeButton />
    </div>
  );
}
