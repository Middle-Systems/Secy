import { Heart } from 'lucide-react';

/**
 * Thin sticky footer, 45px tall, spanning everything to the right of the sidenav.
 *
 * The status text and version are placeholders — wire the middle slot to a real
 * feed-freshness signal once one exists.
 */
export function Footer() {
  return (
    <footer className="app-footer-sticky fixed bottom-0 right-0 z-40 flex h-footer items-center border-t border-border bg-card">
      <div className="grid w-full grid-cols-3 items-center px-4">
        <div className="flex items-center gap-3">
          <span className="text-[0.85rem] text-muted-foreground">&copy; 2026 Secy Platform</span>
          <a href="#" className="text-[0.85rem] text-muted-foreground hover:underline">
            Terms
          </a>
          <a href="#" className="text-[0.85rem] text-muted-foreground hover:underline">
            Privacy
          </a>
        </div>

        <div className="flex items-center justify-center whitespace-nowrap">
          <span className="badge-dot mr-2.5" aria-hidden="true" />
          <span className="text-[0.85rem] text-muted-foreground">All systems operational</span>
        </div>

        <div className="flex items-center justify-end text-[0.85rem] text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            Made with
            <Heart className="h-3.5 w-3.5 fill-destructive text-destructive" aria-label="love" />
            by
            <a
              href="https://github.com/jdesive"
              className="font-bold text-primary hover:underline"
              target="_blank"
              rel="noreferrer"
            >
              @jdesive
            </a>
          </span>
          <span className="ml-2 opacity-50">v1.0.4-stable</span>
        </div>
      </div>
    </footer>
  );
}
