import type { LucideIcon } from 'lucide-react';
import { Construction } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

interface PlaceholderPageProps {
  /** Human name of the view, e.g. "Dashboard". */
  title: string;
  description?: string;
  icon?: LucideIcon;
}

/**
 * Temporary "coming soon" card used by every route that has not been built yet.
 *
 * Delete the `<PlaceholderPage />` call from a route file when you implement the
 * real view; once no route references this component any more, delete the file.
 */
export function PlaceholderPage({
  title,
  description,
  icon: Icon = Construction,
}: PlaceholderPageProps) {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <Card className="w-full max-w-md text-center">
        <CardHeader>
          <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-accent text-primary">
            <Icon className="h-6 w-6" aria-hidden="true" />
          </div>
          <CardTitle>{title} — coming soon</CardTitle>
          <CardDescription>{description ?? 'This view has not been built yet.'}</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Check back once the {title.toLowerCase()} view ships.
        </CardContent>
      </Card>
    </div>
  );
}
