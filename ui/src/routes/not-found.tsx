import { Link } from '@tanstack/react-router';
import { FileQuestion } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

/** Rendered by the root route's `notFoundComponent` for any unmatched URL. */
export function NotFound() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <Card className="w-full max-w-md text-center">
        <CardHeader>
          <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-accent text-primary">
            <FileQuestion className="h-6 w-6" aria-hidden="true" />
          </div>
          <CardTitle>404 — page not found</CardTitle>
          <CardDescription>That page does not exist, or has moved.</CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild>
            <Link to="/dashboard">Back to dashboard</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
