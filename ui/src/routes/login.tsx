import { useEffect, useState, type FormEvent } from 'react';
import { createRoute, useNavigate } from '@tanstack/react-router';
import { AlertCircle, Loader2, ShieldCheck } from 'lucide-react';

import { ApiError } from '@/api/client';
import secyLogo from '@/assets/img/secy-logo.svg';
import { safeRedirect } from '@/auth/redirect';
import { useAuth } from '@/auth/useAuth';
import { useAuthConfig } from '@/auth/useAuthConfig';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { rootRoute } from '@/routes/__root';

type Mode = 'signin' | 'register';

/** Minimum accepted by the backend's `@Size(min = 8)` on the register DTO. */
const MIN_PASSWORD_LENGTH = 8;

function errorMessage(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    const body = error.body;
    if (typeof body === 'object' && body !== null && 'message' in body) {
      const message = (body as { message: unknown }).message;
      if (typeof message === 'string' && message.trim()) return message;
    }
    if (error.status === 401) return 'That email and password do not match an account.';
    if (error.status === 403) return 'Registration is currently disabled on this instance.';
    if (error.status === 409) return 'An account with that email already exists.';
  }
  return fallback;
}

function LoginPage() {
  const { status, login, register } = useAuth();
  const { registrationEnabled } = useAuthConfig();
  const search = loginRoute.useSearch();
  const navigate = useNavigate();

  const [mode, setMode] = useState<Mode>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const target = safeRedirect(search.redirect);
  const registering = mode === 'register';

  // Leaving is a side effect of the session existing, not of the submit
  // handler — so a token restored in another tab lands here too.
  useEffect(() => {
    if (status === 'authenticated') {
      navigate({ href: target, replace: true });
    }
  }, [status, target, navigate]);

  function switchTo(next: Mode) {
    setMode(next);
    setError(null);
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (registering && password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }

    setSubmitting(true);
    try {
      if (registering) {
        await register({
          email: email.trim(),
          password,
          displayName: displayName.trim() || undefined,
        });
      } else {
        await login({ email: email.trim(), password });
      }
      // The effect above performs the navigation once the session commits.
    } catch (caught) {
      setError(
        errorMessage(
          caught,
          registering ? 'Could not create the account.' : 'Could not sign in.',
        ),
      );
      setSubmitting(false);
    }
  }

  return (
    <div className="flex h-full min-h-screen w-full items-center justify-center overflow-y-auto bg-background px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <img src={secyLogo} alt="Secy" className="mb-3 h-12 w-12" />
          <h1 className="text-2xl font-bold tracking-tight text-foreground">Secy</h1>
          <p className="mt-1 text-sm text-muted-foreground">Security posture management</p>
        </div>

        <div className="rounded-lg border border-border bg-card p-6 shadow-sm">
          {registrationEnabled ? (
            <div
              role="tablist"
              aria-label="Authentication mode"
              className="mb-6 grid grid-cols-2 gap-1 rounded-md bg-muted p-1"
            >
              {(['signin', 'register'] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  role="tab"
                  aria-selected={mode === value}
                  onClick={() => switchTo(value)}
                  className={
                    mode === value
                      ? 'rounded-sm bg-card px-3 py-1.5 text-sm font-semibold text-foreground shadow-sm'
                      : 'rounded-sm px-3 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground'
                  }
                >
                  {value === 'signin' ? 'Sign in' : 'Create account'}
                </button>
              ))}
            </div>
          ) : (
            <h2 className="mb-6 text-lg font-semibold text-foreground">Sign in</h2>
          )}

          <form onSubmit={onSubmit} className="space-y-4" noValidate>
            {registering && (
              <div className="space-y-1.5">
                <Label htmlFor="displayName">
                  Display name <span className="text-muted-foreground">(optional)</span>
                </Label>
                <Input
                  id="displayName"
                  name="displayName"
                  autoComplete="name"
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                  placeholder="Alex Analyst"
                />
              </div>
            )}

            <div className="space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                required
                autoFocus
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                required
                autoComplete={registering ? 'new-password' : 'current-password'}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="••••••••"
              />
              {registering && (
                <p className="text-xs text-muted-foreground">
                  At least {MIN_PASSWORD_LENGTH} characters.
                </p>
              )}
            </div>

            {error && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive"
              >
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />}
              {registering ? 'Create account' : 'Sign in'}
            </Button>
          </form>

          {registering && (
            <p className="mt-4 flex items-start gap-2 text-xs text-muted-foreground">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span>The first account created on an instance becomes its administrator.</span>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * `/login` hangs directly off the root route, not off `_app` — it is the one
 * screen that must render without the shell and without a session.
 */
export const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  validateSearch: (search: Record<string, unknown>): { redirect?: string } => ({
    redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
  }),
  component: LoginPage,
});
