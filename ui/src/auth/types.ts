/** Shapes exchanged with the backend's `/auth/**` endpoints. */

/** Mirrors `net.jdesive.secy.persistence.entity.Role`. */
export type Role = 'USER' | 'ADMIN';

/** Mirrors `UserResponse` — deliberately never carries a credential. */
export interface AuthUser {
  id: string;
  email: string;
  displayName: string | null;
  role: Role;
  enabled: boolean;
  /** ISO-8601 string, like every other date the API returns. */
  createdAt: string | null;
}

/** Mirrors `AuthResponse`. */
export interface AuthResponse {
  token: string;
  /** ISO-8601 instant at which the token stops being accepted. */
  expiresAt: string;
  user: AuthUser;
}

/** Mirrors `AuthConfigResponse` — what the login screen may know anonymously. */
export interface AuthConfig {
  registrationEnabled: boolean;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface RegisterPayload extends LoginPayload {
  displayName?: string;
}

/**
 * `loading` is the window between mount and the `/auth/me` round trip that
 * validates a token restored from storage. Nothing that depends on identity
 * should render during it — a stored token is a claim, not a session.
 */
export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated';

export interface AuthSnapshot {
  status: AuthStatus;
  user: AuthUser | null;
}

export interface AuthContextValue extends AuthSnapshot {
  token: string | null;
  isAuthenticated: boolean;
  login: (payload: LoginPayload) => Promise<AuthUser>;
  register: (payload: RegisterPayload) => Promise<AuthUser>;
  logout: () => void;
}
