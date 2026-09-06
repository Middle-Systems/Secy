import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClientProvider } from '@tanstack/react-query';

import { AppRouter } from '@/AppRouter';
import { AuthProvider } from '@/auth/AuthProvider';
import { queryClient } from '@/lib/query-client';
import '@/styles/index.css';

const container = document.getElementById('root');
if (!container) {
  throw new Error('Root element #root not found in index.html');
}

createRoot(container).render(
  <StrictMode>
    {/* AuthProvider sits outside the router: the route guard depends on the
        session, not the other way round. */}
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <AppRouter />
      </QueryClientProvider>
    </AuthProvider>
  </StrictMode>,
);
