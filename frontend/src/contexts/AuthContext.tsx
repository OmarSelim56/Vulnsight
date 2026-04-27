import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { getMe, login as apiLogin } from '../api/client';
import type { UserInfo } from '../types';

interface AuthState {
  user: UserInfo | null;
  token: string | null;
  isLoading: boolean;
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  hasRole: (...roles: string[]) => boolean;
  isAdmin: boolean;
  isAnalyst: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    token: localStorage.getItem('vs_token'),
    isLoading: true,
  });

  const hydrateUser = useCallback(async (token: string) => {
    try {
      const user = await getMe();
      setState({ user, token, isLoading: false });
    } catch {
      localStorage.removeItem('vs_token');
      setState({ user: null, token: null, isLoading: false });
    }
  }, []);

  useEffect(() => {
    const stored = localStorage.getItem('vs_token');
    if (stored) {
      hydrateUser(stored);
    } else {
      setState((s) => ({ ...s, isLoading: false }));
    }
  }, [hydrateUser]);

  const login = useCallback(async (username: string, password: string) => {
    const { access_token } = await apiLogin(username, password);
    localStorage.setItem('vs_token', access_token);
    await hydrateUser(access_token);
  }, [hydrateUser]);

  const logout = useCallback(() => {
    localStorage.removeItem('vs_token');
    setState({ user: null, token: null, isLoading: false });
  }, []);

  const hasRole = useCallback(
    (...roles: string[]) =>
      state.user?.roles.some((r) => roles.includes(r)) ?? false,
    [state.user],
  );

  return (
    <AuthContext.Provider
      value={{
        ...state,
        login,
        logout,
        hasRole,
        isAdmin: hasRole('admin'),
        isAnalyst: hasRole('admin', 'analyst'),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
