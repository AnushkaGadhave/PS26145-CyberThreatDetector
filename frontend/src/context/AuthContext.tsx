import React, { createContext, useContext, useState, useEffect, useCallback, useRef, type ReactNode } from 'react';
import { api, type UserProfile } from '../services/api';

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isAuthLoading: boolean;
  login: (credentials: { email: string; password: string }) => Promise<UserProfile>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState<boolean>(true);
  const requestSeqRef = useRef<number>(0);

  // Check existing session on application startup
  const refreshUser = useCallback(async () => {
    const seq = ++requestSeqRef.current;
    try {
      const res = await api.getCurrentUser();
      if (seq === requestSeqRef.current) {
        setUser(res.user);
      }
    } catch {
      if (seq === requestSeqRef.current) {
        setUser(null);
      }
    } finally {
      if (seq === requestSeqRef.current) {
        setIsAuthLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = async (credentials: { email: string; password: string }): Promise<UserProfile> => {
    const seq = ++requestSeqRef.current;
    setIsAuthLoading(true);
    try {
      const res = await api.login(credentials);
      if (seq === requestSeqRef.current) {
        setUser(res.user);
        setIsAuthLoading(false);
      }
      return res.user;
    } catch (err) {
      if (seq === requestSeqRef.current) {
        setUser(null);
        setIsAuthLoading(false);
      }
      throw err;
    }
  };

  const logout = async () => {
    ++requestSeqRef.current;
    setUser(null);
    setIsAuthLoading(false);
    try {
      await api.logout();
    } catch {
      // Ignore network errors on logout
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isAuthLoading,
        login,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
