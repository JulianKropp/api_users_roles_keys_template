import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authAPI } from '@/utils/api';

interface User {
  id: string;
  username: string;
  roles: string[];
  last_login?: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuthStatus: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const storedToken = localStorage.getItem('authToken');
    if (storedToken) {
      setToken(storedToken);
      checkAuthStatus();
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = async (username: string, password: string) => {
    try {
      setIsLoading(true);
      const response = await authAPI.login(username, password);
      
      console.log('Login response:', response); // Debug-Ausgabe
      
      if (response && response.token) {
        localStorage.setItem('authToken', response.token);
        setToken(response.token);
        
        // Überprüfe, ob die Benutzerinformationen in der erwarteten Struktur vorliegen
        if (response.user) {
          setUser(response.user);
        } else if (response.session_type === 'user') {
          // Alternative Struktur aus der API
          setUser({
            id: response.user?.id || '',
            username: response.user?.username || '',
            roles: response.user?.roles || [],
            last_login: response.user?.last_login
          });
        }
        
        setIsAuthenticated(true);
      }
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      setIsLoading(true);
      await authAPI.logout();
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      localStorage.removeItem('authToken');
      setToken(null);
      setUser(null);
      setIsAuthenticated(false);
      setIsLoading(false);
    }
  };

  const checkAuthStatus = async () => {
    try {
      setIsLoading(true);
      const response = await authAPI.status();
      
      console.log('Auth status response:', response); // Debug-Ausgabe
      
      // Überprüfe verschiedene mögliche Antwortformate
      if (response) {
        if (response.authenticated) {
          // Format 1: { authenticated: true, user: {...} }
          setUser(response.user);
          setIsAuthenticated(true);
        } else if (response.token && (response.user || response.session_type === 'user')) {
          // Format 2: { token: '...', user: {...} } oder { token: '...', session_type: 'user', ... }
          if (response.user) {
            setUser(response.user);
          } else if (response.session_type === 'user') {
            setUser({
              id: response.user?.id || '',
              username: response.user?.username || '',
              roles: response.user?.roles || [],
              last_login: response.user?.last_login
            });
          }
          setIsAuthenticated(true);
        } else {
          // Keine gültige Authentifizierung
          localStorage.removeItem('authToken');
          setToken(null);
          setUser(null);
          setIsAuthenticated(false);
        }
      } else {
        localStorage.removeItem('authToken');
        setToken(null);
        setUser(null);
        setIsAuthenticated(false);
      }
    } catch (error) {
      console.error('Auth status check failed:', error);
      localStorage.removeItem('authToken');
      setToken(null);
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated,
        isLoading,
        login,
        logout,
        checkAuthStatus,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
